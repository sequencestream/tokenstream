//! Production data-plane composition with connection-owned streaming work.
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::{BodyExt, Full, combinators::UnsyncBoxBody};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper::{Request, Response};

use crate::auth::GatewayAuthenticator;
use crate::config::Config;
use crate::crypto::{Argon2GatewaySecretVerifier, SharedCipher};
use crate::domain::{ProviderSnapshot, RequestId, TransportType};
use crate::events::EventBus;
use crate::logging::{RequestLogLifecycle, observe_response};
use crate::persistence::Database;
use crate::proxy::admission::{AdmissionPermit, ProxyLimits};
use crate::proxy::error::{ERROR_CONTENT_TYPE, GatewayError};
use crate::proxy::http::HttpProxy;
use crate::proxy::layered::{LayerRejection, LayeredAdmission, LayeredSlots};
use crate::proxy::websocket::{RelayOutcome, WebSocketProxy};
use crate::routing::resolve_route;
use crate::telemetry::{
    ExchangeOutcome, Metrics, ProxyFailureCategory, RejectionLayer, RejectionReason,
};

pub type DataBody = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
pub type Session = Pin<Box<dyn Future<Output = ()> + Send>>;
pub type Exchange = (Response<DataBody>, Option<Session>);

pub fn boxed<B>(body: B) -> DataBody
where
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    body.map_err(Into::into).boxed_unsync()
}

pub struct Gateway {
    authenticator: GatewayAuthenticator<Database, SharedCipher, Argon2GatewaySecretVerifier>,
    http: HttpProxy<Incoming>,
    websocket: WebSocketProxy,
    events: EventBus,
    metrics: Metrics,
    admission: LayeredAdmission,
    settings: crate::ConnectionSettings,
}

impl Gateway {
    pub fn new(config: &Config, database: Database, events: EventBus, metrics: Metrics) -> Self {
        Self::with_password_work(
            config,
            database,
            events,
            metrics,
            crate::crypto::PasswordWork::default(),
        )
    }

    pub fn with_password_work(
        config: &Config,
        database: Database,
        events: EventBus,
        metrics: Metrics,
        work: crate::crypto::PasswordWork,
    ) -> Self {
        Self::with_shared_cipher(
            config,
            database,
            events,
            metrics,
            work,
            SharedCipher::new(config.master_key().expose()),
        )
    }

    pub fn with_shared_cipher(
        config: &Config,
        database: Database,
        events: EventBus,
        metrics: Metrics,
        work: crate::crypto::PasswordWork,
        cipher: SharedCipher,
    ) -> Self {
        Self {
            settings: crate::ConnectionSettings::data(config),
            authenticator: GatewayAuthenticator::new(
                database,
                cipher,
                Argon2GatewaySecretVerifier::new(),
            )
            .with_password_work(work),
            http: HttpProxy::with_pool(
                config.upstream_connect_timeout(),
                config.upstream_header_timeout(),
                config.stream_idle_timeout(),
                config.http_buffer_bytes(),
                config.upstream_idle_per_host(),
                config.upstream_pool_idle_timeout(),
            ),
            websocket: WebSocketProxy::new(
                config.upstream_connect_timeout(),
                config.upstream_header_timeout(),
                config.stream_idle_timeout(),
                &ProxyLimits::from_config(config),
            ),
            events,
            metrics,
            admission: LayeredAdmission::new(),
        }
    }

    /// The layered admission registry, shared by every clone of this gateway.
    pub fn admission(&self) -> LayeredAdmission {
        self.admission.clone()
    }

    async fn forward(
        &self,
        mut request: Request<Incoming>,
        peer: SocketAddr,
        permit: AdmissionPermit,
        id: RequestId,
    ) -> Result<Exchange, (GatewayError, TransportType)> {
        // A request that never resolves a route has no transport, so every
        // failure this can return carries the transport it was decided under.
        // A failure before the route resolves is an HTTP request by definition:
        // a WebSocket exchange cannot exist without a resolved upgrade route.
        let transport = TransportType::Http;
        let snapshot = self
            .authenticator
            .authenticate(request.headers())
            .await
            .map_err(|error| (GatewayError::from(error), transport))?;
        let route = resolve_route(
            snapshot.protocol_type(),
            request.method(),
            request.uri().path(),
            request.headers(),
        )
        .map_err(|error| (GatewayError::from(error), transport))?;
        let transport = route.transport();
        let query = request.uri().query().map(str::to_owned);

        // Layered admission runs once the snapshot is frozen and the route is
        // valid, and before any upstream is contacted. A rejection here costs
        // one credential lookup and no network, and it releases everything an
        // outer layer already took.
        let slots = self
            .admit_layers(&snapshot, transport)
            .map_err(|error| (error, transport))?;
        let slots = Arc::new(slots);

        if transport == TransportType::Http {
            let response = self
                .http
                .forward_logged(
                    &snapshot,
                    &route,
                    query.as_deref(),
                    peer,
                    request,
                    self.events.clone(),
                    self.metrics.clone(),
                    id,
                )
                .await
                .map_err(|error| (error, transport))?;
            return Ok((
                response.map(|body| {
                    boxed(PermittedBody {
                        inner: body,
                        _permit: permit,
                        _slots: Arc::clone(&slots),
                    })
                }),
                None,
            ));
        }
        let mut lifecycle = RequestLogLifecycle::start(
            self.events.clone(),
            self.metrics.clone(),
            id,
            &snapshot,
            &route,
        )
        .observe_websocket();
        let (response, relay) = match self
            .websocket
            .prepare(&snapshot, &route, query.as_deref(), peer, &mut request)
            .await
        {
            Ok(prepared) => prepared,
            Err(error) => {
                // The lifecycle records this terminal point itself, including
                // the exchange outcome, so the caller must not count it again.
                lifecycle.complete(None, Some(error.code()));
                return Err((error, transport));
            }
        };
        let status = response.status();
        match relay {
            None => Ok((
                observe_response(response, lifecycle).map(|inner| {
                    boxed(PermittedBody {
                        inner,
                        _permit: permit,
                        _slots: Arc::clone(&slots),
                    })
                }),
                None,
            )),
            Some(relay) => {
                let session: Session = Box::pin(async move {
                    let _permit = permit;
                    let _slots = slots;
                    let outcome = relay.await;
                    let error = match outcome {
                        RelayOutcome::Closed => None,
                        RelayOutcome::MessageTooLarge => Some("message_too_large"),
                        RelayOutcome::IdleTimeout => Some("idle_timeout"),
                        RelayOutcome::Failed => Some("relay_failed"),
                    };
                    lifecycle.complete(Some(status), error);
                });
                Ok((response.map(boxed), Some(session)))
            }
        }
    }

    /// Records a layer refusal and passes the sanitized error upward.
    ///
    /// The rejection is counted at the layer that made the decision, which is
    /// the only point in the process that knows which bound was full.
    fn refuse(&self, rejection: LayerRejection, layer: RejectionLayer) -> GatewayError {
        let reason = match rejection {
            LayerRejection::Concurrency => RejectionReason::Concurrency,
            LayerRejection::Rate => RejectionReason::Rate,
        };
        self.metrics.record_rejection(layer, reason);
        rejection.error()
    }

    /// Runs the provider and credential admission layers for one request.
    ///
    /// Layers are evaluated outside in: provider concurrency, then credential
    /// concurrency, then the long-lived connection bound a WebSocket is subject
    /// to, then the two rate allowances. Every acquisition either succeeds
    /// immediately or refuses, and a refusal drops the slots already taken, so a
    /// rejected request never holds capacity it cannot use.
    ///
    /// A rate allowance is consumed once per request on every transport, so an
    /// HTTP exchange and a WebSocket handshake are counted alike. The
    /// long-lived connection bound is not: it exists only to bound sockets a
    /// client keeps open, so an HTTP exchange never consumes it.
    fn admit_layers(
        &self,
        snapshot: &ProviderSnapshot,
        transport: TransportType,
    ) -> Result<LayeredSlots, GatewayError> {
        let provider = self
            .admission
            .provider_layers(snapshot.id(), snapshot.provider_admission());
        let credential = self
            .admission
            .credential_layers(snapshot.api_key_id(), snapshot.credential_admission());

        // Every refusal is attributed to the layer that made it. The layer is
        // the fact an operator acts on: a credential whose rate allowance is
        // exhausted and a provider whose concurrency bound is full are the same
        // visible symptom and two different fixes.
        let acquired = (|| -> Result<LayeredSlots, GatewayError> {
            let provider_concurrency = provider
                .acquire_concurrency()
                .map_err(|rejection| self.refuse(rejection, RejectionLayer::ProviderConcurrency))?;
            let credential_concurrency = credential.acquire_concurrency().map_err(|rejection| {
                self.refuse(rejection, RejectionLayer::CredentialConcurrency)
            })?;
            let credential_websockets = if transport == TransportType::WebSocket {
                credential.acquire_websocket().map_err(|rejection| {
                    self.refuse(rejection, RejectionLayer::CredentialWebSockets)
                })?
            } else {
                None
            };
            provider
                .acquire_rate()
                .map_err(|rejection| self.refuse(rejection, RejectionLayer::ProviderRate))?;
            credential
                .acquire_rate()
                .map_err(|rejection| self.refuse(rejection, RejectionLayer::CredentialRate))?;
            Ok(LayeredSlots::new(
                provider_concurrency,
                credential_concurrency,
                credential_websockets,
            ))
        })();

        match acquired {
            Ok(slots) => Ok(slots),
            Err(error) => {
                // A refusal at any layer drops the slots taken before it, and
                // releases a registry entry whose bound is now lifted. The
                // error was already the sanitized one the layer refusal maps
                // to, so it is returned unchanged.
                credential.finish();
                Err(error)
            }
        }
    }
}

impl crate::DataPlaneService for Gateway {
    fn connection_settings(&self) -> crate::ConnectionSettings {
        self.settings
    }
    async fn serve(
        &self,
        request: Request<Incoming>,
        peer: SocketAddr,
        permit: AdmissionPermit,
        id: RequestId,
        metrics: Metrics,
    ) -> Exchange {
        let started = std::time::Instant::now();
        let mut result = match self.forward(request, peer, permit, id.clone()).await {
            Ok(result) => result,
            Err((error, transport)) => {
                // Health isolation is a refusal before an exchange exists. It
                // has its own counter and must not contribute a latency sample
                // or inflate the gateway-failure rate.
                if error.category() == ProxyFailureCategory::ProviderUnhealthy {
                    metrics.record_health_refusal();
                    return with_request_id((error_response(error, &id), None), &id);
                }
                // Every gateway-originated failure classifies through the error
                // contract, so no failure the exposition has a series for goes
                // uncounted. A failure with a lifecycle of its own already
                // recorded that exchange, and this path is only reached for
                // failures decided before one existed.
                metrics.record_failure(error.category());
                metrics.record_exchange(
                    ExchangeOutcome::failure(transport, error.category()),
                    started.elapsed(),
                );
                (error_response(error, &id), None)
            }
        };
        result.0.headers_mut().insert(
            "x-request-id",
            id.as_str().parse().expect("generated request ID"),
        );
        result
    }
}

fn with_request_id(mut exchange: Exchange, id: &RequestId) -> Exchange {
    exchange.0.headers_mut().insert(
        "x-request-id",
        id.as_str().parse().expect("generated request ID"),
    );
    exchange
}

pub fn error_response(error: GatewayError, id: &RequestId) -> Response<DataBody> {
    Response::builder()
        .status(error.status())
        .header("content-type", ERROR_CONTENT_TYPE)
        .header("x-request-id", id.as_str())
        .body(boxed(Full::new(error.render(id))))
        .expect("safe error response")
}

struct PermittedBody<B> {
    inner: B,
    _permit: AdmissionPermit,
    /// Held for the whole exchange alongside the global permit, so a layered
    /// slot is released exactly when the response body is dropped.
    _slots: Arc<LayeredSlots>,
}
impl<B: Body<Data = Bytes> + Unpin> Body for PermittedBody<B> {
    type Data = Bytes;
    type Error = B::Error;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}
