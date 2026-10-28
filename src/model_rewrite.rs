//! Replaces one caller-facing model name after the provider is already selected.
//!
//! The proxy core does not depend on this module. An empty alias table skips
//! every read. A non-empty table scans a bounded prefix for a single top-level
//! JSON string named `model` and, when that string is an alias for the selected
//! provider, replaces only that string. The scan tracks strings and nesting. It
//! does not validate the rest of the payload. The unread remainder of an HTTP
//! body streams through unchanged.

use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::HeaderMap;
use hyper::body::{Body, Frame, SizeHint};

use crate::domain::{AliasLookup, ModelAliasTable, ModelRewriteFailure};

/// How many leading body bytes the HTTP rewrite will scan.
///
/// The bound is what keeps a request with aliases from buffering an entire
/// payload. A top-level `model` that begins past this prefix is left unchanged.
pub const MODEL_PREFIX_LIMIT: usize = 64 * 1024;

/// A failure while preparing a body for the proxy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PrepareError {
    /// The model field cannot be forwarded as it is.
    Rewrite(ModelRewriteFailure),
    /// The prefix could not be read.
    Read,
}

/// A request body after the alias decision, ready for the proxy to stream.
///
/// `Original` is the untouched downstream body, used when the account has no
/// aliases. `Prefixed` replays the bytes the adapter already had to read, then
/// the unread remainder.
pub struct RewrittenBody<B> {
    state: BodyState<B>,
    length_changed: bool,
}

enum BodyState<B> {
    Original(B),
    Prefixed {
        pending: std::collections::VecDeque<Bytes>,
        rest: B,
        trailers: Option<HeaderMap>,
    },
}

impl<B> RewrittenBody<B> {
    fn original(body: B) -> Self {
        Self {
            state: BodyState::Original(body),
            length_changed: false,
        }
    }

    /// Whether the replacement changed the number of body bytes.
    ///
    /// The caller drops the client's content length when this is true, because
    /// that length no longer describes the bytes the upstream will receive.
    pub fn length_changed(&self) -> bool {
        self.length_changed
    }
}

impl<B> Body for RewrittenBody<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match &mut this.state {
            BodyState::Original(body) => Pin::new(body).poll_frame(context),
            BodyState::Prefixed {
                pending,
                rest,
                trailers,
            } => {
                if let Some(chunk) = pending.pop_front()
                    && !chunk.is_empty()
                {
                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                }
                if !rest.is_end_stream() {
                    return Pin::new(rest).poll_frame(context);
                }
                match Pin::new(rest).poll_frame(context) {
                    Poll::Ready(None) => {
                        if let Some(trailers) = trailers.take() {
                            Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                        } else {
                            Poll::Ready(None)
                        }
                    }
                    other => other,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        match &self.state {
            BodyState::Original(body) => body.is_end_stream(),
            BodyState::Prefixed {
                pending,
                rest,
                trailers,
            } => pending.is_empty() && rest.is_end_stream() && trailers.is_none(),
        }
    }

    fn size_hint(&self) -> SizeHint {
        match &self.state {
            BodyState::Original(body) => body.size_hint(),
            BodyState::Prefixed { pending, rest, .. } => {
                let extra = pending.iter().map(|chunk| chunk.len() as u64).sum();
                add_len(rest.size_hint(), extra)
            }
        }
    }
}

fn add_len(hint: SizeHint, extra: u64) -> SizeHint {
    let mut combined = SizeHint::new();
    combined.set_lower(hint.lower().saturating_add(extra));
    if let Some(upper) = hint.upper() {
        combined.set_upper(upper.saturating_add(extra));
    }
    combined
}

/// Rewrites a complete client text message.
///
/// `Ok(None)` means the message is forwarded unchanged. `Ok(Some)` is the
/// replacement. A message longer than the HTTP prefix is scanned only through
/// that prefix; the remainder is copied after it.
pub fn rewrite_text(
    table: &ModelAliasTable,
    text: &str,
) -> Result<Option<String>, ModelRewriteFailure> {
    if table.is_empty() {
        return Ok(None);
    }
    let bytes = text.as_bytes();
    let (head, tail) = if bytes.len() > MODEL_PREFIX_LIMIT {
        bytes.split_at(MODEL_PREFIX_LIMIT)
    } else {
        (bytes, &[][..])
    };
    let decision = commit(head, table)?;
    match decision {
        Decision::Passthrough => Ok(None),
        Decision::Replace(mut replaced) => {
            replaced.extend_from_slice(tail);
            let rewritten =
                String::from_utf8(replaced).map_err(|_| ModelRewriteFailure::Invalid)?;
            if rewritten == text {
                Ok(None)
            } else {
                Ok(Some(rewritten))
            }
        }
    }
}

/// Reads at most [`MODEL_PREFIX_LIMIT`] bytes and decides the rewrite.
///
/// An empty table returns the original body without polling it.
pub async fn prepare<B>(
    table: &ModelAliasTable,
    mut body: B,
) -> Result<RewrittenBody<B>, PrepareError>
where
    B: Body<Data = Bytes> + Unpin,
{
    if table.is_empty() {
        return Ok(RewrittenBody::original(body));
    }

    let mut buffered = Vec::new();
    let mut overflow = Bytes::new();
    let mut trailers = None;
    loop {
        // `Pending` means the prefix is incomplete, not that the body failed.
        // A body failure is the `frame()` error below.
        match classify(&buffered, table) {
            Ok(Progress::Ready) => return apply(body, buffered, overflow, trailers, table),
            Ok(Progress::Pending) => {}
            Err(error) => return Err(PrepareError::Rewrite(error)),
        }
        if buffered.len() >= MODEL_PREFIX_LIMIT {
            break;
        }
        match body.frame().await {
            None => break,
            Some(Err(_)) => return Err(PrepareError::Read),
            Some(Ok(frame)) => match frame.into_data() {
                Ok(data) if data.is_empty() => {}
                Ok(data) => {
                    let room = MODEL_PREFIX_LIMIT - buffered.len();
                    if data.len() > room {
                        buffered.extend_from_slice(&data[..room]);
                        overflow = data.slice(room..);
                        break;
                    }
                    buffered.extend_from_slice(&data);
                }
                Err(frame) => {
                    if let Ok(headers) = frame.into_trailers() {
                        trailers = Some(headers);
                    }
                    break;
                }
            },
        }
    }

    apply(body, buffered, overflow, trailers, table)
}

fn apply<B>(
    body: B,
    buffered: Vec<u8>,
    overflow: Bytes,
    trailers: Option<HeaderMap>,
    table: &ModelAliasTable,
) -> Result<RewrittenBody<B>, PrepareError> {
    match commit(&buffered, table).map_err(PrepareError::Rewrite)? {
        Decision::Passthrough => Ok(finish(
            body,
            Bytes::from(buffered),
            overflow,
            trailers,
            false,
        )),
        Decision::Replace(replaced) => {
            let changed = replaced.len() != buffered.len();
            Ok(finish(
                body,
                Bytes::from(replaced),
                overflow,
                trailers,
                changed,
            ))
        }
    }
}

fn finish<B>(
    body: B,
    prefix: Bytes,
    overflow: Bytes,
    trailers: Option<HeaderMap>,
    length_changed: bool,
) -> RewrittenBody<B> {
    if prefix.is_empty() && overflow.is_empty() && trailers.is_none() {
        return RewrittenBody::original(body);
    }
    let mut pending = std::collections::VecDeque::new();
    if !prefix.is_empty() {
        pending.push_back(prefix);
    }
    if !overflow.is_empty() {
        pending.push_back(overflow);
    }
    RewrittenBody {
        state: BodyState::Prefixed {
            pending,
            rest: body,
            trailers,
        },
        length_changed,
    }
}

enum Decision {
    Passthrough,
    Replace(Vec<u8>),
}

enum Progress {
    Ready,
    Pending,
}

/// Whether the bytes already decide the rewrite.
///
/// `Pending` means a later byte could still reveal the top-level model. The
/// replacement itself is built only by [`commit`], once, when the prefix is
/// finished or the object has ended.
fn classify(bytes: &[u8], table: &ModelAliasTable) -> Result<Progress, ModelRewriteFailure> {
    match Scan::new(bytes, table, false).walk() {
        Halt::Reject(error) => Err(error),
        Halt::Settled => Ok(Progress::Ready),
        Halt::NeedMore { .. } => Ok(Progress::Pending),
    }
}

/// Builds the rewrite from a finished prefix.
///
/// A cut inside the top-level model string fails. Any other unfinished prefix
/// keeps a model string already completed, and otherwise forwards the bytes.
fn commit(bytes: &[u8], table: &ModelAliasTable) -> Result<Decision, ModelRewriteFailure> {
    let mut scan = Scan::new(bytes, table, true);
    match scan.walk() {
        Halt::Reject(error) => Err(error),
        Halt::NeedMore { inside_model: true } => Err(ModelRewriteFailure::Invalid),
        Halt::NeedMore {
            inside_model: false,
        }
        | Halt::Settled => Ok(scan.decision()),
    }
}

struct Replacement {
    start: usize,
    end: usize,
    upstream: String,
}

fn splice(bytes: &[u8], replacement: &Replacement) -> Vec<u8> {
    let quoted = serde_json::to_string(&replacement.upstream)
        .expect("a Rust string is always a JSON string");
    let mut out =
        Vec::with_capacity(bytes.len() - (replacement.end - replacement.start) + quoted.len());
    out.extend_from_slice(&bytes[..replacement.start]);
    out.extend_from_slice(quoted.as_bytes());
    out.extend_from_slice(&bytes[replacement.end..]);
    out
}

struct Scan<'a> {
    input: &'a [u8],
    index: usize,
    table: &'a ModelAliasTable,
    capture: bool,
    model_seen: bool,
    hit: Option<Replacement>,
}

enum Halt {
    Settled,
    NeedMore { inside_model: bool },
    Reject(ModelRewriteFailure),
}

enum Stop {
    NeedMore,
    Invalid,
}

enum Skip {
    Done,
    NeedMore,
    Confused,
}

impl<'a> Scan<'a> {
    fn new(input: &'a [u8], table: &'a ModelAliasTable, capture: bool) -> Self {
        Self {
            input,
            index: 0,
            table,
            capture,
            model_seen: false,
            hit: None,
        }
    }

    fn decision(&self) -> Decision {
        match &self.hit {
            Some(hit) => Decision::Replace(splice(self.input, hit)),
            None => Decision::Passthrough,
        }
    }

    fn walk(&mut self) -> Halt {
        if self.skip_ws().is_err() {
            return Halt::NeedMore {
                inside_model: false,
            };
        }
        if self.peek() != Some(b'{') {
            return Halt::Settled;
        }
        self.index += 1;
        self.top_object()
    }

    /// Reads one top-level object, recording at most one `model` string.
    ///
    /// A structural break before that string settles as a passthrough. A second
    /// `model`, or a `model` whose value is not a string, rejects.
    fn top_object(&mut self) -> Halt {
        loop {
            if self.skip_ws().is_err() {
                return Halt::NeedMore {
                    inside_model: false,
                };
            }
            match self.peek() {
                Some(b'}') => {
                    self.index += 1;
                    return Halt::Settled;
                }
                Some(b'"') => {}
                Some(_) => return Halt::Settled,
                None => {
                    return Halt::NeedMore {
                        inside_model: false,
                    };
                }
            }
            let key = match self.decode_string() {
                Ok(key) => key,
                Err(Stop::NeedMore) => {
                    return Halt::NeedMore {
                        inside_model: false,
                    };
                }
                Err(Stop::Invalid) => return Halt::Settled,
            };
            let is_model = key == "model";
            if is_model {
                if self.model_seen {
                    return Halt::Reject(ModelRewriteFailure::Invalid);
                }
                self.model_seen = true;
            }
            if self.skip_ws().is_err() {
                return Halt::NeedMore {
                    inside_model: false,
                };
            }
            if self.peek() != Some(b':') {
                return Halt::Settled;
            }
            self.index += 1;
            if self.skip_ws().is_err() {
                return Halt::NeedMore {
                    inside_model: false,
                };
            }
            if is_model {
                if self.peek() != Some(b'"') {
                    return Halt::Reject(ModelRewriteFailure::Invalid);
                }
                let start = self.index;
                let decoded = match self.decode_string() {
                    Ok(value) => value,
                    Err(Stop::NeedMore) => return Halt::NeedMore { inside_model: true },
                    Err(Stop::Invalid) => return Halt::Reject(ModelRewriteFailure::Invalid),
                };
                let end = self.index;
                match self.table.lookup(&decoded) {
                    AliasLookup::Unavailable => {
                        return Halt::Reject(ModelRewriteFailure::Unavailable);
                    }
                    AliasLookup::Passthrough => {}
                    AliasLookup::Upstream(upstream) => {
                        if self.capture {
                            self.hit = Some(Replacement {
                                start,
                                end,
                                upstream: upstream.to_owned(),
                            });
                        }
                    }
                }
            } else {
                match self.skip_value() {
                    Skip::Done => {}
                    Skip::NeedMore => {
                        return Halt::NeedMore {
                            inside_model: false,
                        };
                    }
                    Skip::Confused => return Halt::Settled,
                }
            }
            if self.skip_ws().is_err() {
                return Halt::NeedMore {
                    inside_model: false,
                };
            }
            match self.peek() {
                Some(b',') => self.index += 1,
                Some(b'}') => {
                    self.index += 1;
                    return Halt::Settled;
                }
                Some(_) => return Halt::Settled,
                None => {
                    return Halt::NeedMore {
                        inside_model: false,
                    };
                }
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.index).copied()
    }

    fn bump(&mut self) -> Result<u8, Stop> {
        let byte = *self.input.get(self.index).ok_or(Stop::NeedMore)?;
        self.index += 1;
        Ok(byte)
    }

    fn bump_raw(&mut self) -> Option<u8> {
        let byte = self.input.get(self.index).copied()?;
        self.index += 1;
        Some(byte)
    }

    fn skip_ws(&mut self) -> Result<(), ()> {
        while self.index < self.input.len() && self.input[self.index].is_ascii_whitespace() {
            self.index += 1;
        }
        if self.index >= self.input.len() {
            Err(())
        } else {
            Ok(())
        }
    }

    fn decode_string(&mut self) -> Result<String, Stop> {
        if self.bump()? != b'"' {
            return Err(Stop::Invalid);
        }
        let mut decoded = String::new();
        loop {
            match self.bump()? {
                b'"' => return Ok(decoded),
                b'\\' => decoded.push(self.decode_escape()?),
                byte if byte < 0x20 => return Err(Stop::Invalid),
                byte if byte < 0x80 => decoded.push(byte as char),
                _ => {
                    self.index -= 1;
                    decoded.push(self.decode_utf8()?);
                }
            }
        }
    }

    fn decode_escape(&mut self) -> Result<char, Stop> {
        match self.bump()? {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.decode_unicode(),
            _ => Err(Stop::Invalid),
        }
    }

    fn decode_unicode(&mut self) -> Result<char, Stop> {
        let unit = self.hex4()?;
        if (0xD800..=0xDBFF).contains(&unit) {
            if self.bump()? != b'\\' || self.bump()? != b'u' {
                return Err(Stop::Invalid);
            }
            let low = self.hex4()?;
            if !(0xDC00..=0xDFFF).contains(&low) {
                return Err(Stop::Invalid);
            }
            let value = 0x10000 + (((u32::from(unit) - 0xD800) << 10) | (u32::from(low) - 0xDC00));
            return char::from_u32(value).ok_or(Stop::Invalid);
        }
        if (0xDC00..=0xDFFF).contains(&unit) {
            return Err(Stop::Invalid);
        }
        char::from_u32(u32::from(unit)).ok_or(Stop::Invalid)
    }

    fn hex4(&mut self) -> Result<u16, Stop> {
        let mut value = 0u16;
        for _ in 0..4 {
            let digit = match self.bump()? {
                byte @ b'0'..=b'9' => byte - b'0',
                byte @ b'a'..=b'f' => byte - b'a' + 10,
                byte @ b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(Stop::Invalid),
            };
            value = (value << 4) | u16::from(digit);
        }
        Ok(value)
    }

    fn decode_utf8(&mut self) -> Result<char, Stop> {
        let rest = &self.input[self.index..];
        let first = *rest.first().ok_or(Stop::NeedMore)?;
        let width = if first & 0b1110_0000 == 0b1100_0000 {
            2
        } else if first & 0b1111_0000 == 0b1110_0000 {
            3
        } else if first & 0b1111_1000 == 0b1111_0000 {
            4
        } else {
            return Err(Stop::Invalid);
        };
        if rest.len() < width {
            return Err(Stop::NeedMore);
        }
        let text = std::str::from_utf8(&rest[..width]).map_err(|_| Stop::Invalid)?;
        let ch = text.chars().next().ok_or(Stop::Invalid)?;
        self.index += width;
        Ok(ch)
    }

    fn skip_value(&mut self) -> Skip {
        match self.peek() {
            None => Skip::NeedMore,
            Some(b'"') => self.skip_string(),
            Some(b'{' | b'[') => self.skip_container(),
            Some(b'-' | b'0'..=b'9' | b't' | b'f' | b'n') => self.skip_atom(),
            Some(_) => Skip::Confused,
        }
    }

    fn skip_string(&mut self) -> Skip {
        if self.bump_raw() != Some(b'"') {
            return Skip::Confused;
        }
        loop {
            let Some(byte) = self.bump_raw() else {
                return Skip::NeedMore;
            };
            if byte == b'\\' {
                if self.bump_raw().is_none() {
                    return Skip::NeedMore;
                }
                continue;
            }
            if byte == b'"' {
                return Skip::Done;
            }
        }
    }

    fn skip_container(&mut self) -> Skip {
        if !matches!(self.bump_raw(), Some(b'{' | b'[')) {
            return Skip::Confused;
        }
        let mut depth = 1usize;
        let mut in_string = false;
        let mut escaped = false;
        while depth > 0 {
            let Some(byte) = self.bump_raw() else {
                return Skip::NeedMore;
            };
            if in_string {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = false;
                }
                continue;
            }
            match byte {
                b'"' => in_string = true,
                b'{' | b'[' => depth += 1,
                b'}' | b']' => depth -= 1,
                _ => {}
            }
        }
        Skip::Done
    }

    fn skip_atom(&mut self) -> Skip {
        let start = self.index;
        while self.index < self.input.len() {
            let byte = self.input[self.index];
            if byte.is_ascii_whitespace()
                || matches!(byte, b',' | b'}' | b']' | b'{' | b'[' | b'"' | b':')
            {
                break;
            }
            self.index += 1;
        }
        if self.index == start {
            Skip::Confused
        } else if self.index >= self.input.len() {
            Skip::NeedMore
        } else {
            Skip::Done
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::{BodyExt, Full};

    fn table() -> ModelAliasTable {
        let mut table = ModelAliasTable::default();
        table.insert_available("coding".to_owned(), "gpt-5.2-codex".to_owned());
        table.insert_unavailable("writing".to_owned());
        table
    }

    #[test]
    fn an_alias_replaces_only_the_top_level_model_string() {
        let rewritten = rewrite_text(
            &table(),
            r#"{"input":{"model":"coding"},"model":"coding","n":1}"#,
        )
        .expect("rewrite");
        assert_eq!(
            rewritten.as_deref(),
            Some(r#"{"input":{"model":"coding"},"model":"gpt-5.2-codex","n":1}"#)
        );
    }

    #[test]
    fn a_raw_model_name_and_a_missing_model_pass_through() {
        let raw = r#"{"model":"gpt-5.2-codex","messages":[]}"#;
        assert_eq!(rewrite_text(&table(), raw).expect("raw"), None);
        assert_eq!(
            rewrite_text(&table(), r#"{"messages":[]}"#).expect("missing"),
            None
        );
        assert_eq!(rewrite_text(&table(), "not-json").expect("text"), None);
    }

    #[test]
    fn an_alias_without_a_target_and_an_ambiguous_model_fail() {
        assert_eq!(
            rewrite_text(&table(), r#"{"model":"writing"}"#),
            Err(ModelRewriteFailure::Unavailable)
        );
        assert_eq!(
            rewrite_text(&table(), r#"{"model":1}"#),
            Err(ModelRewriteFailure::Invalid)
        );
        assert_eq!(
            rewrite_text(&table(), r#"{"model":"coding","model":"coding"}"#),
            Err(ModelRewriteFailure::Invalid)
        );
    }

    #[test]
    fn escapes_are_decoded_for_matching_and_reencoded_for_the_upstream_name() {
        let mut quoted = ModelAliasTable::default();
        quoted.insert_available("coding".to_owned(), "gpt\"5".to_owned());
        let rewritten = rewrite_text(&quoted, r#"{"model":"cod\u0069ng"}"#).expect("escaped alias");
        assert_eq!(rewritten.as_deref(), Some(r#"{"model":"gpt\"5"}"#));
    }

    #[test]
    fn a_model_past_the_prefix_is_left_unchanged() {
        let padding = "x".repeat(MODEL_PREFIX_LIMIT);
        let body = format!(r#"{{"pad":"{padding}","model":"coding"}}"#);
        assert_eq!(rewrite_text(&table(), &body).expect("late model"), None);
    }

    #[test]
    fn a_completed_model_is_rewritten_when_the_object_runs_past_the_prefix() {
        let padding = "x".repeat(MODEL_PREFIX_LIMIT);
        let body = format!(r#"{{"model":"coding","pad":"{padding}"}}"#);
        let rewritten = rewrite_text(&table(), &body).expect("early model");
        let expected = format!(r#"{{"model":"gpt-5.2-codex","pad":"{padding}"}}"#);
        assert_eq!(rewritten.as_deref(), Some(expected.as_str()));
    }

    #[test]
    fn a_cut_model_string_fails_and_unfollowed_json_passes_through() {
        assert_eq!(
            rewrite_text(&table(), r#"{"model":"cod"#),
            Err(ModelRewriteFailure::Invalid)
        );
        assert_eq!(rewrite_text(&table(), "{not-json").expect("broken"), None);
        let rewritten = rewrite_text(&table(), r#"{"model":"coding",}"#).expect("trailing comma");
        assert_eq!(rewritten.as_deref(), Some(r#"{"model":"gpt-5.2-codex",}"#));
        let nested = rewrite_text(
            &table(),
            r#"{"messages":[{"content":"say \"model\""}],"model":"coding"}"#,
        )
        .expect("messages");
        assert_eq!(
            nested.as_deref(),
            Some(r#"{"messages":[{"content":"say \"model\""}],"model":"gpt-5.2-codex"}"#)
        );
        let escaped_key =
            rewrite_text(&table(), r#"{"mod\u0065l":"coding"}"#).expect("escaped key");
        assert_eq!(
            escaped_key.as_deref(),
            Some(r#"{"mod\u0065l":"gpt-5.2-codex"}"#)
        );
    }

    #[test]
    fn an_empty_table_does_not_read_the_body() {
        let body = Full::new(Bytes::from_static(br#"{"model":"coding"}"#));
        let rewritten = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime")
            .block_on(prepare(&ModelAliasTable::default(), body))
            .expect("prepare");
        assert!(!rewritten.length_changed());
        assert!(matches!(rewritten.state, BodyState::Original(_)));
    }

    #[tokio::test]
    async fn a_chunked_body_keeps_the_bytes_after_the_replaced_model() {
        let body = Full::new(Bytes::from_static(
            br#"{"model":"coding","messages":["keep"]}"#,
        ));
        let rewritten = prepare(&table(), body).await.expect("prepare");
        assert!(rewritten.length_changed());
        let collected = rewritten.collect().await.expect("body").to_bytes();
        assert_eq!(
            collected.as_ref(),
            br#"{"model":"gpt-5.2-codex","messages":["keep"]}"#
        );
    }
}
