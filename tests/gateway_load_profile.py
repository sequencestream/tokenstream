"""Sustained mixed load profile against a real Tokenstream process.

The component profile proves bounded memory for the proxy in isolation. This
profile instead measures the deployed process under the default hashing budget
and a separately labelled declared-admission configuration: it drives mixed
short HTTP requests with long-lived HTTP, SSE and WebSocket traffic through the
formal listeners, samples success and rejection rates, latency percentiles,
resident memory and file descriptors, compares bounded HTTP connection reuse
with no reuse, and then exercises slow consumers, a slow database,
authentication pressure, logging saturation, near-limit admission and a storage
fault. Raised hashing budgets are never a substitute for the default-configuration
run.
"""
import base64
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
import platform
import socket
import sqlite3
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

PAYLOAD = b'opaque\x00unknown{not-json}'
# Makes request-log writes fail without affecting the provider reads that
# authentication depends on, so only the logging path is under fault.
FAULT_TRIGGER = """
CREATE TRIGGER request_log_write_fault BEFORE INSERT ON request_log
BEGIN SELECT RAISE(ABORT, 'injected storage fault'); END
"""
SSE = b'data: opaque\n\ndata: [DONE]\n\n'
WS_MESSAGE = b'x' * 1024

HTTP_CLIENTS = 24
WEBSOCKET_CLIENTS = 12
RAMP_UP_SECONDS = 2.0
STEADY_SECONDS = 20.0
SAMPLE_INTERVAL = 0.25
WARMUP_SAMPLES = 8
MAX_STEADY_RSS_SPREAD_KIB = 24 * 1024
MAX_STEADY_FD_SPREAD = 512
AUTH_PRESSURE_CLIENTS = 12
SLOW_CONSUMERS = 6
# Default process hashing is 4 slots with 1 reserved for administration, so at
# most 3 new data-plane authentications may run at once. Load that exceeds this
# must reject rather than queue.
DEFAULT_DATA_HASH_SLOTS = 3
TURNOVER_REQUESTS = 24
BURST_REQUESTS = 16
REUSE_REQUESTS = 48
MAX_SHORT_REQUEST_P99_S = 8.0
DECLARED_ADMISSION = 4096
NEAR_LIMIT_HTTP = 2
NEAR_LIMIT_WEBSOCKET = 2
# Layered admission bounds. The gateway gate is left wide open here, so every
# refusal observed below can only have come from the provider or credential
# layer that is full.
LAYERED_GATE = 256
LAYERED_PROVIDER_CONCURRENCY = 2
LAYERED_CREDENTIAL_WEBSOCKETS = 2
LAYERED_CREDENTIAL_RATE = 4

observed_upstream = set()
active_upstream = 0
accepted_upstream = 0
upstream_lock = threading.Lock()
release_hold = threading.Event()
log_db_lock = threading.Lock()


def exact(stream, size):
    data = b''
    while len(data) < size:
        chunk = stream.read(size - len(data))
        if not chunk:
            raise EOFError()
        data += chunk
    return data


class Upstream(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *_):
        pass

    def handle_one_request(self):
        # Load generators abandon bounded connections; that is expected.
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, TimeoutError, OSError):
            self.close_connection = True

    def do_POST(self):
        global active_upstream
        body = exact(self.rfile, int(self.headers.get('content-length', '0')))
        mode = self.headers.get('x-test-mode', 'sse')
        with log_db_lock:
            observed_upstream.add(mode)
        with upstream_lock:
            active_upstream += 1
        try:
            streaming = mode in ('sse', 'hold', 'slow')
            self.send_response(200)
            self.send_header('content-type', 'text/event-stream' if streaming else 'application/octet-stream')
            self.send_header('transfer-encoding', 'chunked')
            self.end_headers()
            self.wfile.write(f'{len(SSE[:3]):x}\r\n'.encode() + SSE[:3] + b'\r\n')
            self.wfile.flush()
            if mode == 'hold':
                while not release_hold.wait(.02):
                    self.wfile.write(b'1\r\nx\r\n')
                    self.wfile.flush()
            elif mode == 'slow':
                # A slow consumer: bytes arrive far below the driver's read rate.
                for index in range(4):
                    self.wfile.write(f'{len(SSE[3:]):x}\r\n'.encode() + SSE[3:] + b'\r\n')
                    self.wfile.flush()
                    time.sleep(.25)
            else:
                self.wfile.write(f'{len(SSE[3:]):x}\r\n'.encode() + SSE[3:] + b'\r\n')
                self.wfile.flush()
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass
        finally:
            with upstream_lock:
                active_upstream -= 1

    def do_GET(self):
        global active_upstream
        with log_db_lock:
            observed_upstream.add('websocket')
        key = self.headers['Sec-WebSocket-Key']
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        self.wfile.flush()
        with upstream_lock:
            active_upstream += 1
        try:
            while True:
                first, length = exact(self.rfile, 2)
                size = length & 127
                if size == 126:
                    size = struct.unpack('!H', exact(self.rfile, 2))[0]
                mask = exact(self.rfile, 4) if length & 128 else b'\0' * 4
                data = exact(self.rfile, size)
                data = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
                if size < 126:
                    head = bytes([first, size])
                elif size < 65536:
                    head = bytes([first, 126]) + struct.pack('!H', size)
                else:
                    head = bytes([first, 127]) + struct.pack('!Q', size)
                self.wfile.write(head + data)
                self.wfile.flush()
                if first & 15 == 8:
                    break
        except (EOFError, OSError):
            pass
        finally:
            self.close_connection = True
            with upstream_lock:
                active_upstream -= 1


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(predicate, description, timeout=30):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError(description)


def exchange(port, method, path, body=b'', headers=None, timeout=15):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
    try:
        connection.request(method, path, body, headers or {})
        response = connection.getresponse()
        return response.status, dict(response.getheaders()), response.read()
    finally:
        connection.close()


def websocket_pair(port, credential):
    sock = socket.create_connection(('127.0.0.1', port), timeout=15)
    sock.sendall((f'GET /v1/responses HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\n'
                  'Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n'
                  'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n').encode())
    stream = sock.makefile('rb')
    status = stream.readline()
    if b'101' not in status:
        raise AssertionError(f'upgrade refused: {status!r} {stream.read(4096)!r}')
    while stream.readline() != b'\r\n':
        pass
    return sock, stream


def send_text(sock, payload):
    """Sends a masked client text frame using the smallest legal length form."""
    mask = b'abcd'
    masked = bytes(v ^ mask[i % 4] for i, v in enumerate(payload))
    if len(payload) < 126:
        header = bytes([0x81, 0x80 | len(payload)])
    elif len(payload) < 65536:
        header = bytes([0x81, 0x80 | 126]) + len(payload).to_bytes(2, 'big')
    else:
        header = bytes([0x81, 0x80 | 127]) + len(payload).to_bytes(8, 'big')
    sock.sendall(header + mask + masked)


def rss_kib(pid):
    output = subprocess.run(['ps', '-o', 'rss=', '-p', str(pid)], capture_output=True, check=True)
    return int(output.stdout.decode().strip())


def open_http_stream(port, credential, mode, opened):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=20)
    connection.request('POST', '/v1/responses', PAYLOAD, {
        'authorization': 'Bearer ' + credential,
        'x-test-mode': mode,
    })
    response = connection.getresponse()
    assert response.status == 200, response.status
    first = response.read(3)
    opened.append((response, connection))
    return first


def start_gateway(directory, db_name, capacity, log_queue, password_concurrency=None, idle_per_host=None):
    data_port, admin_port = free_port(), free_port()
    db = directory / db_name
    values = {
        'DATA_LISTEN_ADDR': f'127.0.0.1:{data_port}', 'ADMIN_LISTEN_ADDR': f'127.0.0.1:{admin_port}',
        'DATABASE_URL': f'sqlite://{db}', 'MASTER_KEY': '11' * 32,
        'ADMIN_PASSWORD_HASH': os.environ['TEST_ADMIN_HASH'], 'ADMIN_PASSWORD': 'test-admin',
        'DEVELOPMENT_MODE': 'true',
        'UPSTREAM_CONNECT_TIMEOUT_MS': '2000', 'UPSTREAM_HEADER_TIMEOUT_MS': '10000',
        'STREAM_IDLE_TIMEOUT_MS': '60000', 'SHUTDOWN_DRAIN_TIMEOUT_MS': '3000', 'LOG_FLUSH_TIMEOUT_MS': '5000',
        'DATABASE_MAX_CONNECTIONS': '16', 'MAX_PROXY_CONNECTIONS': str(capacity),
        'DATA_MAX_CONNECTIONS': str(capacity + 32), 'ADMIN_MAX_CONNECTIONS': '64',
        'HTTP_BUFFER_BYTES': '65536',
        'WEBSOCKET_MAX_FRAME_BYTES': '1048576', 'WEBSOCKET_MAX_MESSAGE_BYTES': '8388608',
        'WEBSOCKET_QUEUE_CAPACITY': '32', 'LOG_QUEUE_CAPACITY': str(log_queue),
        'LOG_BATCH_SIZE': '64', 'LOG_BATCH_INTERVAL_MS': '20',
    }
    if password_concurrency is not None:
        values['PASSWORD_MAX_CONCURRENCY'] = str(password_concurrency)
    if idle_per_host is not None:
        values['UPSTREAM_IDLE_PER_HOST'] = str(idle_per_host)
    env = dict(os.environ, **{f'TOKENSTREAM_{key}': value for key, value in values.items()})
    process = subprocess.Popen([os.environ['GATEWAY_BINARY']], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wait_for(lambda: process.poll() is None and _listening(admin_port), 'gateway did not listen')
    return process, data_port, admin_port, db


def machine_info():
    memory = os.environ.get('TOKENSTREAM_LOAD_MACHINE_MEMORY', 'unspecified')
    return {
        'system': platform.system(),
        'release': platform.release(),
        'machine': platform.machine(),
        'cpus': os.cpu_count() or 1,
        'memory': memory,
    }


def fd_count(pid):
    proc = Path(f'/proc/{pid}/fd')
    if proc.is_dir():
        return len(list(proc.iterdir()))
    output = subprocess.run(['lsof', '-nP', '-p', str(pid)], capture_output=True)
    if output.returncode != 0:
        return 0
    lines = output.stdout.decode().splitlines()
    return max(0, len(lines) - 1)


def percentile(values, fraction):
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def reset_upstream_stats():
    global accepted_upstream
    with upstream_lock:
        accepted_upstream = 0
    observed_upstream.clear()


def accepted_count():
    with upstream_lock:
        return accepted_upstream


def timed_proxy_request(port, headers, timeout=20):
    started = time.monotonic()
    try:
        status, _, _ = exchange(port, 'POST', '/v1/responses', PAYLOAD, headers, timeout=timeout)
        return status, time.monotonic() - started, None
    except Exception as error:
        return None, time.monotonic() - started, repr(error)


def run_short_requests(port, headers, count, parallelism):
    statuses = []
    latencies = []
    errors = []
    gate = threading.Semaphore(parallelism)

    def one(_index):
        with gate:
            return timed_proxy_request(port, headers)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, parallelism)) as pool:
        for status, latency, error in pool.map(one, range(count)):
            latencies.append(latency)
            if error is not None:
                errors.append(error)
            else:
                statuses.append(status)
    success = sum(1 for status in statuses if status == 200)
    rejected = sum(1 for status in statuses if status == 503)
    other = len(statuses) - success - rejected
    return {
        'success': success,
        'rejected': rejected,
        'other': other,
        'errors': errors,
        'p50': percentile(latencies, 0.50),
        'p95': percentile(latencies, 0.95),
        'p99': percentile(latencies, 0.99),
        'latencies': latencies,
    }


def summarise_short(label, stats, accepts, rss, fds):
    print(f'  {label}: success {stats["success"]}  rejected {stats["rejected"]}  '
          f'other {stats["other"]}  errors {len(stats["errors"])}  '
          f'p50 {stats["p50"]:.3f}s  p95 {stats["p95"]:.3f}s  p99 {stats["p99"]:.3f}s  '
          f'upstream_accepts {accepts}  rss {rss} KiB  fds {fds}')
    assert not stats['errors'], stats['errors']
    assert stats['other'] == 0, stats
    assert stats['p99'] <= MAX_SHORT_REQUEST_P99_S, stats
    return stats


def _listening(port):
    try:
        return exchange(port, 'GET', '/healthz', timeout=2)[0] == 200
    except OSError:
        return False


def authenticate(admin_port, name='admin', password='test-admin'):
    status, headers, body = exchange(admin_port, 'POST', '/admin/api/session', json.dumps({'name': name, 'password': password}).encode())
    assert status == 200, (status, body)
    return {
        'Cookie': headers['set-cookie'].split(';')[0],
        'x-csrf-token': json.loads(body)['csrf_token'],
        'content-type': 'application/json',
    }


def create_provider(admin_port, auth, name, endpoint):
    body = json.dumps({
        'name': name, 'protocol_type': 'openai', 'endpoint': endpoint,
        'upstream_api_key': 'upstream-secret', 'status': 'enabled',
    }).encode()
    status, _, response = exchange(admin_port, 'POST', '/admin/api/providers', body, auth)
    assert status == 201, (status, response)
    return issue_credential(admin_port, auth, name, json.loads(response)['id'])


def create_limited_provider(admin_port, auth, name, endpoint, concurrency, rate):
    """A provider that carries its own admission bounds."""
    body = json.dumps({
        'name': name, 'protocol_type': 'openai', 'endpoint': endpoint,
        'upstream_api_key': 'upstream-secret', 'status': 'enabled',
        'max_concurrent_requests': concurrency, 'max_requests_per_second': rate,
    }).encode()
    status, _, response = exchange(admin_port, 'POST', '/admin/api/providers', body, auth)
    assert status == 201, (status, response)
    return json.loads(response)['id']


def create_limited_credential(admin_port, auth, name, provider_id, concurrency, rate, websockets):
    """A credential that carries its own admission bounds."""
    body = json.dumps({
        'account_id': 1, 'name': name, 'provider_ids': [provider_id],
        'default_provider_id': provider_id, 'status': 'enabled',
        'max_concurrent_requests': concurrency,
        'max_requests_per_second': rate,
        'max_websockets': websockets,
    }).encode()
    status, _, response = exchange(admin_port, 'POST', '/admin/api/api-keys', body, auth)
    assert status == 201, (status, response)
    return json.loads(response)['api_key_secret']


def issue_credential(admin_port, auth, name, provider_id):
    """A provider no longer issues credentials; an account owns them."""
    body = json.dumps({
        'account_id': 1, 'name': f'key-{name}', 'provider_ids': [provider_id],
        'default_provider_id': provider_id, 'status': 'enabled',
    }).encode()
    status, _, response = exchange(admin_port, 'POST', '/admin/api/api-keys', body, auth)
    assert status == 201, (status, response)
    return json.loads(response)['api_key_secret']


def metrics(admin_port, auth):
    return exchange(admin_port, 'GET', '/metrics', headers=auth)[2].decode()


def metric_value(rendered, name, labels=''):
    for line in rendered.splitlines():
        if line.startswith(name + labels + ' '):
            return int(line.split()[1])
    raise AssertionError(f'metric {name}{labels} is missing')


# Drops are attributed to the subscriber that lost them, so a lagging consumer is
# distinguishable from a healthy one. The request-log subscriber is the one the
# load profile exercises.
REQUEST_LOG_DROPPED = 'tokenstream_event_subscriber_events_dropped_total'
REQUEST_LOG_LABELS = '{subscriber="request_log"}'


def request_log_drops(rendered):
    return metric_value(rendered, REQUEST_LOG_DROPPED, REQUEST_LOG_LABELS)


def stop(process):
    if process.poll() is None:
        process.send_signal(2)
        assert process.wait(timeout=30) == 0


class ConcurrentUpstream(http.server.ThreadingHTTPServer):
    """Accepts connections on their own threads.

    The stock threaded server still accepts in the serving thread, so a handful
    of long-lived held responses would starve later handshakes. A load profile
    must never make the upstream the bottleneck it is meant to measure.
    """

    daemon_threads = True
    request_queue_size = 256

    def process_request(self, request, client_address):
        global accepted_upstream
        with upstream_lock:
            accepted_upstream += 1
        threading.Thread(target=self._handle, args=(request, client_address), daemon=True).start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)


def run():
    info = machine_info()
    print('load machine:', info)
    print('thresholds: default hashing 4 (data 3); steady '
          f'{STEADY_SECONDS:.0f}s of {HTTP_CLIENTS} HTTP + {WEBSOCKET_CLIENTS} WebSocket; '
          f'RSS spread <= {MAX_STEADY_RSS_SPREAD_KIB} KiB; FD spread <= {MAX_STEADY_FD_SPREAD}; '
          f'short-request p99 <= {MAX_SHORT_REQUEST_P99_S}s; admitted success 100%; '
          'raised hashing budgets are not a substitute for this default-configuration run')
    upstream = ConcurrentUpstream(('127.0.0.1', 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_endpoint = f'http://127.0.0.1:{upstream.server_port}/prefix'
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        reset_upstream_stats()
        # Default hashing budget (4, not a raised 32). Admission is large enough
        # for the documented mixed set plus a burst margin.
        process, data_port, admin_port, db = start_gateway(
            directory, 'load.db', capacity=64, log_queue=4096)
        opened = []
        try:
            auth = authenticate(admin_port)
            credential = create_provider(admin_port, auth, 'load', upstream_endpoint)
            headers = {'authorization': 'Bearer ' + credential}
            auth_slots = threading.Semaphore(DEFAULT_DATA_HASH_SLOTS)

            print(f'default-config warmup {HTTP_CLIENTS} HTTP and {WEBSOCKET_CLIENTS} WebSocket clients')
            http_errors = []

            def hold_http(_index):
                try:
                    with auth_slots:
                        assert open_http_stream(data_port, credential, 'hold', opened) == SSE[:3]
                except Exception as error:  # recorded, asserted after the window
                    http_errors.append(repr(error))

            def hold_ws(_index):
                with auth_slots:
                    return websocket_pair(data_port, credential)

            with concurrent.futures.ThreadPoolExecutor(max_workers=HTTP_CLIENTS + WEBSOCKET_CLIENTS + 8) as pool:
                http_futures = [pool.submit(hold_http, index) for index in range(HTTP_CLIENTS)]
                ws_futures = [pool.submit(hold_ws, index) for index in range(WEBSOCKET_CLIENTS)]
                for future in http_futures:
                    future.result(timeout=90)
                ws_clients = [future.result(timeout=90) for future in ws_futures]
                time.sleep(RAMP_UP_SECONDS)
                assert not http_errors, http_errors

                rendered = metrics(admin_port, auth)
                assert metric_value(rendered, 'tokenstream_active_http_requests') == HTTP_CLIENTS, rendered
                assert metric_value(rendered, 'tokenstream_active_websockets') == WEBSOCKET_CLIENTS, rendered

                print(f'sampling the gateway process for {STEADY_SECONDS:.0f}s of default-config steady state')
                samples = []
                fds = []
                steady_started = time.monotonic()
                progress_at = 0
                while time.monotonic() - steady_started < STEADY_SECONDS:
                    for sock, _ in ws_clients:
                        send_text(sock, WS_MESSAGE)
                    samples.append(rss_kib(process.pid))
                    fds.append(fd_count(process.pid))
                    elapsed = time.monotonic() - steady_started
                    if elapsed >= progress_at:
                        print(f'  steady {elapsed:5.1f}s  rss {samples[-1] // 1024} MiB  '
                              f'fds {fds[-1]}  '
                              f'http {metric_value(metrics(admin_port, auth), "tokenstream_active_http_requests")}'
                              f'  ws {metric_value(metrics(admin_port, auth), "tokenstream_active_websockets")}')
                        progress_at += 5
                    time.sleep(SAMPLE_INTERVAL)
                steady = samples[WARMUP_SAMPLES:]
                steady_fds = fds[WARMUP_SAMPLES:]
                assert len(steady) >= 20, f'too few steady samples: {len(steady)}'
                spread = max(steady) - min(steady)
                fd_spread = max(steady_fds) - min(steady_fds)
                print(f'  steady RSS spread {spread} KiB over {len(steady)} samples '
                      f'(warmup {samples[:WARMUP_SAMPLES]} -> {max(steady) // 1024} MiB)')
                print(f'  steady FD spread {fd_spread} over {len(steady_fds)} samples')
                assert spread <= MAX_STEADY_RSS_SPREAD_KIB, (
                    f'steady-state RSS spread {spread} KiB exceeded {MAX_STEADY_RSS_SPREAD_KIB} KiB')
                assert fd_spread <= MAX_STEADY_FD_SPREAD, (
                    f'steady-state FD spread {fd_spread} exceeded {MAX_STEADY_FD_SPREAD}')
                half = len(steady) // 2
                first_half, second_half = steady[:half], steady[half:]
                assert (sum(second_half) / len(second_half)) - (sum(first_half) / len(first_half)) <= MAX_STEADY_RSS_SPREAD_KIB / 2, (
                    'resident memory grew with connection age')

                rendered = metrics(admin_port, auth)
                assert metric_value(rendered, 'tokenstream_active_http_requests') == HTTP_CLIENTS, rendered
                assert metric_value(rendered, 'tokenstream_active_websockets') == WEBSOCKET_CLIENTS, rendered
                assert not http_errors, http_errors
                dropped_at_steady = request_log_drops(rendered)

                print('mixed short-request turnover while long-lived streams remain admitted')
                before_accepts = accepted_count()
                turnover = run_short_requests(
                    data_port, headers, TURNOVER_REQUESTS, DEFAULT_DATA_HASH_SLOTS)
                summarise_short(
                    'default mixed turnover',
                    turnover,
                    accepted_count() - before_accepts,
                    rss_kib(process.pid),
                    fd_count(process.pid),
                )
                assert turnover['success'] == TURNOVER_REQUESTS, turnover
                assert metric_value(metrics(admin_port, auth), 'tokenstream_active_http_requests') == HTTP_CLIENTS
                assert metric_value(metrics(admin_port, auth), 'tokenstream_active_websockets') == WEBSOCKET_CLIENTS

                print('bursting new authentications above the default hashing budget')
                burst_barrier = threading.Barrier(BURST_REQUESTS, timeout=30)

                def burst_once(_index):
                    burst_barrier.wait()
                    return timed_proxy_request(data_port, headers)

                burst_futures = [pool.submit(burst_once, index) for index in range(BURST_REQUESTS)]
                burst_results = [future.result(timeout=60) for future in burst_futures]
                burst_statuses = [status for status, _, error in burst_results if error is None]
                assert all(error is None for _, _, error in burst_results), burst_results
                assert all(status in (200, 503) for status in burst_statuses), burst_statuses
                assert any(status == 503 for status in burst_statuses), burst_statuses
                assert metric_value(metrics(admin_port, auth), 'tokenstream_active_http_requests') == HTTP_CLIENTS
                print(f'  burst statuses: {sorted(burst_statuses)}')

                print('exercising a slow database without stalling admitted streams')
                blocker = sqlite3.connect(str(db), timeout=8, isolation_level=None)
                try:
                    blocker.execute('BEGIN EXCLUSIVE')
                    status, latency, error = timed_proxy_request(data_port, headers, timeout=5)
                    assert latency < 4.5, (status, latency, error)
                    assert error is not None or status in (200, 503), (status, error)
                    assert metric_value(metrics(admin_port, auth), 'tokenstream_active_http_requests') == HTTP_CLIENTS
                    print(f'  locked lookup status={status} latency={latency:.3f}s error={error}')
                finally:
                    try:
                        blocker.execute('ROLLBACK')
                    except sqlite3.Error:
                        pass
                    blocker.close()
                wait_for(
                    lambda: exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200,
                    'the data plane did not recover after the database lock was released')

                print('releasing the long-lived clients and confirming capacity returns')
                peak_rss = max(samples)
                peak_fds = max(fds)
                for item in opened:
                    item[0].close()
                    item[1].close()
                opened.clear()
                for sock, stream in ws_clients:
                    sock.close()
                    stream.close()
                wait_for(lambda: active_upstream == 0, 'closed clients left upstream sessions alive')
                wait_for(
                    lambda: metric_value(metrics(admin_port, auth), 'tokenstream_active_http_requests') == 0
                    and metric_value(metrics(admin_port, auth), 'tokenstream_active_websockets') == 0,
                    'activity metrics did not return to zero')
                released_rss = rss_kib(process.pid)
                released_fds = fd_count(process.pid)
                print(f'  after release rss {released_rss} KiB (peak {peak_rss} KiB)  '
                      f'fds {released_fds} (peak {peak_fds})  dropped_logs {dropped_at_steady}')
                assert released_fds <= peak_fds, (released_fds, peak_fds)
                assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200

                print('exercising slow consumers')
                for _ in range(SLOW_CONSUMERS):
                    connection = http.client.HTTPConnection('127.0.0.1', data_port, timeout=20)
                    connection.request('POST', '/v1/responses', PAYLOAD, dict(headers, **{'x-test-mode': 'slow'}))
                    response = connection.getresponse()
                    assert response.status == 200
                    opened.append((response, connection))
                time.sleep(1.5)
                assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200, \
                    'a slow consumer blocked the proxy'
                for item in opened:
                    item[0].close()
                    item[1].close()
                opened.clear()

                print('exercising authentication pressure')
                barrier = threading.Barrier(AUTH_PRESSURE_CLIENTS, timeout=20)

                def authenticate_once(_index):
                    barrier.wait()
                    return exchange(admin_port, 'POST', '/admin/api/session', json.dumps({'name': 'admin', 'password': 'test-admin'}).encode())[0]

                auth_futures = [pool.submit(authenticate_once, index) for index in range(AUTH_PRESSURE_CLIENTS)]
                assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200
                auth_statuses = [future.result(timeout=60) for future in auth_futures]
                assert all(status in (200, 503) for status in auth_statuses), auth_statuses
                assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200

                print('exercising logging saturation without stalling the proxy')
                before_dropped = request_log_drops(metrics(admin_port, auth))
                for _ in range(80):
                    exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)
                rendered = metrics(admin_port, auth)
                assert metric_value(rendered, 'tokenstream_active_http_requests') == 0, rendered
                after_dropped = request_log_drops(rendered)
                assert after_dropped >= before_dropped
                print(f'  dropped logs {before_dropped} -> {after_dropped}')

            print('stopping the default-config gateway')
            stop(process)
            wait_for(lambda: active_upstream == 0, 'shutdown left upstream sessions alive')
            rows = sqlite3.connect(db).execute(
                'select transport_type, count(*) from request_log group by transport_type').fetchall()
            print('  request log rows by transport:', dict(rows))
            print('  upstream modes exercised:', sorted(observed_upstream))
            assert {'sse', 'hold', 'slow', 'websocket'} <= observed_upstream, observed_upstream
            assert dict(rows).get('http', 0) > 0
            assert dict(rows).get('websocket', 0) > 0
            print('passed default-config mixed load, steady state and pressure paths')

            print('comparing bounded HTTP reuse against no reuse under short-request load')
            reuse_rows = []
            for label, idle in [('no_reuse', 0), ('bounded_reuse', 8)]:
                reset_upstream_stats()
                candidate, cand_data, cand_admin, _cand_db = start_gateway(
                    directory, f'{label}.db', capacity=64, log_queue=1024, idle_per_host=idle)
                try:
                    cand_auth = authenticate(cand_admin)
                    cand_credential = create_provider(cand_admin, cand_auth, label, upstream_endpoint)
                    cand_headers = {'authorization': 'Bearer ' + cand_credential}
                    before = accepted_count()
                    stats = run_short_requests(
                        cand_data, cand_headers, REUSE_REQUESTS, DEFAULT_DATA_HASH_SLOTS)
                    accepts = accepted_count() - before
                    rss = rss_kib(candidate.pid)
                    fds = fd_count(candidate.pid)
                    summarise_short(label, stats, accepts, rss, fds)
                    assert stats['success'] == REUSE_REQUESTS, stats
                    reuse_rows.append((label, stats, accepts, rss, fds))
                finally:
                    stop(candidate)
            no_reuse, bounded = reuse_rows
            print(f'  connection delta: no_reuse {no_reuse[2]} accepts -> bounded_reuse {bounded[2]} accepts; '
                  f'p50 {no_reuse[1]["p50"]:.3f}s -> {bounded[1]["p50"]:.3f}s; '
                  f'rss {no_reuse[3]} -> {bounded[3]} KiB; fds {no_reuse[4]} -> {bounded[4]}')
            assert bounded[2] < no_reuse[2], reuse_rows
            assert bounded[3] <= no_reuse[3] + 32 * 1024, reuse_rows
            print('passed bounded reuse comparison; idle HTTP connections stay enabled')

            print('declared admission with the default hashing budget')
            reset_upstream_stats()
            declared, declared_data, declared_admin, _declared_db = start_gateway(
                directory, 'declared.db', capacity=DECLARED_ADMISSION, log_queue=4096)
            try:
                declared_auth = authenticate(declared_admin)
                declared_credential = create_provider(
                    declared_admin, declared_auth, 'declared', upstream_endpoint)
                declared_headers = {'authorization': 'Bearer ' + declared_credential}
                declared_stats = run_short_requests(
                    declared_data, declared_headers, TURNOVER_REQUESTS, DEFAULT_DATA_HASH_SLOTS)
                summarise_short(
                    'declared turnover',
                    declared_stats,
                    accepted_count(),
                    rss_kib(declared.pid),
                    fd_count(declared.pid),
                )
                assert declared_stats['success'] == TURNOVER_REQUESTS, declared_stats
                declared_barrier = threading.Barrier(BURST_REQUESTS, timeout=30)

                def declared_burst(_index):
                    declared_barrier.wait()
                    return timed_proxy_request(declared_data, declared_headers)

                with concurrent.futures.ThreadPoolExecutor(max_workers=BURST_REQUESTS) as burst_pool:
                    declared_burst_results = [
                        future.result(timeout=60)
                        for future in [burst_pool.submit(declared_burst, index) for index in range(BURST_REQUESTS)]
                    ]
                declared_burst_statuses = [
                    status for status, _, error in declared_burst_results if error is None]
                assert all(error is None for _, _, error in declared_burst_results), declared_burst_results
                assert all(status in (200, 503) for status in declared_burst_statuses), declared_burst_statuses
                assert any(status == 503 for status in declared_burst_statuses), declared_burst_statuses
                print(f'  declared burst statuses: {sorted(declared_burst_statuses)}')
            finally:
                stop(declared)
            print('passed declared-admission profile; default hashing still sheds overload')

            print('exercising mixed near-limit admission and a storage fault')
            small, small_data, small_admin, small_db = start_gateway(
                directory, 'capacity.db', capacity=4, log_queue=64)
            small_opened = []
            small_ws = []
            try:
                small_auth = authenticate(small_admin)
                small_credential = create_provider(small_admin, small_auth, 'capacity', upstream_endpoint)
                small_headers = {'authorization': 'Bearer ' + small_credential}
                for _ in range(NEAR_LIMIT_HTTP):
                    assert open_http_stream(small_data, small_credential, 'hold', small_opened) == SSE[:3]
                for _ in range(NEAR_LIMIT_WEBSOCKET):
                    small_ws.append(websocket_pair(small_data, small_credential))
                status, _, body = exchange(small_data, 'POST', '/v1/responses', PAYLOAD, small_headers)
                assert status == 503 and b'connection_limit_reached' in body, (status, body)
                for item in small_opened:
                    item[0].close()
                    item[1].close()
                small_opened.clear()
                for sock, stream in small_ws:
                    sock.close()
                    stream.close()
                small_ws.clear()
                wait_for(lambda: exchange(small_data, 'POST', '/v1/responses', PAYLOAD, small_headers)[0] == 200,
                         'released permits were not reusable over real connections')

                print('exercising layered admission under a wide-open global gate')
                layered, layered_data, layered_admin, _ = start_gateway(
                    directory, 'layered.db', capacity=LAYERED_GATE, log_queue=4096)
                layered_opened = []
                layered_ws = []
                try:
                    layered_auth = authenticate(layered_admin)
                    # The provider bounds concurrency only, so a refusal here can
                    # only be the provider layer shedding.
                    provider_id = create_limited_provider(
                        layered_admin, layered_auth, 'layered-provider',
                        upstream_endpoint, LAYERED_PROVIDER_CONCURRENCY, None)
                    provider_credential = create_limited_credential(
                        layered_admin, layered_auth, 'key-provider', provider_id,
                        None, None, None)
                    provider_headers = {'authorization': 'Bearer ' + provider_credential}
                    for _ in range(LAYERED_PROVIDER_CONCURRENCY):
                        assert open_http_stream(
                            layered_data, provider_credential, 'hold', layered_opened) == SSE[:3]
                    before = accepted_upstream
                    status, _, body = exchange(
                        layered_data, 'POST', '/v1/responses', PAYLOAD, provider_headers)
                    assert status == 503 and b'connection_limit_reached' in body, (status, body)
                    assert accepted_upstream == before, 'a refused request reached the upstream'
                    for item in layered_opened:
                        item[0].close()
                        item[1].close()
                    layered_opened.clear()
                    wait_for(lambda: exchange(layered_data, 'POST', '/v1/responses', PAYLOAD,
                                              provider_headers)[0] == 200,
                             'the provider layer did not release its slots')

                    # The credential bounds long-lived connections and its request
                    # rate. The global gate and the provider layer are both far
                    # from full, so these refusals can only be the credential's.
                    ws_provider_id = create_limited_provider(
                        layered_admin, layered_auth, 'layered-ws',
                        upstream_endpoint, None, None)
                    ws_credential = create_limited_credential(
                        layered_admin, layered_auth, 'key-ws', ws_provider_id,
                        None, LAYERED_CREDENTIAL_RATE, LAYERED_CREDENTIAL_WEBSOCKETS)
                    ws_headers = {'authorization': 'Bearer ' + ws_credential}
                    for _ in range(LAYERED_CREDENTIAL_WEBSOCKETS):
                        layered_ws.append(websocket_pair(layered_data, ws_credential))
                    before = accepted_upstream
                    # The long-lived bound is only reached by another socket, so
                    # the refusal is read from an upgrade attempt rather than from
                    # a plain request.
                    refused_sock = socket.create_connection(
                        ('127.0.0.1', layered_data), timeout=15)
                    refused_sock.sendall(
                        (f'GET /v1/responses HTTP/1.1\r\nHost: localhost\r\n'
                         f'Authorization: Bearer {ws_credential}\r\n'
                         'Connection: Upgrade\r\nUpgrade: websocket\r\n'
                         'Sec-WebSocket-Version: 13\r\n'
                         'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n').encode())
                    refused_stream = refused_sock.makefile('rb')
                    refusal = refused_stream.read(4096)
                    assert b'503' in refusal and b'connection_limit_reached' in refusal, refusal
                    assert accepted_upstream == before, 'a refused connection reached the upstream'
                    refused_sock.close()
                    refused_stream.close()

                    # A plain request does not consume the long-lived bound: the
                    # sockets above are still holding every one of its slots.
                    assert exchange(layered_data, 'POST', '/v1/responses', PAYLOAD,
                                    ws_headers)[0] == 200
                    for sock, stream in layered_ws:
                        sock.close()
                        stream.close()
                    layered_ws.clear()
                    wait_for(lambda: exchange(layered_data, 'POST', '/v1/responses', PAYLOAD,
                                              ws_headers)[0] == 200,
                             'the credential layers did not release their slots')

                    # The rate bound is the only one still in play here, and it
                    # is a per-second allowance, so the requests have to arrive
                    # together rather than one after another.
                    rate_provider_id = create_limited_provider(
                        layered_admin, layered_auth, 'layered-rate',
                        upstream_endpoint, None, None)
                    rate_credential = create_limited_credential(
                        layered_admin, layered_auth, 'key-rate', rate_provider_id,
                        None, LAYERED_CREDENTIAL_RATE, None)
                    rate_headers = {'authorization': 'Bearer ' + rate_credential}

                    def burst_once():
                        return exchange(layered_data, 'POST', '/v1/responses',
                                        PAYLOAD, rate_headers)[0]

                    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as burst_pool:
                        statuses = list(burst_pool.map(
                            lambda _: burst_once(), range(LAYERED_CREDENTIAL_RATE * 6)))
                    refused = sum(1 for value in statuses if value == 503)
                    assert refused > 0, \
                        f'the credential rate bound never refused anything: {statuses}'
                    print(f'  the provider, connection, and rate bounds each shed load')
                    stop(layered)
                finally:
                    for item in layered_opened:
                        try:
                            item[0].close()
                            item[1].close()
                        except OSError:
                            pass
                    for sock, stream in layered_ws:
                        try:
                            sock.close()
                            stream.close()
                        except OSError:
                            pass
                    if layered.poll() is None:
                        layered.kill()
                        layered.wait(timeout=10)
                print('passed layered admission under a wide-open global gate')

                print('exercising a logging storage fault while the proxy keeps serving')
                dropped_before = request_log_drops(metrics(small_admin, small_auth))
                fault = sqlite3.connect(small_db, timeout=5, isolation_level=None)
                fault.execute(FAULT_TRIGGER)
                fault.close()
                try:
                    for _ in range(100):
                        fault_status, _, fault_body = exchange(
                            small_data, 'POST', '/v1/responses', PAYLOAD, small_headers)
                        assert fault_status == 200, (fault_status, fault_body[:200])
                finally:
                    repair = sqlite3.connect(small_db, timeout=5, isolation_level=None)
                    repair.execute('DROP TRIGGER request_log_write_fault')
                    repair.close()
                assert exchange(small_data, 'POST', '/v1/responses', PAYLOAD, small_headers)[0] == 200
                assert request_log_drops(metrics(small_admin, small_auth)) > dropped_before, \
                    'the failing logging path dropped no events'
                print('  the proxy kept serving while every log write failed')
                stop(small)
            finally:
                for item in small_opened:
                    try:
                        item[0].close()
                        item[1].close()
                    except OSError:
                        pass
                for sock, stream in small_ws:
                    try:
                        sock.close()
                        stream.close()
                    except OSError:
                        pass
                if small.poll() is None:
                    small.kill()
                    small.wait(timeout=10)
            print('passed mixed near-limit admission and storage fault paths')
        finally:
            release_hold.set()
            for item in opened:
                try:
                    item[0].close()
                    item[1].close()
                except OSError:
                    pass
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)
            print('gateway stderr:', process.stderr.read().decode()[:4000])
    upstream.shutdown()
    upstream.server_close()


if __name__ == '__main__':
    run()
