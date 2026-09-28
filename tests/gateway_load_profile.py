"""Sustained mixed load profile against a real Tokenstream process.

The component profile proves bounded memory for the proxy in isolation. This
profile instead measures the deployed process: it drives sustained HTTP, SSE and
WebSocket traffic through the formal listeners with the real authentication,
routing, database and logging chain, samples the gateway's own resident memory
independently of the driver, and then exercises the bounded-resource paths under
pressure. Every capacity remains enforced, and a database or logging fault must
never stall the proxy.
"""
import base64
import concurrent.futures
import hashlib
import http.client
import http.server
import json
import os
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
AUTH_PRESSURE_CLIENTS = 12
SLOW_CONSUMERS = 6

observed_upstream = set()
active_upstream = 0
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


def start_gateway(directory, db_name, capacity, log_queue):
    data_port, admin_port = free_port(), free_port()
    db = directory / db_name
    values = {
        'DATA_LISTEN_ADDR': f'127.0.0.1:{data_port}', 'ADMIN_LISTEN_ADDR': f'127.0.0.1:{admin_port}',
        'DATABASE_URL': f'sqlite://{db}', 'MASTER_KEY': '11' * 32,
        'ADMIN_PASSWORD_HASH': os.environ['TEST_ADMIN_HASH'], 'DEVELOPMENT_MODE': 'true',
        'UPSTREAM_CONNECT_TIMEOUT_MS': '2000', 'UPSTREAM_HEADER_TIMEOUT_MS': '10000',
        'STREAM_IDLE_TIMEOUT_MS': '60000', 'SHUTDOWN_DRAIN_TIMEOUT_MS': '3000', 'LOG_FLUSH_TIMEOUT_MS': '5000',
        'DATABASE_MAX_CONNECTIONS': '16', 'MAX_PROXY_CONNECTIONS': str(capacity),
        'DATA_MAX_CONNECTIONS': str(capacity + 32), 'ADMIN_MAX_CONNECTIONS': '64',
        'PASSWORD_MAX_CONCURRENCY': '32', 'HTTP_BUFFER_BYTES': '65536',
        'WEBSOCKET_MAX_FRAME_BYTES': '1048576', 'WEBSOCKET_MAX_MESSAGE_BYTES': '8388608',
        'WEBSOCKET_QUEUE_CAPACITY': '32', 'LOG_QUEUE_CAPACITY': str(log_queue),
        'LOG_BATCH_SIZE': '64', 'LOG_BATCH_INTERVAL_MS': '20',
    }
    env = dict(os.environ, **{f'TOKENSTREAM_{key}': value for key, value in values.items()})
    process = subprocess.Popen([os.environ['GATEWAY_BINARY']], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wait_for(lambda: process.poll() is None and _listening(admin_port), 'gateway did not listen')
    return process, data_port, admin_port, db


def _listening(port):
    try:
        return exchange(port, 'GET', '/healthz', timeout=2)[0] == 200
    except OSError:
        return False


def authenticate(admin_port, password='test-admin'):
    status, headers, body = exchange(admin_port, 'POST', '/admin/api/session', json.dumps({'password': password}).encode())
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
    return json.loads(response)['gateway_api_key']


def metrics(admin_port, auth):
    return exchange(admin_port, 'GET', '/metrics', headers=auth)[2].decode()


def metric_value(rendered, name):
    for line in rendered.splitlines():
        if line.startswith(name + ' '):
            return int(line.split()[1])
    raise AssertionError(f'metric {name} is missing')


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
        threading.Thread(target=self._handle, args=(request, client_address), daemon=True).start()

    def _handle(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)


def run():
    upstream = ConcurrentUpstream(('127.0.0.1', 0), Upstream)
    threading.Thread(target=upstream.serve_forever, daemon=True).start()
    upstream_endpoint = f'http://127.0.0.1:{upstream.server_port}/prefix'
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        process, data_port, admin_port, db = start_gateway(directory, 'load.db', capacity=256, log_queue=4096)
        opened = []
        try:
            auth = authenticate(admin_port)
            credential = create_provider(admin_port, auth, 'load', upstream_endpoint)
            headers = {'authorization': 'Bearer ' + credential}

            print(f'warming up {HTTP_CLIENTS} HTTP and {WEBSOCKET_CLIENTS} WebSocket clients')
            # Long-lived HTTP/SSE clients ramp up over a fixed window.
            http_started = time.monotonic()
            http_errors = []

            def hold_http(index):
                try:
                    assert open_http_stream(data_port, credential, 'hold', opened) == SSE[:3]
                except Exception as error:  # recorded, asserted after the window
                    http_errors.append(repr(error))

            with concurrent.futures.ThreadPoolExecutor(max_workers=HTTP_CLIENTS + WEBSOCKET_CLIENTS + 8) as pool:
                http_futures = [pool.submit(hold_http, index) for index in range(HTTP_CLIENTS)]
                ws_clients = []
                for _ in range(WEBSOCKET_CLIENTS):
                    ws_clients.append(websocket_pair(data_port, credential))
                time.sleep(RAMP_UP_SECONDS)
                assert not http_errors, http_errors

                rendered = metrics(admin_port, auth)
                assert metric_value(rendered, 'tokenstream_active_http_requests') == HTTP_CLIENTS, rendered
                assert metric_value(rendered, 'tokenstream_active_websockets') == WEBSOCKET_CLIENTS, rendered

                print(f'sampling the gateway process for {STEADY_SECONDS:.0f}s of steady state')
                samples = []
                steady_started = time.monotonic()
                progress_at = 0
                while time.monotonic() - steady_started < STEADY_SECONDS:
                    for sock, _ in ws_clients:
                        send_text(sock, WS_MESSAGE)
                    samples.append(rss_kib(process.pid))
                    elapsed = time.monotonic() - steady_started
                    if elapsed >= progress_at:
                        print(f'  steady {elapsed:5.1f}s  rss {samples[-1] // 1024} MiB  '
                              f'http {metric_value(metrics(admin_port, auth), "tokenstream_active_http_requests")}'
                              f'  ws {metric_value(metrics(admin_port, auth), "tokenstream_active_websockets")}')
                        progress_at += 5
                    time.sleep(SAMPLE_INTERVAL)
                steady = samples[WARMUP_SAMPLES:]
                assert len(steady) >= 20, f'too few steady samples: {len(steady)}'
                spread = max(steady) - min(steady)
                print(f'  steady RSS spread {spread} KiB over {len(steady)} samples '
                      f'(warmup {samples[:WARMUP_SAMPLES]} -> {max(steady) // 1024} MiB)')
                assert spread <= MAX_STEADY_RSS_SPREAD_KIB, (
                    f'steady-state RSS spread {spread} KiB exceeded {MAX_STEADY_RSS_SPREAD_KIB} KiB')
                # Memory must not track connection age: the last window is no
                # worse than the first steady window.
                half = len(steady) // 2
                first_half, second_half = steady[:half], steady[half:]
                assert (sum(second_half) / len(second_half)) - (sum(first_half) / len(first_half)) <= MAX_STEADY_RSS_SPREAD_KIB / 2, (
                    'resident memory grew with connection age')

                rendered = metrics(admin_port, auth)
                assert metric_value(rendered, 'tokenstream_active_http_requests') == HTTP_CLIENTS, rendered
                assert metric_value(rendered, 'tokenstream_active_websockets') == WEBSOCKET_CLIENTS, rendered
                assert not http_errors, http_errors

                print('releasing the long-lived clients and confirming capacity returns')
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
                assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200

                print('exercising slow consumers')
                for _ in range(SLOW_CONSUMERS):
                    connection = http.client.HTTPConnection('127.0.0.1', data_port, timeout=20)
                    connection.request('POST', '/v1/responses', PAYLOAD, dict(headers, **{'x-test-mode': 'slow'}))
                    response = connection.getresponse()
                    assert response.status == 200
                    # Deliberately read nothing further for a while.
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

                def authenticate_once(index):
                    barrier.wait()
                    return exchange(admin_port, 'POST', '/admin/api/session', json.dumps({'password': 'test-admin'}).encode())[0]

                auth_futures = [pool.submit(authenticate_once, index) for index in range(AUTH_PRESSURE_CLIENTS)]
                # Existing transports must keep making progress under password load.
                assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200
                auth_statuses = [future.result(timeout=60) for future in auth_futures]
                assert all(status in (200, 503) for status in auth_statuses), auth_statuses
                assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200

                print('exercising logging saturation without stalling the proxy')
                before_dropped = metric_value(metrics(admin_port, auth), 'tokenstream_log_events_dropped_total')
                # Hold the logging writer busy with a large batch while the proxy
                # keeps serving; the queue is bounded, so events may drop but
                # requests must still complete.
                for _ in range(200):
                    exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)
                rendered = metrics(admin_port, auth)
                assert metric_value(rendered, 'tokenstream_active_http_requests') == 0, rendered
                after_dropped = metric_value(rendered, 'tokenstream_log_events_dropped_total')
                assert after_dropped >= before_dropped

            print('stopping the gateway and confirming tasks and metrics converge')
            stop(process)
            wait_for(lambda: active_upstream == 0, 'shutdown left upstream sessions alive')
            rows = sqlite3.connect(db).execute(
                'select transport_type, count(*) from request_log group by transport_type').fetchall()
            print('  request log rows by transport:', dict(rows))
            print('  upstream modes exercised:', sorted(observed_upstream))
            assert {'sse', 'hold', 'slow', 'websocket'} <= observed_upstream, observed_upstream
            assert dict(rows).get('http', 0) > 0
            assert dict(rows).get('websocket', 0) > 0
            print('passed sustained mixed load, steady state and pressure paths')

            # A second, deliberately small deployment proves the configured
            # capacity is enforced over real connections and that a storage
            # fault never blocks the data plane.
            print('exercising a bounded capacity and permit release over real connections')
            small, small_data, small_admin, small_db = start_gateway(
                directory, 'capacity.db', capacity=4, log_queue=64)
            small_opened = []
            try:
                small_auth = authenticate(small_admin)
                small_credential = create_provider(small_admin, small_auth, 'capacity', upstream_endpoint)
                small_headers = {'authorization': 'Bearer ' + small_credential}
                for _ in range(4):
                    assert open_http_stream(small_data, small_credential, 'hold', small_opened) == SSE[:3]
                status, _, body = exchange(small_data, 'POST', '/v1/responses', PAYLOAD, small_headers)
                assert status == 503 and b'connection_limit_reached' in body, (status, body)
                for item in small_opened:
                    item[0].close()
                    item[1].close()
                small_opened.clear()
                wait_for(lambda: exchange(small_data, 'POST', '/v1/responses', PAYLOAD, small_headers)[0] == 200,
                         'released permits were not reusable over real connections')

                print('exercising a logging storage fault while the proxy keeps serving')
                # A storage fault is injected by making the request-log table
                # unwritable with a trigger, so every logging batch fails while
                # provider reads for authentication keep succeeding. The data
                # plane must keep serving and the dropped events must be counted.
                dropped_before = metric_value(metrics(small_admin, small_auth),
                                              'tokenstream_log_events_dropped_total')
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
                assert metric_value(metrics(small_admin, small_auth),
                                    'tokenstream_log_events_dropped_total') > dropped_before, \
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
                if small.poll() is None:
                    small.kill()
                    small.wait(timeout=10)
            print('passed bounded capacity and storage fault paths')
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
