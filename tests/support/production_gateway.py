"""Offline process contracts: real administration, proxy, TLS and shutdown."""
import concurrent.futures
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import signal
import socket
import sqlite3
import ssl
import struct
import subprocess
import tempfile
import threading
import time

PAYLOAD = b'opaque\x00unknown{not-json}'
SSE = b'data: opaque\n\ndata: [DONE]\n\n'
records = []
active = 0
lock = threading.Lock()
release = threading.Event()


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
        # Peers that abandon a bounded connection are expected, not a fault.
        try:
            super().handle_one_request()
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError, TimeoutError):
            self.close_connection = True

    def do_POST(self):
        global active
        if self.headers.get('x-test-mode') == 'slow-head':
            time.sleep(.6)
        body = exact(self.rfile, int(self.headers.get('content-length', '0')))
        records.append((self.path, dict(self.headers), body))
        with lock:
            active += 1
        try:
            streaming = self.headers.get('x-test-mode') in ('sse', 'hold')
            self.send_response(429 if self.headers.get('x-test-mode') == 'error' else 200)
            self.send_header('content-type', 'text/event-stream' if streaming else 'application/octet-stream')
            self.send_header('transfer-encoding', 'chunked')
            self.end_headers()
            chunks = [SSE[:3], SSE[3:]] if streaming else [PAYLOAD]
            for chunk in chunks:
                self.wfile.write(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
                self.wfile.flush()
            if self.headers.get('x-test-mode') == 'hold':
                while not release.wait(.03):
                    self.wfile.write(b'1\r\nx\r\n')
                    self.wfile.flush()
            self.wfile.write(b'0\r\n\r\n')
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, ssl.SSLError):
            pass
        finally:
            with lock:
                active -= 1

    def do_GET(self):
        global active
        records.append((self.path, dict(self.headers), b''))
        if self.headers.get('x-test-mode') == 'slow-head':
            time.sleep(.6)
        key = self.headers['Sec-WebSocket-Key']
        accept = base64.b64encode(hashlib.sha1((key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        self.wfile.flush()
        with lock:
            active += 1
        try:
            while True:
                first, length = exact(self.rfile, 2)
                size = length & 127
                if size == 126:
                    size = struct.unpack('!H', exact(self.rfile, 2))[0]
                mask = exact(self.rfile, 4) if length & 128 else b'\0' * 4
                data = exact(self.rfile, size)
                data = bytes(value ^ mask[i % 4] for i, value in enumerate(data))
                self.wfile.write(bytes([first, size]) + data)
                self.wfile.flush()
                if first & 15 == 8:
                    break
        except (EOFError, OSError):
            pass
        finally:
            self.close_connection = True
            with lock:
                active -= 1


def server(cert=None, key=None):
    srv = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Upstream)
    srv.daemon_threads = True
    if cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        srv.socket = context.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_for(predicate, description):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.025)
    raise AssertionError(description)


def exchange(port, method, path, body=b'', headers=None):
    connection = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
    connection.request(method, path, body, headers or {})
    response = connection.getresponse()
    result = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return result


def websocket(port, credential):
    sock = socket.create_connection(('127.0.0.1', port), timeout=5)
    sock.sendall((f'GET /v1/responses HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {credential}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n').encode())
    stream = sock.makefile('rb')
    assert b'101' in stream.readline()
    while stream.readline() != b'\r\n':
        pass
    for opcode, payload in [(1, b'opaque-text'), (2, PAYLOAD)]:
        mask = b'abcd'
        sock.sendall(bytes([128 | opcode, 128 | len(payload)]) + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(payload)))
        assert exact(stream, 2) == bytes([128 | opcode, len(payload)])
        assert exact(stream, len(payload)) == payload
    return sock, stream


def runtime_bounds(data_port, admin_port, credential, auth, capacity, opened, provider):
    headers = {'authorization': 'Bearer ' + credential}
    # Both planes close incomplete headers; an idle keep-alive also has a bound.
    for port in [data_port, admin_port]:
        sock = socket.create_connection(('127.0.0.1', port), timeout=2)
        sock.sendall(b'GET /healthz HTTP/1.1\r\nHost:')
        started = time.monotonic()
        try:
            received = sock.recv(4096)
            assert not received or b'408' in received
        except ConnectionResetError:
            pass
        assert .25 < time.monotonic() - started < 1.5
        sock.close()
    sock = socket.create_connection(('127.0.0.1', admin_port), timeout=2)
    sock.sendall(b'POST /admin/api/session HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{')
    started = time.monotonic()
    assert b'400' in sock.recv(4096)
    assert .1 < time.monotonic() - started < 1
    sock.close()

    for method in ['POST', 'GET']:
        slow = dict(headers, **{'x-test-mode': 'slow-head'})
        if method == 'GET':
            slow.update({'Connection': 'Upgrade', 'Upgrade': 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ=='})
        started = time.monotonic()
        status, _, body = exchange(data_port, method, '/v1/responses', b'', slow)
        assert status == 504, (status, body)
        assert time.monotonic() - started < .55, 'header deadline must not include connect allowance'

    # A TCP peer that never speaks TLS exercises the connection deadline.
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    stalled = []
    def stall():
        for _ in range(2):
            peer, _ = listener.accept()
            stalled.append(peer)
    thread = threading.Thread(target=stall, daemon=True)
    thread.start()
    key = provider('stalled-tls', 'openai', f'https://localhost:{listener.getsockname()[1]}')
    try:
        for method in ['POST', 'GET']:
            request_headers = {'authorization': 'Bearer ' + key}
            if method == 'GET':
                request_headers.update({'Connection': 'Upgrade', 'Upgrade': 'websocket', 'Sec-WebSocket-Version': '13', 'Sec-WebSocket-Key': 'dGhlIHNhbXBsZSBub25jZQ=='})
            started = time.monotonic()
            status, _, body = exchange(data_port, method, '/v1/responses', b'', request_headers)
            assert status == 504, (status, body)
            assert .2 < time.monotonic() - started < .65
    finally:
        listener.close()
        for peer in stalled:
            peer.close()

    sock, stream = websocket(data_port, credential)
    opened += [stream, sock]
    held = []
    for _ in range(capacity - 2):
        connection = http.client.HTTPConnection('127.0.0.1', data_port, timeout=4)
        connection.request('POST', '/v1/responses', PAYLOAD, dict(headers, **{'x-test-mode': 'hold'}))
        response = connection.getresponse()
        assert response.status == 200
        assert response.read(3) == SSE[:3]
        opened += [response, connection]
        held.append((response, connection))
    # Leave one proxy slot for authentication and saturate the independent password budget.
    barrier = threading.Barrier(17)
    def authenticate(index):
        barrier.wait(timeout=5)
        if index % 2:
            password = 'test-admin' if index % 4 == 1 else 'wrong-password'
            return exchange(admin_port, 'POST', '/admin/api/session', json.dumps({'password': password}).encode())[0]
        return exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as executor:
        futures = [executor.submit(authenticate, index) for index in range(16)]
        barrier.wait(timeout=5)
        # Existing transports make progress while correct and wrong password work runs.
        sock.sendall(b'\x89\x84abcd' + bytes(v ^ b'abcd'[i % 4] for i, v in enumerate(b'ping')))
        assert exact(stream, 2) == b'\x8a\x04'
        assert exact(stream, 4) == b'ping'
        assert held[0][0].read(1) == SSE[3:4]
        statuses = [future.result(timeout=5) for future in futures]
        assert all(status in (200, 401, 500, 503) for status in statuses), statuses
        assert 503 in statuses, statuses
    extra = http.client.HTTPConnection('127.0.0.1', data_port, timeout=4)
    extra.request('POST', '/v1/responses', PAYLOAD, dict(headers, **{'x-test-mode': 'hold'}))
    response = extra.getresponse()
    assert response.status == 200
    opened += [response, extra]
    response.read(3)
    status, _, body = exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)
    assert status == 503 and b'connection_limit_reached' in body
    metrics = exchange(admin_port, 'GET', '/metrics', headers=auth)[2]
    assert f'tokenstream_active_http_requests {capacity - 1}\n'.encode() in metrics, metrics
    assert b'tokenstream_active_websockets 1\n' in metrics, metrics
    response.close()
    extra.close()
    wait_for(lambda: exchange(data_port, 'POST', '/v1/responses', PAYLOAD, headers)[0] == 200, 'capacity not released')


def start(directory, name, master_key, development=True):
    """Starts a gateway process on its own ports and database, ready to serve."""
    data_port, admin_port = free_port(), free_port()
    values = {
        'DATA_LISTEN_ADDR': f'127.0.0.1:{data_port}', 'ADMIN_LISTEN_ADDR': f'127.0.0.1:{admin_port}',
        'DATABASE_URL': f'sqlite://{directory / (name + ".db")}', 'MASTER_KEY': master_key,
        'ADMIN_PASSWORD_HASH': os.environ['TEST_ADMIN_HASH'], 'DEVELOPMENT_MODE': str(development).lower(),
        'UPSTREAM_CONNECT_TIMEOUT_MS': '500', 'UPSTREAM_HEADER_TIMEOUT_MS': '1500',
        'STREAM_IDLE_TIMEOUT_MS': '10000', 'SHUTDOWN_DRAIN_TIMEOUT_MS': '150', 'LOG_FLUSH_TIMEOUT_MS': '1000',
        'DATABASE_MAX_CONNECTIONS': '4', 'MAX_PROXY_CONNECTIONS': '2', 'HTTP_BUFFER_BYTES': '65536',
        'WEBSOCKET_MAX_FRAME_BYTES': '65536', 'WEBSOCKET_MAX_MESSAGE_BYTES': '65536',
        'WEBSOCKET_QUEUE_CAPACITY': '4', 'LOG_QUEUE_CAPACITY': '128', 'LOG_BATCH_SIZE': '16',
        'LOG_BATCH_INTERVAL_MS': '10',
    }
    env = dict(os.environ, **{f'TOKENSTREAM_{key}': value for key, value in values.items()})
    process = subprocess.Popen([os.environ['GATEWAY_BINARY']], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def ready():
        assert process.poll() is None, process.stderr.read().decode()
        try:
            return exchange(admin_port, 'GET', '/healthz')[0] == 200
        except OSError:
            return False
    wait_for(ready, 'gateway did not listen')
    return process, data_port, admin_port


def stored_key_recovery(directory, plain):
    """A stored provider stays usable after a restart under the same master key.

    This is the process-level form of the stored-key recovery regression: a
    process that cannot re-open its own stored upstream keys, or that serves no
    request at all, is caught here rather than by a component test that never
    restarts anything.
    """
    first, data_port, admin_port = start(directory, 'recovery-first', '22' * 32)
    try:
        status, headers, body = exchange(admin_port, 'POST', '/admin/api/session', b'{"password":"test-admin"}')
        assert status == 200, body
        auth = {'Cookie': headers['set-cookie'].split(';')[0], 'x-csrf-token': json.loads(body)['csrf_token'], 'content-type': 'application/json'}
        created = json.dumps(dict(name='recovery', protocol_type='openai',
                                  endpoint=f'http://127.0.0.1:{plain.server_port}/prefix',
                                  upstream_api_key='upstream-secret', status='enabled')).encode()
        status, _, response = exchange(admin_port, 'POST', '/admin/api/providers', created, auth)
        assert status == 201, response
        credential = json.loads(response)['gateway_api_key']
        assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, {'authorization': 'Bearer ' + credential})[0] == 200
    finally:
        first.send_signal(signal.SIGINT)
        assert first.wait(timeout=5) == 0

    # A restart that loses the stored key, or that stops serving, must fail here.
    second, data_port, admin_port = start(directory, 'recovery-first', '22' * 32)
    try:
        status, _, body = exchange(data_port, 'POST', '/v1/responses', PAYLOAD, {'authorization': 'Bearer ' + credential})
        assert status == 200, (status, body)
    finally:
        second.send_signal(signal.SIGINT)
        assert second.wait(timeout=5) == 0
    print('passed stored upstream key recovery across a process restart')


def run_case(directory, trusted, untrusted, plain, development, capacity=None):

    global records
    data_port, admin_port = free_port(), free_port()
    db = directory / ('development.db' if development else 'production.db')
    values = {
        'DATA_LISTEN_ADDR': f'127.0.0.1:{data_port}', 'ADMIN_LISTEN_ADDR': f'127.0.0.1:{admin_port}',
        'DATABASE_URL': f'sqlite://{db}', 'MASTER_KEY': '11' * 32,
        'ADMIN_PASSWORD_HASH': os.environ['TEST_ADMIN_HASH'], 'DEVELOPMENT_MODE': str(development).lower(),
        'UPSTREAM_CONNECT_TIMEOUT_MS': '500', 'UPSTREAM_HEADER_TIMEOUT_MS': '1500',
        'STREAM_IDLE_TIMEOUT_MS': '10000', 'SHUTDOWN_DRAIN_TIMEOUT_MS': '150', 'LOG_FLUSH_TIMEOUT_MS': '1000',
        'DATABASE_MAX_CONNECTIONS': '4', 'MAX_PROXY_CONNECTIONS': '2', 'HTTP_BUFFER_BYTES': '65536',
        'WEBSOCKET_MAX_FRAME_BYTES': '65536', 'WEBSOCKET_MAX_MESSAGE_BYTES': '65536',
        'WEBSOCKET_QUEUE_CAPACITY': '4', 'LOG_QUEUE_CAPACITY': '128', 'LOG_BATCH_SIZE': '16',
        'LOG_BATCH_INTERVAL_MS': '10',
    }
    if capacity:
        db = directory / f'capacity-{capacity}.db'
        values.update(DATABASE_URL=f'sqlite://{db}', MAX_PROXY_CONNECTIONS=str(capacity),
                      DATA_MAX_CONNECTIONS=str(capacity + 16), ADMIN_MAX_CONNECTIONS='80',
                      PASSWORD_MAX_CONCURRENCY='2', HTTP_BUFFER_BYTES='1024',
                      DOWNSTREAM_HEADER_TIMEOUT_MS='500', ADMIN_BODY_TIMEOUT_MS='200',
                      UPSTREAM_CONNECT_TIMEOUT_MS='250', UPSTREAM_HEADER_TIMEOUT_MS='200',
                      STREAM_IDLE_TIMEOUT_MS='30000')
    env = dict(os.environ, **{f'TOKENSTREAM_{key}': value for key, value in values.items()})
    env['SSL_CERT_FILE'] = str(directory / 'trusted.pem')
    env['SSL_CERT_DIR'] = str(directory / 'empty-roots')
    process = subprocess.Popen([os.environ['GATEWAY_BINARY']], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    opened = []
    try:
        def ready():
            assert process.poll() is None, process.stderr.read().decode()
            try:
                return exchange(admin_port, 'GET', '/healthz')[0] == 200
            except OSError:
                return False
        wait_for(ready, 'gateway did not listen')
        status, headers, body = exchange(admin_port, 'POST', '/admin/api/session', b'{"password":"test-admin"}')
        assert status == 200, body
        auth = {'Cookie': headers['set-cookie'].split(';')[0], 'x-csrf-token': json.loads(body)['csrf_token'], 'content-type': 'application/json'}
        def provider(name, protocol, endpoint):
            body = json.dumps(dict(name=name, protocol_type=protocol, endpoint=endpoint, upstream_api_key='upstream-secret', status='enabled')).encode()
            status, _, response = exchange(admin_port, 'POST', '/admin/api/providers', body, auth)
            assert status == 201, response
            return json.loads(response)['gateway_api_key']
        endpoint = f'http://127.0.0.1:{plain.server_port}' if development else f'https://localhost:{trusted.server_port}'
        openai = provider('openai', 'openai', endpoint + '/prefix')
        anthropic = provider('anthropic', 'anthropic', endpoint + '/prefix')
        if capacity:
            runtime_bounds(data_port, admin_port, openai, auth, capacity, opened, provider)
            print('passed runtime resource bounds', capacity)
            return
        for path, key, native in [('/v1/chat/completions', openai, 'authorization'), ('/v1/responses', openai, 'authorization'), ('/v1/messages', anthropic, 'x-api-key')]:
            for mode in ['ordinary', 'sse', 'error']:
                request_headers = {native: f'Bearer {key}' if native == 'authorization' else key, 'x-test-mode': mode, 'x-forwarded-for': 'forged'}
                status, headers, body = exchange(data_port, 'POST', path + '?private=%2f+opaque', PAYLOAD, request_headers)
                assert status == (429 if mode == 'error' else 200), (status, body)
                assert body == (SSE if mode == 'sse' else PAYLOAD)
                assert headers['x-request-id'].startswith('req_')
                target, forwarded, received = records[-1]
                forwarded = {k.lower(): v for k, v in forwarded.items()}
                assert target == '/prefix' + path + '?private=%2f+opaque'
                assert received == PAYLOAD
                assert forwarded[native] == ('Bearer upstream-secret' if native == 'authorization' else 'upstream-secret')
                assert forwarded['x-forwarded-for'] == '127.0.0.1'
                assert key not in str(forwarded)
        before = len(records)
        for method, path, headers, expected in [('POST', '/v1/responses', {}, 401), ('POST', '/v1/messages', {'authorization': 'Bearer ' + openai}, 404), ('GET', '/v1/responses', {'authorization': 'Bearer ' + openai, 'connection': 'Upgrade', 'upgrade': 'websocket'}, 400)]:
            status, response_headers, body = exchange(data_port, method, path, b'', headers)
            assert status == expected, (status, body)
            assert json.loads(body)['error']['request_id'] == response_headers['x-request-id']
        assert len(records) == before
        if not development:
            for name, endpoint in [('untrusted', f'https://localhost:{untrusted.server_port}'), ('hostname', f'https://127.0.0.1:{trusted.server_port}'), ('plaintext', f'https://localhost:{plain.server_port}')]:
                key = provider(name, 'openai', endpoint)
                status, _, body = exchange(data_port, 'POST', '/v1/responses', PAYLOAD, {'authorization': 'Bearer ' + key})
                assert status == 502, (name, status, body)
                assert json.loads(body)['error']['code'] == 'upstream_connect_failed'
                assert b'upstream-secret' not in body and key.encode() not in body
            assert len(records) == before
        else:
            closed_sock, closed_stream = websocket(data_port, openai)
            close_payload, mask = b'\x03\xe8', b'abcd'
            closed_sock.sendall(b'\x88\x82' + mask + bytes(v ^ mask[i % 4] for i, v in enumerate(close_payload)))
            assert exact(closed_stream, 4) == b'\x88\x02' + close_payload
            closed_stream.close()
            closed_sock.close()
            wait_for(lambda: active == 0, 'normal WebSocket close left an upstream session alive')
            def idle_metrics():
                metrics = exchange(admin_port, 'GET', '/metrics', headers=auth)[2]
                return b'tokenstream_active_http_requests 0' in metrics and b'tokenstream_active_websockets 0' in metrics
            wait_for(idle_metrics, 'completed sessions retained activity metrics')
            sock, stream = websocket(data_port, openai)
            opened += [stream, sock]
            hold = http.client.HTTPConnection('127.0.0.1', data_port, timeout=5)
            hold.request('POST', '/v1/responses', PAYLOAD, {'authorization': 'Bearer ' + openai, 'x-test-mode': 'hold'})
            response = hold.getresponse()
            assert response.status == 200
            assert response.read(3) == SSE[:3], 'SSE must arrive while upstream remains open'
            opened += [response, hold]
            assert exchange(data_port, 'POST', '/v1/responses', b'', {'authorization': 'Bearer ' + openai})[0] == 503
            metrics = exchange(admin_port, 'GET', '/metrics', headers=auth)[2]
            assert b'tokenstream_active_http_requests 1' in metrics, metrics
            assert b'tokenstream_active_websockets 1' in metrics, metrics
            response.close()
            hold.close()
            wait_for(lambda: active == 1, 'HTTP cancellation left an upstream stream alive')
            assert exchange(data_port, 'POST', '/v1/responses', PAYLOAD, {'authorization': 'Bearer ' + openai})[0] == 200
        started = time.monotonic()
        process.send_signal(signal.SIGINT)
        assert process.wait(timeout=4) == 0
        assert time.monotonic() - started < 3
        wait_for(lambda: active == 0, 'shutdown left upstream sessions alive')
        rows = sqlite3.connect(db).execute('select request_id, transport_type, path, end_time, error_msg from request_log').fetchall()
        assert len(rows) >= 9
        assert len({row[0] for row in rows}) == len(rows)
        assert all('?' not in row[2] for row in rows)
        assert all(row[3] is not None for row in rows if row[1] == 'http')
        assert 'upstream-secret' not in str(rows) and 'private=' not in str(rows)
        if development:
            websocket_rows = [row for row in rows if row[1] == 'websocket']
            assert len(websocket_rows) == 2
            assert sum(row[3] is None for row in websocket_rows) == 1, 'forced shutdown must not invent completion'
            assert any(row[4] == 'downstream_cancelled' for row in rows if row[1] == 'http')

        print('passed', 'development HTTP/WebSocket/shutdown' if development else 'production HTTPS/SSE/certificate validation')
    finally:
        for item in opened:
            item.close()
        if process.poll() is None:
            process.kill()
        process.communicate(timeout=5)


with tempfile.TemporaryDirectory() as temp:
    directory = Path(temp)
    (directory / 'empty-roots').mkdir()
    for name in ['trusted', 'untrusted']:
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(directory / (name + '.key')), '-out', str(directory / (name + '.pem')), '-days', '1', '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE'], check=True, capture_output=True)
    trusted = server(directory / 'trusted.pem', directory / 'trusted.key')
    untrusted = server(directory / 'untrusted.pem', directory / 'untrusted.key')
    plain = server()
    try:
        run_case(directory, trusted, untrusted, plain, False)
        run_case(directory, trusted, untrusted, plain, True)
        for capacity in [3, 70]:
            run_case(directory, trusted, untrusted, plain, True, capacity)
        stored_key_recovery(directory, plain)
    finally:
        release.set()
        for srv in [trusted, untrusted, plain]:
            srv.shutdown()
            srv.server_close()
