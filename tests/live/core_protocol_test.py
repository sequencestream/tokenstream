#!/usr/bin/env python3
"""Run core protocol verification and real-provider probes without persisting secrets."""
import datetime
from functools import lru_cache
import http.client
import json
import os
import re
from pathlib import Path
import secrets
import shlex
import signal
import socket
import ssl
import sys
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
LIMIT = 4 * 1024 * 1024


def configuration(path):
    values = {}
    for line in path.read_text().splitlines():
        parts = shlex.split(line, comments=True)
        if not parts:
            continue
        if parts[0] == 'export':
            parts = parts[1:]
        if len(parts) != 1 or '=' not in parts[0]:
            raise ValueError('invalid configuration assignment')
        key, value = parts[0].split('=', 1)
        values[key] = value
    for key in ('DEEPSEEK_API_KEY', 'DEEPSEEK_MODEL', 'DEEPSEEK_OPENAI_URL', 'DEEPSEEK_ANTHROPIC_URL'):
        if not values.get(key) or values[key] == 'sk-xxx':
            raise ValueError('missing configuration or placeholder')
    for key in ('DEEPSEEK_OPENAI_URL', 'DEEPSEEK_ANTHROPIC_URL'):
        url = urlsplit(values[key])
        if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError('upstream must be an HTTPS origin with optional path prefix')
    return values


@lru_cache(maxsize=1)
def tls_context():
    context = ssl.create_default_context()
    # Framework Python on macOS can ship without an OpenSSL CA bundle.
    # Add the OS root certificates while retaining hostname and chain verification.
    if sys.platform == 'darwin' and not context.get_ca_certs():
        roots = subprocess.run(
            ['security', 'find-certificate', '-a', '-p',
             '/System/Library/Keychains/SystemRootCertificates.keychain'],
            check=True, capture_output=True, timeout=15)
        context.load_verify_locations(cadata=roots.stdout.decode('ascii'))
    return context


def exchange(base, path, body=None, headers=None, method='POST'):
    url = urlsplit(base)
    connection_type = http.client.HTTPSConnection if url.scheme == 'https' else http.client.HTTPConnection
    options = {'context': tls_context()} if url.scheme == 'https' else {}
    conn = connection_type(url.hostname, url.port, timeout=60, **options)
    started = time.monotonic()
    try:
        conn.request(method, url.path.rstrip('/') + path,
                     None if body is None else json.dumps(body).encode(),
                     {'Content-Type': 'application/json', **(headers or {})})
        response = conn.getresponse()
        first = None
        chunks = []
        size = 0
        while True:
            if time.monotonic() - started > 180:
                raise TimeoutError('response deadline')
            chunk = response.read1(65536)
            if not chunk:
                break
            if first is None:
                first = time.monotonic() - started
            size += len(chunk)
            if size > LIMIT:
                raise ValueError('response exceeds test bound')
            chunks.append(chunk)
        return {'status': response.status, 'headers': {key.lower(): value for key, value in response.getheaders()},
                'body': b''.join(chunks), 'first': first,
                'elapsed': time.monotonic() - started}
    finally:
        conn.close()


def valid_response(result, api, streaming):
    if result['status'] != 200:
        return False
    try:
        if not streaming:
            body = json.loads(result['body'])
            if api == 'chat':
                return bool(body['choices'][0]['message'].get('content')) and bool(body['choices'][0]['finish_reason'])
            if api == 'responses':
                return body.get('status') == 'completed' and bool(body.get('output'))
            return body.get('type') == 'message' and bool(body.get('content')) and bool(body.get('stop_reason'))
        headers = {key.lower(): value for key, value in result['headers'].items()}
        if 'text/event-stream' not in headers.get('content-type', ''):
            return False
        data = result['body'].decode().replace('\r\n', '\n')
        events = []
        done = False
        for frame in data.split('\n\n'):
            payload = '\n'.join(line[5:].lstrip(' ') for line in frame.splitlines() if line.startswith('data:'))
            if payload == '[DONE]':
                done = True
            elif payload:
                events.append(json.loads(payload))
        if any(event.get('error') or event.get('type') in ('error', 'response.failed', 'response.incomplete') for event in events):
            return False
        if api == 'chat':
            return done and any(choice.get('delta', {}).get('content') for event in events for choice in event.get('choices', [])) and any(choice.get('finish_reason') for event in events for choice in event.get('choices', []))
        types = [event.get('type') for event in events]
        if api == 'responses':
            return 'response.output_text.delta' in types and 'response.completed' in types
        return 'message_start' in types and 'content_block_delta' in types and bool(types) and types[-1] == 'message_stop'
    except (ValueError, KeyError, IndexError, TypeError, AttributeError, UnicodeError):
        return False


def compatible_error(direct, proxy):
    if direct['status'] < 400 or direct['status'] != proxy['status']:
        return False
    if direct['headers'].get('content-type', '').split(';')[0].lower() != proxy['headers'].get('content-type', '').split(';')[0].lower():
        return False
    try:
        left, right = json.loads(direct['body'])['error'], json.loads(proxy['body'])['error']
        return (bool(left.get('type') or left.get('code'))
                and all(left.get(field) == right.get(field) for field in ('type', 'code', 'param'))
                and isinstance(left.get('message'), str) and bool(left['message'])
                and isinstance(right.get('message'), str) and bool(right['message']))
    except (ValueError, KeyError, TypeError, AttributeError):
        return False


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class Run:
    def __init__(self):
        self.started = datetime.datetime.now().astimezone()
        directory = ROOT / 'dist/report'
        directory.mkdir(parents=True, exist_ok=True)
        self.path = directory / f'core-protocol-test-{self.started:%Y%m%d%H%M%S}.md'
        self.rows = []
        self.finished = False

    def record(self, name, status, detail):
        self.rows.append((name, status, detail))
        print(f'{status}: {name}: {detail}', flush=True)
        self.report()

    def report(self):
        passed = bool(self.rows) and all(row[1] == 'PASS' for row in self.rows)
        lines = ['# Core protocol test', '', f'Started: {self.started.isoformat()}', '',
                 f'Overall: {("PASS" if passed else "NOT FULLY VERIFIED") if self.finished else "RUNNING"}', '',
                 '| Check | Result | Evidence |', '| --- | --- | --- |']
        lines.extend('| ' + ' | '.join(row) + ' |' for row in self.rows)
        lines += ['', 'Live probes compare direct upstream and gateway requests separately. Generated text is nondeterministic; successful bodies are validated by protocol, not byte equality.',
                  '', 'Upstream rejection is not a successful API capability check. Live error checks compare status, media type and stable error type/code/parameter fields; independent upstream calls may include different metadata in their messages. Controlled HTTP/SSE/WebSocket, cancellation, header, security, repository, load and pinned-client checks are covered by the core protocol gate. Administration browser acceptance is outside this protocol run; use the full release gate for release approval.',
                  '', 'No credentials, session headers, request/response bodies, upstream URLs or raw exception messages are included. Timing is observational, not a latency assertion.', '']
        self.path.write_text('\n'.join(lines))

    def command(self, name, command, timeout):
        started = time.monotonic()
        # Child checks never receive the live provider key file as environment.
        env = {key: value for key, value in os.environ.items() if not key.startswith('DEEPSEEK_')}
        print(f'Running {name} …', flush=True)
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen(command, cwd=ROOT, env=env, stdout=output,
                                    stderr=subprocess.STDOUT, start_new_session=True)
            try:
                deadline = started + timeout
                next_progress = started + 30
                while proc.poll() is None:
                    if time.monotonic() > deadline:
                        raise TimeoutError()
                    if time.monotonic() >= next_progress:
                        print(f'{name}: still running ({time.monotonic() - started:.0f}s)', flush=True)
                        next_progress = time.monotonic() + 30
                    time.sleep(1)
                success = proc.returncode == 0
                detail = f'exit={proc.returncode}; duration={time.monotonic() - started:.1f}s'
                # Only fixed gate stage names, never raw subprocess output.
                output.seek(0)
                transcript = output.read().decode(errors='replace')
                stages = [line.strip()[4:] for line in transcript.splitlines() if line.startswith('==> ')]
                failed_tests = re.findall(r'^test ([A-Za-z0-9_:]+) \.\.\. FAILED$', transcript, re.MULTILINE)
                failed_targets = re.findall(r'to rerun pass `--test ([A-Za-z0-9_]+)`', transcript)
                if "Operation not permitted: 'ps'" in transcript:
                    detail += '; process-memory sampling blocked by environment (ps)'
                if failed_tests or failed_targets:
                    detail += '; failed=' + ', '.join(dict.fromkeys(failed_targets + failed_tests))
                allowed = {'administration frontend', 'format and static analysis', 'ephemeral PostgreSQL', 'unit, repository, protocol, and security suites', 'mixed HTTP/SSE and WebSocket component load profile', 'sustained mixed load against the real gateway process', 'pinned client compatibility', 'pinned clients through the production gateway', 'release gate passed', 'core protocol gate passed'}
                for index, stage in enumerate(stages):
                    if stage in allowed:
                        following = []
                        for item in stages[index + 1:]:
                            if item in allowed:
                                break
                            following.append(item)
                        stage_ok = ('CHECK FAILED' not in following and
                                    ('CHECK PASSED' in following or success or index < len(stages) - 1))
                        self.record(stage, 'PASS' if stage_ok else 'FAIL', 'verification stage completed' if stage_ok else 'verification stage failed; see gate summary for failed test names')
                if not success and stages and stages[-1] in allowed:
                    detail += '; last stage=' + stages[-1]
            except BaseException:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                raise
        self.record(name, 'PASS' if success else 'FAIL', detail)
        return success

    def probe(self, label, base, path, payload, headers):
        try:
            result = exchange(base, path, payload, headers)
            return result
        except Exception as error:
            self.record(label, 'FAIL', f'transport exception: {type(error).__name__}')
            return None

    def live(self, config, directory):
        data_port, admin_port = free_port(), free_port()
        while data_port == admin_port:
            admin_port = free_port()
        data = f'http://127.0.0.1:{data_port}'
        admin = f'http://127.0.0.1:{admin_port}'
        password = secrets.token_urlsafe(24)
        env = {key: value for key, value in os.environ.items() if not key.startswith(('TOKENSTREAM_', 'DEEPSEEK_'))}
        values = {'DATA_DIR': str(directory), 'DATA_LISTEN_ADDR': f'127.0.0.1:{data_port}',
                  'ADMIN_LISTEN_ADDR': f'127.0.0.1:{admin_port}', 'ADMIN_PASSWORD': password,
                  'DEVELOPMENT_MODE': 'true', 'UPSTREAM_CONNECT_TIMEOUT_MS': '15000',
                  'UPSTREAM_HEADER_TIMEOUT_MS': '60000', 'STREAM_IDLE_TIMEOUT_MS': '60000',
                  'SHUTDOWN_DRAIN_TIMEOUT_MS': '1000'}
        env.update({'TOKENSTREAM_' + key: value for key, value in values.items()})
        with tempfile.TemporaryFile() as output:
            proc = subprocess.Popen([str(ROOT / 'target/debug/tokenstream')], cwd=ROOT, env=env, stdout=output, stderr=output)
            try:
                deadline = time.monotonic() + 30
                while True:
                    if proc.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError('gateway startup failed')
                    try:
                        if exchange(admin, '/healthz', method='GET')['status'] == 200:
                            break
                    except OSError:
                        pass
                    time.sleep(.1)
                def control(path, body=None, headers=None, method='POST', expected=200):
                    result = exchange(admin, path, body, headers, method)
                    if result['status'] != expected:
                        raise RuntimeError('control plane setup failed')
                    return result
                login = control('/admin/api/session', {'name': 'admin', 'password': password})
                auth = {'Cookie': login['headers']['set-cookie'].split(';')[0],
                        'x-csrf-token': json.loads(login['body'])['csrf_token']}
                accounts = json.loads(control('/admin/api/accounts?limit=100', headers=auth, method='GET')['body'])
                owner = next(account['id'] for account in accounts['items'] if account['is_bootstrap'])
                keys = {}
                for protocol, endpoint_key in [('openai', 'DEEPSEEK_OPENAI_URL'), ('anthropic', 'DEEPSEEK_ANTHROPIC_URL')]:
                    provider = json.loads(control('/admin/api/providers', {'name': protocol, 'protocol_type': protocol,
                        'endpoint': config[endpoint_key].rstrip('/'), 'upstream_api_key': config['DEEPSEEK_API_KEY'],
                        'status': 'enabled'}, auth, expected=201)['body'])
                    keys[protocol] = json.loads(control('/admin/api/api-keys', {'name': protocol, 'account_id': owner,
                        'provider_ids': [provider['id']], 'default_provider_id': provider['id'], 'status': 'enabled'},
                        auth, expected=201)['body'])['api_key_secret']
                self.record('isolated gateway setup', 'PASS', 'temporary database; providers and credentials created through administration API')
                for api, path, protocol in [('chat', '/v1/chat/completions', 'openai'), ('responses', '/v1/responses', 'openai'), ('messages', '/v1/messages', 'anthropic')]:
                    base = config['DEEPSEEK_' + protocol.upper() + '_URL']
                    def native(key):
                        return {'Authorization': 'Bearer ' + key} if protocol == 'openai' else {'x-api-key': key, 'anthropic-version': '2023-06-01'}
                    for streaming in (False, True):
                        payload = {'model': config['DEEPSEEK_MODEL'], 'stream': streaming}
                        if api == 'responses':
                            payload.update(input='Reply with just OK.', max_output_tokens=64)
                        else:
                            payload.update(messages=[{'role': 'user', 'content': 'Reply with just OK.'}], max_tokens=64)
                        label = api + (' SSE' if streaming else ' HTTP')
                        direct = self.probe(label + ' direct', base, path, payload, native(config['DEEPSEEK_API_KEY']))
                        proxy = self.probe(label + ' gateway', data, path, payload, native(keys[protocol]))
                        for side, result in [('direct', direct), ('gateway', proxy)]:
                            if result is not None:
                                valid = valid_response(result, api, streaming)
                                status = 'PASS' if valid else ('UPSTREAM_REJECTED' if side == 'direct' and result['status'] >= 400 else 'FAIL')
                                first = result['first']
                                self.record(label + ' ' + side, status,
                                    f"HTTP {result['status']}; bytes={len(result['body'])}; first-byte={first:.3f}s; total={result['elapsed']:.3f}s" if first is not None else f"HTTP {result['status']}; empty body")
                    invalid = {'model': '__tokenstream_nonexistent_model__', 'messages': [{'role': 'user', 'content': 'OK'}], 'max_tokens': 1}
                    if api == 'responses':
                        invalid = {'model': '__tokenstream_nonexistent_model__', 'input': 'OK'}
                    direct = self.probe(api + ' error direct', base, path, invalid, native(config['DEEPSEEK_API_KEY']))
                    proxy = self.probe(api + ' error gateway', data, path, invalid, native(keys[protocol]))
                    if direct and proxy:
                        same = compatible_error(direct, proxy)
                        self.record(api + ' upstream error compatibility', 'PASS' if same else 'FAIL',
                            f"direct HTTP {direct['status']}; gateway HTTP {proxy['status']}; stable error fields={'match' if same else 'mismatch'}; body bytes={'equal' if direct['body'] == proxy['body'] else 'different across independent calls'}")
                for label, path, headers, expected in [('missing credential', '/v1/responses', {}, 401), ('cross-protocol route', '/v1/messages', {'Authorization': 'Bearer ' + keys['openai']}, 404)]:
                    result = exchange(data, path, {}, headers)
                    self.record(label, 'PASS' if result['status'] == expected else 'FAIL', f"HTTP {result['status']}; expected {expected}")
            finally:
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait()
                self.record('gateway shutdown', 'PASS' if proc.returncode == 0 else 'FAIL', f'exit={proc.returncode}; temporary state removed after run')


def main():
    run = Run()
    try:
        config = configuration(ROOT / 'tests/test-keys.env')
        run.record('configuration', 'PASS', 'all four required settings loaded; key withheld')
        run.command('runner regression tests', ['python3', '-m', 'unittest', 'discover', '-s', 'tests/live', '-p', 'core_protocol_runner_test.py'], 60)
        run.command('core protocol gate', ['./scripts/release-gate.sh', '--core-protocol'], 3600)
        if run.command('gateway build', ['cargo', 'build', '--locked', '--bin', 'tokenstream', '--target-dir', 'target'], 900):
            with tempfile.TemporaryDirectory(prefix='tokenstream-core-') as directory:
                run.live(config, Path(directory))
    except (Exception, KeyboardInterrupt) as error:
        run.record('runner', 'FAIL', f'{type(error).__name__}; raw details withheld to protect credentials')
    finally:
        run.finished = True
        run.report()
        print(f'Report: {run.path}', flush=True)
    return 0 if run.rows and all(row[1] == 'PASS' for row in run.rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
