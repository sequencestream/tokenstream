"""Offline checks for live-test configuration and protocol verdicts."""
import contextlib
import io
import json
import sys
import tempfile
from unittest.mock import patch

import core_protocol_test
import unittest
from pathlib import Path

from core_protocol_test import compatible_error, configuration, valid_response


class RunnerTests(unittest.TestCase):
    def test_failure_still_writes_sanitized_report(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(core_protocol_test, 'ROOT', Path(directory)), \
                    patch.object(core_protocol_test, 'configuration', side_effect=ValueError('private-key-value')), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(core_protocol_test.main(), 1)
            reports = list((Path(directory) / 'dist/report').glob('core-protocol-test-*.md'))
            self.assertEqual(len(reports), 1)
            report = reports[0].read_text()
            self.assertIn('NOT FULLY VERIFIED', report)
            self.assertIn('ValueError', report)
            self.assertNotIn('private-key-value', report)

    def test_live_errors_allow_request_specific_messages_but_not_changed_codes(self):
        def error(code, message):
            return {'status': 400, 'headers': {'content-type': 'application/json'},
                    'body': json.dumps({'error': {'type': 'invalid_request_error',
                                                'code': code, 'message': message}}).encode()}
        direct = error('model_not_found', 'Unknown model; request A')
        self.assertTrue(compatible_error(direct, error('model_not_found', 'Unknown model; request B')))
        self.assertFalse(compatible_error(direct, error('invalid_api_key', 'Invalid credential')))
        self.assertFalse(compatible_error(direct, {**direct, 'status': 502}))
        self.assertFalse(compatible_error(direct, {**direct, 'body': b'{}'}))

    def test_failed_stage_does_not_hide_later_success(self):
        transcript = ('==> unit, repository, protocol, and security suites\n'
                      'test sample_contract ... FAILED\n'
                      '==> CHECK FAILED\n'
                      '==> pinned client compatibility\n'
                      '==> CHECK PASSED\n')
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(core_protocol_test, 'ROOT', Path(directory)), \
                    contextlib.redirect_stdout(io.StringIO()):
                run = core_protocol_test.Run()
                passed = run.command('core protocol gate',
                                     [sys.executable, '-c', f'print({transcript!r}); raise SystemExit(1)'], 10)
            self.assertFalse(passed)
            statuses = {name: status for name, status, _ in run.rows}
            self.assertEqual(statuses['unit, repository, protocol, and security suites'], 'FAIL')
            self.assertEqual(statuses['pinned client compatibility'], 'PASS')
            self.assertIn('sample_contract', run.rows[-1][2])

    def test_env_is_data_and_supports_quotes_comments(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'keys.env'
            path.write_text('export DEEPSEEK_API_KEY="$(do-not-execute)#secret" # comment\n'
                            'DEEPSEEK_MODEL=example\n'
                            'DEEPSEEK_OPENAI_URL=https://example.com\n'
                            'DEEPSEEK_ANTHROPIC_URL=https://example.com/anthropic\n')
            self.assertEqual(configuration(path)['DEEPSEEK_API_KEY'], '$(do-not-execute)#secret')
            path.write_text(path.read_text().replace('https://example.com', 'https://user:password@example.com'))
            with self.assertRaises(ValueError):
                configuration(path)

    def test_sse_requires_completion_content_and_correct_content_type(self):
        result = {'status': 200, 'headers': {'Content-Type': 'text/event-stream'},
                  'body': b'data: {"choices":[{"delta":{"content":"OK"},"finish_reason":null}]}\r\n\r\n'
                          b'data: {"choices":[{"delta":{},"finish_reason":"stop"}]}\r\n\r\n'
                          b'data: [DONE]\r\n\r\n'}
        self.assertTrue(valid_response(result, 'chat', True))
        self.assertFalse(valid_response({**result, 'body': result['body'].replace(b'data: [DONE]', b'')}, 'chat', True))
        self.assertFalse(valid_response({**result, 'headers': {}}, 'chat', True))
        self.assertFalse(valid_response({**result, 'status': 404}, 'chat', True))

    def test_error_event_and_incomplete_response_never_pass(self):
        result = {'status': 200, 'headers': {'content-type': 'text/event-stream'},
                  'body': b'data: {"type":"response.output_text.delta","delta":"OK"}\n\n'
                          b'data: {"type":"response.completed"}\n\n'}
        self.assertTrue(valid_response(result, 'responses', True))
        self.assertFalse(valid_response({**result, 'body': result['body'] + b'data: {"type":"error"}\n\n'}, 'responses', True))
        self.assertFalse(valid_response({**result, 'body': b'{"status":"incomplete","output":[{}]}'}, 'responses', False))

    def test_anthropic_stop_and_json_output(self):
        result = {'status': 200, 'headers': {'content-type': 'text/event-stream'},
                  'body': b'data: {"type":"message_start"}\n\n'
                          b'data: {"type":"content_block_delta"}\n\n'
                          b'data: {"type":"message_stop"}\n\n'}
        self.assertTrue(valid_response(result, 'messages', True))
        self.assertFalse(valid_response({**result, 'body': b'{}'}, 'messages', False))
        self.assertFalse(valid_response({**result, 'body': b'not json'}, 'responses', False))


if __name__ == '__main__':
    unittest.main()
