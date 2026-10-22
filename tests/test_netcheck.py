import argparse
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
import netcheck


class NetCheckTests(unittest.TestCase):
    def test_dns_deduplicates_addresses(self):
        with patch('socket.getaddrinfo', return_value=[(2, 1, 6, '', ('127.0.0.1', 0))] * 2):
            result = netcheck.check('DNS', 'localhost', 1)
        self.assertTrue(result['ok'])
        self.assertEqual(result['detail'], '127.0.0.1')

    def test_connection_failure_becomes_result(self):
        with patch('socket.create_connection', side_effect=TimeoutError('timeout')):
            result = netcheck.check('TCP', 'example.com:443', 1)
        self.assertFalse(result['ok'])
        self.assertIn('timeout', result['detail'])

    def test_html_escapes_untrusted_details(self):
        report = netcheck.make_report([dict(kind='DNS', target='<script>', ok=False,
                                          elapsed_ms=0, detail='<img src=x onerror=alert(1)>')])
        page = netcheck.render_html(report)
        self.assertNotIn('<script>', page)
        self.assertIn('&lt;img', page)

    def test_demo_generates_both_files_without_network(self):
        with tempfile.TemporaryDirectory() as folder, patch('socket.getaddrinfo', side_effect=AssertionError):
            self.assertEqual(netcheck.main(['--demo', '--output', folder]), 0)
            self.assertIn('DEMO', (Path(folder) / 'report.html').read_text())
            self.assertTrue((Path(folder) / 'report.json').exists())

    def test_cli_rejects_invalid_targets(self):
        for value in ['host:0', 'host:65536', 'host', ':443']:
            with self.assertRaises(argparse.ArgumentTypeError):
                netcheck.tcp_target(value)


class RobustnessTests(unittest.TestCase):
    def test_https_uses_certificate_verification_and_timeout(self):
        import ssl
        from unittest.mock import MagicMock
        opener = MagicMock()
        opener.open.return_value.__enter__.return_value.status = 200
        with patch('netcheck.urllib.request.build_opener', return_value=opener) as build:
            result = netcheck.check('HTTPS', 'https://example.com', 2.5)
        self.assertTrue(result['ok'])
        handler = build.call_args.args[1]
        self.assertEqual(handler._context.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(handler._context.check_hostname)
        self.assertEqual(opener.open.call_args.kwargs['timeout'], 2.5)

    def test_https_certificate_and_http_errors(self):
        import ssl
        import urllib.error
        from unittest.mock import MagicMock
        for error in [ssl.SSLCertVerificationError('bad certificate'),
                      urllib.error.HTTPError('https://example.com', 503, 'Unavailable', {}, None)]:
            opener = MagicMock()
            opener.open.side_effect = error
            with patch('netcheck.urllib.request.build_opener', return_value=opener):
                result = netcheck.check('HTTPS', 'https://example.com', 1)
            self.assertFalse(result['ok'])
            self.assertTrue(result['error'])

    def test_https_redirect_cannot_downgrade(self):
        with self.assertRaises(argparse.ArgumentTypeError):
            netcheck.HTTPSOnlyRedirect().redirect_request(None, None, 302, '', {}, 'http://example.com')

    def test_invalid_arguments(self):
        for value in ['https://[broken', 'https://example.com:bad', 'https://example.com:0',
                      'http://example.com', 'https://user@example.com', 'https://example.com/a b']:
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                netcheck.https_target(value)
        for value in ['nan', 'inf', '0', '-1', '61', 'abc']:
            with self.subTest(value=value), self.assertRaises(argparse.ArgumentTypeError):
                netcheck.positive_timeout(value)
        self.assertEqual(netcheck.tcp_target('[::1]:443'), '[::1]:443')

    def test_tcp_ipv6_brackets_removed(self):
        with patch('socket.create_connection') as connect:
            self.assertTrue(netcheck.check('TCP', '[::1]:443', 2)['ok'])
        connect.assert_called_once_with(('::1', 443), timeout=2)

    def test_parallel_execution_and_exit_status(self):
        import threading
        barrier = threading.Barrier(3)
        def fake(kind, target, timeout):
            barrier.wait(timeout=5)
            return dict(kind=kind, target=target, ok=False, elapsed_ms=1,
                        detail='Fallo simulado', error='Fallo simulado')
        with tempfile.TemporaryDirectory() as folder, patch('netcheck.check', side_effect=fake):
            self.assertEqual(netcheck.main(['--output', folder]), 1)

    def test_demo_schema_and_no_network(self):
        import json
        import datetime
        with tempfile.TemporaryDirectory() as folder, \
             patch('socket.getaddrinfo', side_effect=AssertionError('Network forbidden')), \
             patch('socket.create_connection', side_effect=AssertionError('Network forbidden')), \
             patch('urllib.request.OpenerDirector.open', side_effect=AssertionError('Network forbidden')):
            self.assertEqual(netcheck.main(['--demo', '--output', folder]), 0)
            report = json.loads((Path(folder) / 'report.json').read_text(encoding='utf-8'))
        self.assertTrue(report['demo'])
        self.assertIsNotNone(datetime.datetime.fromisoformat(report['generated_at']).tzinfo)
        self.assertEqual({r['kind'] for r in report['results']}, {'DNS', 'TCP', 'HTTPS'})
        for r in report['results']:
            self.assertIn('error', r)
            self.assertGreaterEqual(r['elapsed_ms'], 0)

    def test_custom_destination_replaces_defaults_and_success_exit(self):
        fake = dict(kind='DNS', target='example.com', ok=True, elapsed_ms=1,
                    detail='192.0.2.1', error=None)
        with tempfile.TemporaryDirectory() as folder, patch('netcheck.check', return_value=fake) as check:
            self.assertEqual(netcheck.main(['--dns', 'example.com', '--output', folder]), 0)
        check.assert_called_once_with('DNS', 'example.com', 4)

    def test_output_failure_has_documented_exit_code(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / 'file'
            output.write_text('occupied', encoding='utf-8')
            self.assertEqual(netcheck.main(['--demo', '--output', str(output)]), 3)

    def test_cli_errors_have_no_traceback(self):
        import subprocess
        import sys
        for args in [['--timeout', 'abc'], ['--https', 'https://[broken'],
                     ['--dns', ''], ['--demo', '--dns', 'example.com']]:
            result = subprocess.run([sys.executable, str(Path(netcheck.__file__)), *args],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
