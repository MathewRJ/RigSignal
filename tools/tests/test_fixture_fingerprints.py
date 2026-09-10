"""Regression coverage for the fixture host-fingerprint gate."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / 'scripts/check-fixture-fingerprints.py'


class FixtureFingerprintTests(unittest.TestCase):
    def scan(self, root=None):
        command = [sys.executable, str(SCANNER)]
        if root is not None:
            command.extend(['--root', str(root)])
        return subprocess.run(command, cwd=ROOT, capture_output=True, text=True)

    def test_rejected_fingerprints(self):
        cases = [
            ('ipv4', 'host.ip', '198.18.0.1', 'IP'),
            ('ipv6_zone', 'host.ip', 'fe80::1%eth0', 'IP'),
            ('ipv4_mapped', 'host.ip', '::ffff:198.18.0.1', 'IP'),
            ('ipv6_local', 'host.ip', 'fd00::1', 'IP'),
            ('mac', 'host.mac', 'AA:BB:CC:DD:EE:FF', 'MAC'),
            ('uuid', 'agent.id', '123e4567-e89b-12d3-a456-426614174000', 'UUID'),
            ('agent_ephemeral_id', 'agent.ephemeral_id', '123e4567-e89b-12d3-a456-426614174000', 'UUID'),
            ('agent_name', 'agent.name', 'some-real-box', 'allowlist-only'),
            ('host_id', 'host.id', 'abcdef0123456789abcdef0123456789', 'host.id'),
            ('hostname', 'host.name', 'some-real-box', 'allowlist-only'),
            ('peer_id', 'peer.id', 99999999999999, 'allowlist-only'),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            fixtures = Path(temporary) / 'tests'
            fixtures.mkdir()
            for name, field, value, _ in cases:
                (fixtures / f'{name}.json').write_text(json.dumps({field: value}))
            result = self.scan(temporary)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        for name, field, value, category in cases:
            with self.subTest(name=name):
                self.assertIn(f'tests/{name}.json: {field} = {value} ({category})', result.stdout)
        self.assertIn('Scanned 11 files; found 11 violations.', result.stdout)

    def test_allowed_fingerprints(self):
        allow = json.loads((ROOT / 'scripts/fixture-fingerprint-allowlist.json').read_text())['allow']
        document = {'host': {
            'name': list(allow),
            'ip': ['127.0.0.1', '::1', '192.0.2.5', '2001:db8::5'],
            'mac': ['00-00-5E-00-53-01'],
        }}
        with tempfile.TemporaryDirectory() as temporary:
            fixtures = Path(temporary) / 'tests'
            fixtures.mkdir()
            (fixtures / 'allowed.json').write_text(json.dumps(document))
            result = self.scan(temporary)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, 'Scanned 1 files; found 0 violations.\n')

    def test_ndjson_paths_and_scope(self):
        document = {'hits': {'hits': [{'_source': {
            'host': {'ip': ['192.0.2.5', 'fe80::1%eth0']},
            'rigsignal.session.label': 'unlisted-session',
            'event': {'id': '123e4567-e89b-12d3-a456-426614174000'},
        }}]}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixtures = root / 'testdata'
            fixtures.mkdir()
            (fixtures / 'events.ndjson').write_text(
                '\n' + json.dumps({'host.name': 'fixture-host.example'}) + '\n\n'
                + json.dumps(document) + '\n'
            )
            (root / 'ignored.json').write_text('{"host.name": "outside-scope"}')
            (fixtures / 'ignored.txt').write_text('{"host.name": "outside-scope"}')
            result = self.scan(root)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('hits.hits[0]._source.host.ip[1] = fe80::1%eth0 (IP)', result.stdout)
        self.assertIn('hits.hits[0]._source.rigsignal.session.label = unlisted-session (allowlist-only)', result.stdout)
        self.assertIn('Scanned 1 files; found 2 violations.', result.stdout)

    def test_repository_corpus_is_clean(self):
        result = self.scan()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn('found 0 violations.', result.stdout)


if __name__ == '__main__':
    unittest.main()
