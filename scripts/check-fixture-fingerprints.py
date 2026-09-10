#!/usr/bin/env python3
"""Reject captured host identities in JSON fixtures deterministically."""

import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import uuid


IDENTITY_FIELDS = {
    tuple(field.split('.'))
    for field in (
        'host.name', 'host.hostname', 'host.id', 'host.ip', 'host.mac',
        'agent.id', 'agent.name', 'agent.ephemeral_id', 'elastic_agent.id',
        'rigsignal.session.id',
        'rigsignal.session.label', 'peer.name', 'peer.id',
    )
}
DOCUMENTATION_NETWORKS = tuple(map(ipaddress.ip_network, (
    '192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32',
)))


def leaves(document, segments=(), display=''):
    """Keep array indices for reporting, but omit them from field matching."""
    if isinstance(document, dict):
        for key in sorted(document):
            yield from leaves(
                document[key], segments + tuple(key.split('.')),
                f'{display}.{key}' if display else key,
            )
    elif isinstance(document, list):
        for index, value in enumerate(document):
            yield from leaves(value, segments, f'{display}[{index}]')
    elif segments[-2:] in IDENTITY_FIELDS or segments[-3:] in IDENTITY_FIELDS:
        yield segments, display, document if isinstance(document, str) else str(document)


def rejected_class(segments, value, allow):
    if value in allow:
        return None
    try:
        address = ipaddress.ip_address(value.split('%', 1)[0])
    except ValueError:
        pass
    else:
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        # Only loopback, unspecified and documentation addresses are safe here.
        # Link-local fe80::/10 and unique-local fc00::/7 still identify real
        # hosts, so they are rejected even though they are not globally routable.
        if address.is_loopback or address.is_unspecified or any(
            address in network for network in DOCUMENTATION_NETWORKS
        ):
            return None
        return 'IP'
    if re.fullmatch(r'[0-9A-F]{12}', value.upper().replace(':', '').replace('-', '')):
        return 'MAC'
    # UUID also accepts bare 32-hex strings; report host.id specifically first.
    if segments[-2:] == ('host', 'id') and re.fullmatch(r'[0-9a-fA-F]{32}', value):
        return 'host.id'
    try:
        uuid.UUID(value)
    except ValueError:
        return 'allowlist-only'
    return 'UUID'


def fixture_paths(root, direct):
    if direct:
        paths = (path.relative_to(root) for path in root.rglob('*') if path.is_file())
    else:
        tracked = subprocess.check_output(['git', '-C', str(root), 'ls-files', '-z'])
        paths = (Path(path.decode('utf-8')) for path in tracked.split(b'\0') if path)
    return sorted(
        path for path in paths
        if path.suffix in {'.json', '.ndjson'}
        and {'fixtures', 'testdata', 'tests'}.intersection(path.parts[:-1])
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, help='Scan a directory tree without git')
    args = parser.parse_args()
    root = args.root.resolve() if args.root is not None else Path(
        subprocess.check_output(['git', 'rev-parse', '--show-toplevel'], text=True).strip()
    )
    allow = json.loads(
        Path(__file__).with_name('fixture-fingerprint-allowlist.json').read_text(encoding='utf-8')
    )['allow']
    paths = fixture_paths(root, args.root is not None)
    violations = 0
    for path in paths:
        with (root / path).open(encoding='utf-8') as source:
            documents = (
                (json.loads(line) for line in source if line.strip())
                if path.suffix == '.ndjson' else (json.load(source),)
            )
            for document in documents:
                for segments, display, value in leaves(document):
                    category = rejected_class(segments, value, allow)
                    if category:
                        print(f'{path.as_posix()}: {display} = {value} ({category})')
                        violations += 1
    print(f'Scanned {len(paths)} files; found {violations} violations.')
    return 1 if violations else 0


if __name__ == '__main__':
    raise SystemExit(main())
