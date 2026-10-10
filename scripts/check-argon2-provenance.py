"""Verify complete distribution identity, not source/compiler correspondence.

Exit 0: both artifacts match. Exit 1: readable bytes mismatch. Exit 2:
missing, incomplete or unreadable evidence. No archive paths are extracted.
"""
import argparse
import base64
import hashlib
import io
import json
import pathlib
import re
import tarfile
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARCHIVE_URL = 'https://registry.npmjs.org/argon2-browser/-/argon2-browser-1.18.0.tgz'
EXPECTED = {
    'demos/iron-serpent/public/argon2-bundled.min.js':
        ('package/dist/argon2-bundled.min.js', True),
    'demos/iron-serpent/public/argon2.wasm': ('package/dist/argon2.wasm', False),
}


def validate_manifest(manifest):
    if not isinstance(manifest, dict):
        raise ValueError('metadata must be an object')
    if (manifest.get('package'), manifest.get('version'), manifest.get('archiveUrl')) != (
            'argon2-browser', '1.18.0', ARCHIVE_URL):
        raise ValueError('unexpected package/version/distribution URL')
    integrity = manifest.get('archiveIntegrity', '')
    if not isinstance(integrity, str) or not integrity.startswith('sha512-'):
        raise ValueError('missing SHA-512 archive integrity')
    if len(base64.b64decode(integrity[7:], validate=True)) != 64:
        raise ValueError('invalid SHA-512 archive integrity')
    artifacts = manifest.get('artifacts')
    if not isinstance(artifacts, list) or len(artifacts) != len(EXPECTED):
        raise ValueError('artifact inventory must cover both bundled and standalone artifacts')
    seen = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict):
            raise ValueError('artifact descriptor must be an object')
        path = artifact.get('path')
        if not isinstance(path, str) or path not in EXPECTED or path in seen:
            raise ValueError('unknown, missing or duplicate artifact path')
        seen.add(path)
        package_path, active = EXPECTED[path]
        if artifact.get('packagePath') != package_path or artifact.get('active') is not active:
            raise ValueError('artifact distribution path or active/retained role changed')
        digest = artifact.get('sha256')
        if not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest):
            raise ValueError('missing or malformed artifact SHA-256')
    if seen != set(EXPECTED):
        raise ValueError('incomplete artifact coverage')


def main(argv=None, *, root=ROOT, fetch=urllib.request.urlopen):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--distribution', action='store_true',
                        help='compare both artifacts with integrity-pinned official npm archive')
    args = parser.parse_args(argv)
    root = pathlib.Path(root).resolve()
    result = {'originalCompiler': None, 'upstreamSourceToBinary': 'unverified',
              'expectedArtifactCount': len(EXPECTED), 'artifacts': []}

    def finish(state, code, error=None):
        result.update(state=state, attemptedArtifactCount=len(result['artifacts']),
                      checkedArtifactCount=sum(row.get('state') in ('matched', 'mismatch')
                                               for row in result['artifacts']))
        if error is not None:
            result['error'] = str(error)
        print(json.dumps(result, indent=2))
        return code

    try:
        manifest = json.loads((root / 'docs/argon2-provenance.json').read_text())
    except (OSError, ValueError) as error:
        return finish('metadata-unreadable', 2, error)
    try:
        validate_manifest(manifest)
    except (ValueError, TypeError) as error:
        return finish('incomplete', 2, error)

    archive = None
    if args.distribution:
        try:
            with fetch(manifest['archiveUrl'], timeout=60) as response:
                data = response.read(10 * 1024 * 1024 + 1)
            if len(data) > 10 * 1024 * 1024:
                raise ValueError('distribution exceeds read limit')
            actual = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()
            result['archiveIntegrityMatches'] = actual == manifest['archiveIntegrity']
            if not result['archiveIntegrityMatches']:
                return finish('distribution-integrity-mismatch', 1)
            archive = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
        except (OSError, ValueError, EOFError, tarfile.TarError) as error:
            return finish('distribution-unreadable', 2, error)

    unreadable = False
    try:
        for artifact in manifest['artifacts']:
            row = {'path': artifact['path'], 'active': artifact['active'],
                   'fingerprintMatches': None, 'distributionMatches': None}
            result['artifacts'].append(row)
            try:
                path = root / artifact['path']
                if not path.resolve().is_relative_to(root):
                    raise ValueError('artifact resolves outside repository')
                content = path.read_bytes()
                row['trackedSha256'] = hashlib.sha256(content).hexdigest()
                row['fingerprintMatches'] = row['trackedSha256'] == artifact['sha256']
                if archive is not None:
                    matches = [entry for entry in archive.getmembers()
                               if entry.name == artifact['packagePath']]
                    if len(matches) != 1 or not matches[0].isfile():
                        raise ValueError('missing, duplicate or non-file distribution entry')
                    with archive.extractfile(matches[0]) as stream:
                        row['distributionMatches'] = content == stream.read()
                row['state'] = ('matched' if row['fingerprintMatches'] and (
                    not args.distribution or row['distributionMatches']) else 'mismatch')
            except (OSError, ValueError, EOFError, tarfile.TarError) as error:
                unreadable = True
                row.update(state='unreadable', error=str(error))
    finally:
        if archive is not None:
            archive.close()
    if unreadable:
        return finish('incomplete', 2)
    if any(row['state'] != 'matched' for row in result['artifacts']):
        return finish('mismatch', 1)
    return finish('distribution-matched' if args.distribution else 'fingerprints-matched', 0)


if __name__ == '__main__':
    raise SystemExit(main())
