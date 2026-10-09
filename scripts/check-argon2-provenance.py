"""Verify distribution identity, not upstream source/compiler correspondence."""
import argparse, base64, hashlib, io, json, pathlib, sys, tarfile, urllib.request
ROOT = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--distribution', action='store_true', help='compare with integrity-pinned official npm archive')
args = p.parse_args()
m = json.loads((ROOT / 'docs/argon2-provenance.json').read_text())
archive = None
if args.distribution:
    try:
        data = urllib.request.urlopen(m['archiveUrl'], timeout=60).read()
        actual = 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()
        if actual != m['archiveIntegrity']:
            raise ValueError('official archive integrity mismatch')
        archive = tarfile.open(fileobj=io.BytesIO(data), mode='r:gz')
    except Exception as error:
        print(json.dumps({'state': 'distribution-unreadable', 'error': str(error)}))
        sys.exit(2)
rows = []
for a in m['artifacts']:
    content = (ROOT / a['path']).read_bytes()
    row = {'path': a['path'], 'active': a['active'], 'trackedSha256': hashlib.sha256(content).hexdigest()}
    row['fingerprintMatches'] = row['trackedSha256'] == a['sha256']
    row['distributionMatches'] = (content == archive.extractfile(a['packagePath']).read()) if archive else None
    rows.append(row)
print(json.dumps({'originalCompiler': None, 'upstreamSourceToBinary': 'unverified', 'artifacts': rows}, indent=2))
sys.exit(0 if all(r['fingerprintMatches'] and (not args.distribution or r['distributionMatches']) for r in rows) else 1)
