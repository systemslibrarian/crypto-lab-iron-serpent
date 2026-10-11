"""Verify distribution identity or explicitly rebuild pinned publisher sources.

Exit 0: both artifacts match. Exit 1: readable bytes mismatch. Exit 2:
missing, incomplete or unreadable evidence. No archive paths are extracted.
"""
import argparse
import base64
import datetime
import hashlib
import io
import json
import pathlib
import re
import subprocess
import tarfile
import tempfile
import time
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
ARCHIVE_URL = 'https://registry.npmjs.org/argon2-browser/-/argon2-browser-1.18.0.tgz'
EXPECTED = {
    'demos/iron-serpent/public/argon2-bundled.min.js':
        ('package/dist/argon2-bundled.min.js', True),
    'demos/iron-serpent/public/argon2.wasm': ('package/dist/argon2.wasm', False),
}
PUBLISHER_SHA = '63cda65cd2182e39a139aa074e2306332ddd4417'
ARGON2_SHA = '16d3df698db2486dde480b09a732bf9bf48599f9'
LOCK_SHA256 = '373c51383c37ac3cccdc4d367b347a85b772a9787b95b5ce9596f6d2dfa0ebf2'
COMPILER_IMAGE = 'emscripten/emsdk@sha256:5871ba43a788243cbf890e2cb1a95e33e9cb72dcf52e1d2077ca39f2171f8b07'


def extract_sources(data, target, excluded=()):
    """Only authenticated regular Git archive paths enter the fresh build."""
    with tarfile.open(fileobj=io.BytesIO(data)) as archive:
        members = [entry for entry in archive.getmembers() if not any(
            entry.name == prefix or entry.name.startswith(prefix + '/') for prefix in excluded)]
        names = set()
        for entry in members:
            path = pathlib.PurePosixPath(entry.name)
            if (not (entry.isfile() or entry.isdir()) or path.is_absolute()
                    or '..' in path.parts or entry.name in names):
                raise ValueError('unsafe or duplicate source archive member: ' + entry.name)
            names.add(entry.name)
        # Validate the whole inventory before writing any path; links are forbidden.
        for entry in members:
            destination = target.joinpath(*pathlib.PurePosixPath(entry.name).parts)
            if entry.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('xb') as stream:
                    stream.write(archive.extractfile(entry).read())
                destination.chmod(entry.mode & 0o777)
        return len(members)


def compare_rebuild(root, build, manifest):
    rows = []
    for artifact in manifest['artifacts']:
        name = pathlib.PurePosixPath(artifact['packagePath']).name
        row = {'path': artifact['path'], 'rebuiltPath': 'dist/' + name}
        rows.append(row)
        try:
            shipped = root / artifact['path']
            rebuilt = build / 'dist' / name
            if (not shipped.resolve().is_relative_to(root.resolve()) or shipped.is_symlink()
                    or rebuilt.is_symlink() or not rebuilt.is_file()):
                raise ValueError('unreadable or nonregular artifact')
            old, new = shipped.read_bytes(), rebuilt.read_bytes()
            if not old or not new:
                raise ValueError('empty artifact')
            digest = hashlib.sha256(old).hexdigest()
            row.update(shippedSha256=digest,
                       rebuiltSha256=hashlib.sha256(new).hexdigest(),
                       state='matched' if old == new and digest == artifact['sha256'] else 'mismatch')
        except (OSError, ValueError) as error:
            row.update(state='unreadable', error=str(error))
    # The browser loads the bundle, not the retained standalone WASM.
    try:
        bundle = (root / 'demos/iron-serpent/public/argon2-bundled.min.js').read_bytes()
        payloads = []
        for match in re.finditer(rb'[A-Za-z0-9+/]{1000,}={0,2}', bundle):
            try:
                data = base64.b64decode(match.group(), validate=True)
                if data[:8] == b'\x00asm\x01\x00\x00\x00':
                    payloads.append(data)
            except ValueError:
                pass
        if len(payloads) != 1:
            raise ValueError('active bundle must contain exactly one identifiable WASM payload')
        generated = (build / 'dist/argon2.wasm').read_bytes()
        rows.append({'path': 'active embedded WASM', 'rebuiltPath': 'dist/argon2.wasm',
                     'shippedSha256': hashlib.sha256(payloads[0]).hexdigest(),
                     'rebuiltSha256': hashlib.sha256(generated).hexdigest(),
                     'state': 'matched' if payloads[0] == generated else 'mismatch'})
    except (OSError, ValueError) as error:
        rows.append({'path': 'active embedded WASM', 'state': 'unreadable', 'error': str(error)})
    code = 2 if any(row['state'] == 'unreadable' for row in rows) else 1 if any(
        row['state'] != 'matched' for row in rows) else 0
    return code, rows


# Exact historical build tools execute only inside the pinned container and
# fresh public-source scratch. No repository npm installation or lifecycle runs.
REBUILD_COMMAND = r'''
import subprocess,json,pathlib,hashlib
cache=pathlib.Path('/emsdk/upstream/emscripten/cache')
def inventory():
 return {str(x.relative_to(cache)):hashlib.sha256(x.read_bytes()).hexdigest() for x in cache.glob('**/*') if x.is_file()}
before=inventory()
assert before, 'Immutable compiler system-library inventory missing'
print(json.dumps({'compilerStandardLibraryInputs':before}),flush=True)
lock=pathlib.Path('/src/package-lock.json').read_bytes()
package=json.loads(pathlib.Path('/src/package.json').read_text())
assert package['scripts'].get('build-bundle')=='webpack'
assert not any(k in package['scripts'] for k in ('prebuild-bundle','postbuild-bundle'))
commands=[['emcc','--version'],['node','--version'],['npm','--version'],['cmake','--version'],
 ['bash','build-wasm.sh'],
 ['npm','ci','--ignore-scripts','--no-audit','--no-fund','--cache','/src/.build-only-npm-cache'],
 ['node','node_modules/webpack-cli/bin/cli.js']]
for command in commands:
 result=subprocess.run(command,capture_output=True,text=True)
 print(json.dumps({'command':command,'exit':result.returncode,'stdout':result.stdout,'stderr':result.stderr}),flush=True)
 if result.returncode:raise SystemExit(result.returncode)
assert pathlib.Path('/src/package-lock.json').read_bytes()==lock, 'Source lock changed'
assert inventory()==before, 'Compiler system-library inputs changed'
print(json.dumps({'compilerInputsUnchanged':True,'sourceLockUnchanged':True}),flush=True)
'''


def validate_build_stages(captured):
    stages = [json.loads(line) for line in captured.splitlines()]
    expected = [['emcc', '--version'], ['node', '--version'], ['npm', '--version'],
                ['cmake', '--version'], ['bash', 'build-wasm.sh'],
                ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', '/src/.build-only-npm-cache'],
                ['node', 'node_modules/webpack-cli/bin/cli.js']]
    if len(stages) != 9 or any(not isinstance(row, dict) for row in stages):
        raise ValueError('incomplete or malformed compiler/build stage inventory')
    inputs = stages[0].get('compilerStandardLibraryInputs')
    if (not isinstance(inputs, dict) or not inputs
            or any(not isinstance(k, str) or not isinstance(v, str)
                   or not re.fullmatch('[0-9a-f]{64}', v) for k, v in inputs.items())
            or [x.get('command') for x in stages[1:-1]] != expected
            or any(type(x.get('exit')) is not int or x['exit'] != 0
                   or not isinstance(x.get('stdout'), str)
                   or not isinstance(x.get('stderr', ''), str) for x in stages[1:-1])
            or stages[-1] != {'compilerInputsUnchanged': True, 'sourceLockUnchanged': True}
            or any(value is not True for value in stages[-1].values())
            or '2.0.23 (b15ca40ca02f469de3bf9a4de67a2655aede8974)' not in stages[1].get('stdout', '')
            or stages[2].get('stdout', '').strip() != 'v14.15.5'
            or stages[3].get('stdout', '').strip() != '6.14.11'):
        raise ValueError('incomplete, changed or unreadable compiler/build stages')
    compiled = re.findall(r'Building C object CMakeFiles/argon2.dir/([^\s]+)\.o', stages[5]['stdout'])
    expected_c = {'argon2/src/blake2/blake2b.c', 'argon2/src/argon2.c', 'argon2/src/core.c',
                  'argon2/src/encoding.c', 'argon2/src/thread.c', 'src/argon2_library.c', 'argon2/src/ref.c'}
    if len(compiled) != 7 or set(compiled) != expected_c:
        raise ValueError('all seven fresh Argon2 C compilation steps must be readable')


def rebuild_source(args, root, manifest, result):
    proof = {'startedAt': datetime.datetime.now(datetime.timezone.utc).isoformat(),
             'compilerImage': COMPILER_IMAGE, 'originalCompiler': None, 'commands': [],
             'sourceArchives': [], 'artifacts': []}
    result['sourceRebuild'] = proof

    def command(argv, cwd=None, binary=False):
        started = time.monotonic()
        try:
            completed = subprocess.run(argv, cwd=cwd, capture_output=True, text=not binary, timeout=900)
        except subprocess.TimeoutExpired as error:
            def readable(value):
                return value.decode(errors='replace') if isinstance(value, bytes) else value or ''
            proof['commands'].append({'command': argv, 'exit': None, 'timeout': True,
                'seconds': time.monotonic() - started, 'stdout': readable(error.stdout),
                'stderr': readable(error.stderr)})
            raise
        row = {'command': argv, 'exit': completed.returncode, 'seconds': time.monotonic() - started}
        if binary:
            row.update(stdoutSha256=hashlib.sha256(completed.stdout).hexdigest(),
                       stdoutBytes=len(completed.stdout), stderr=completed.stderr.decode(errors='replace'))
        else:
            row.update(stdout=completed.stdout, stderr=completed.stderr)
        proof['commands'].append(row)
        if completed.returncode:
            raise ValueError('source reproduction prerequisite or command failed: ' + repr(argv))
        return completed.stdout

    sha = command(['git', 'rev-parse', 'HEAD'], root).strip()
    if command(['git', 'status', '--porcelain', '--untracked-files=no'], root).strip():
        raise ValueError('source reproduction requires a clean committed lab checkout')
    proof['inspectedLabSha'] = sha
    for artifact in manifest['artifacts']:
        if command(['git', 'show', sha + ':' + artifact['path']], root, True) != (root / artifact['path']).read_bytes():
            raise ValueError('tracked artifact differs from inspected Git source')
    sources = [(args.publisher_source, 'https://github.com/antelle/argon2-browser', PUBLISHER_SHA),
               (args.argon2_source, 'https://github.com/P-H-C/phc-winner-argon2', ARGON2_SHA)]
    for source, remote, pin in sources:
        if source is None:
            raise ValueError('both existing pinned source checkouts must be provided')
        origin = command(['git', 'remote', 'get-url', 'origin'], source).strip().removesuffix('.git')
        if origin != remote or command(['git', 'cat-file', '-t', pin], source).strip() != 'commit':
            raise ValueError('source origin/pinned commit unavailable or changed')
    gitlink = command(['git', 'ls-tree', PUBLISHER_SHA, 'argon2'], args.publisher_source).strip()
    if gitlink != '160000 commit ' + ARGON2_SHA + '\targon2':
        raise ValueError('publisher submodule pin differs from inspected C source')
    docker = ['docker'] + (['--context', args.docker_context] if args.docker_context else [])
    image = json.loads(command(docker + ['image', 'inspect', COMPILER_IMAGE, '--format', '{{json .RepoDigests}}']))
    if not isinstance(image, list) or COMPILER_IMAGE not in image:
        raise ValueError('pinned compiler image unavailable')
    with tempfile.TemporaryDirectory(prefix='iron-argon2-rebuild-', dir=args.scratch_root) as scratch:
        build = pathlib.Path(scratch)
        for index, (source, _, pin) in enumerate(sources):
            raw = command(['git', 'archive', pin], source, True)
            target = build if index == 0 else build / 'argon2'
            target.mkdir(exist_ok=True)
            excluded = ('dist', 'docs/dist', 'argon2') if index == 0 else ()
            count = extract_sources(raw, target, excluded)
            proof['sourceArchives'].append({'sha': pin, 'archiveSha256': hashlib.sha256(raw).hexdigest(),
                                           'excluded': list(excluded), 'members': count})
        if hashlib.sha256((build / 'package-lock.json').read_bytes()).hexdigest() != LOCK_SHA256:
            raise ValueError('publisher build lock differs from inspected source')
        # Normalize archive mtimes so fresh virtiofs builds cannot skip source on clock skew.
        import os
        for path in build.rglob('*'):
            if path.is_file():
                os.utime(path, (946684800, 946684800))
        captured = command(docker + ['run', '--rm', '--platform', 'linux/amd64', '--cap-drop=ALL',
            '--security-opt=no-new-privileges', '--pids-limit=256', '--cpus=2', '--memory=2g',
            '--user', str(os.getuid()) + ':' + str(os.getgid()), '--mount',
            'type=bind,src=' + str(build) + ',dst=/src', '--workdir', '/src',
            '--env', 'ARGON_JS_BUILD_BUILD_WITH_SIMD=0', '--env', 'EM_FROZEN_CACHE=1',
            '--env', 'EMCC_CORES=1', '--env', 'QEMU_STACK_SIZE=16777216',
            COMPILER_IMAGE, 'python3', '-u', '-c', REBUILD_COMMAND])
        validate_build_stages(captured)
        code, rows = compare_rebuild(root, build, manifest)
        proof['artifacts'] = rows
    if command(['git', 'rev-parse', 'HEAD'], root).strip() != sha or command(
            ['git', 'status', '--porcelain', '--untracked-files=no'], root).strip():
        raise ValueError('inspected lab source changed during reproduction')
    proof['finishedAt'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    proof['state'] = 'reproduced' if code == 0 else 'incomplete' if code == 2 else 'mismatch'
    if code == 0:
        result['upstreamSourceToBinary'] = 'reproduced'
    return code


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
    parser.add_argument('--source-rebuild', action='store_true',
                        help='clean rebuild pinned public source with an existing pinned Docker image')
    parser.add_argument('--publisher-source', type=pathlib.Path)
    parser.add_argument('--argon2-source', type=pathlib.Path)
    parser.add_argument('--docker-context')
    parser.add_argument('--scratch-root', type=pathlib.Path,
                        help='existing directory shared with a VM; each build creates a unique child')
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
    if args.source_rebuild:
        try:
            code = rebuild_source(args, root, manifest, result)
            return finish('source-reproduced' if code == 0 else 'source-incomplete' if code == 2 else 'source-mismatch', code)
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired, tarfile.TarError) as error:
            result.get('sourceRebuild', {})['state'] = 'incomplete'
            return finish('source-incomplete', 2, error)
    return finish('distribution-matched' if args.distribution else 'fingerprints-matched', 0)


if __name__ == '__main__':
    raise SystemExit(main())
