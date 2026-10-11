"""Offline coverage/error controls. Synthetic matches are not provenance evidence."""
import base64
import contextlib
import copy
import hashlib
import importlib.util
import io
import json
import pathlib
import tarfile
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'check-argon2-provenance.py'
SPEC = importlib.util.spec_from_file_location('argon2_provenance', SCRIPT)
CHECKER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CHECKER)


class CoverageControls(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name)
        self.contents = {path: ('fixture:' + path).encode() for path in CHECKER.EXPECTED}
        self.manifest = {
            'package': 'argon2-browser', 'version': '1.18.0',
            'archiveUrl': CHECKER.ARCHIVE_URL,
            'artifacts': [{'path': path, 'packagePath': package_path, 'active': active,
                           'sha256': hashlib.sha256(self.contents[path]).hexdigest()}
                          for path, (package_path, active) in CHECKER.EXPECTED.items()],
        }
        for path, content in self.contents.items():
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        self.archive = self.make_archive()
        self.manifest['archiveIntegrity'] = self.integrity(self.archive)
        self.write_manifest()

    def integrity(self, data):
        return 'sha512-' + base64.b64encode(hashlib.sha512(data).digest()).decode()

    def make_archive(self, *, omit=None, duplicate=None, link=None, changed=None):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            for path, (package_path, _) in CHECKER.EXPECTED.items():
                if path == omit:
                    continue
                content = b'changed' if path == changed else self.contents[path]
                entry = tarfile.TarInfo(package_path)
                if path == link:
                    entry.type = tarfile.SYMTYPE
                    entry.linkname = '/outside'
                    archive.addfile(entry)
                else:
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
                    if path == duplicate:
                        archive.addfile(entry, io.BytesIO(content))
        return data.getvalue()

    def write_manifest(self):
        target = self.root / 'docs/argon2-provenance.json'
        target.parent.mkdir(exist_ok=True)
        target.write_text(json.dumps(self.manifest))

    def check(self, *, distribution=False, fetch=None):
        output = io.StringIO()
        requests = []

        def fixture_fetch(url, timeout):
            requests.append((url, timeout))
            return io.BytesIO(self.archive)

        def forbidden_fetch(*args, **kwargs):
            self.fail('fingerprint check must not access network')

        with contextlib.redirect_stdout(output):
            code = CHECKER.main(['--distribution'] if distribution else [], root=self.root,
                                fetch=fetch or (fixture_fetch if distribution else forbidden_fetch))
        result = json.loads(output.getvalue())
        self.assertIsNone(result['originalCompiler'])
        self.assertEqual(result['upstreamSourceToBinary'], 'unverified')
        if requests:
            self.assertEqual(requests, [(CHECKER.ARCHIVE_URL, 60)])
        return code, result

    def test_complete_fingerprints_and_distribution(self):
        for distribution in (False, True):
            with self.subTest(distribution=distribution):
                code, result = self.check(distribution=distribution)
                self.assertEqual(code, 0)
                self.assertEqual(result['checkedArtifactCount'], 2)
                self.assertEqual(result['expectedArtifactCount'], 2)
                self.assertEqual([r['state'] for r in result['artifacts']], ['matched', 'matched'])
                self.assertEqual(result['state'], 'distribution-matched' if distribution
                                 else 'fingerprints-matched')

    def test_empty_omitted_duplicate_and_unknown_inventory(self):
        artifacts = copy.deepcopy(self.manifest['artifacts'])
        for bad in ([], artifacts[:1], [artifacts[0], artifacts[0]],
                    [dict(artifacts[0], path='../other'), artifacts[1]], None):
            with self.subTest(inventory=bad):
                self.manifest['artifacts'] = bad
                self.write_manifest()
                code, result = self.check()
                self.assertEqual((code, result['state']), (2, 'incomplete'))

    def test_invalid_metadata_is_not_a_match(self):
        baseline = copy.deepcopy(self.manifest)
        for key, value in [('active', False), ('active', 1), ('sha256', 'no'),
                           ('packagePath', 'package/other')]:
            with self.subTest(key=key, value=value):
                self.manifest = copy.deepcopy(baseline)
                self.manifest['artifacts'][0][key] = value
                self.write_manifest()
                self.assertEqual(self.check()[0], 2)
        for key, value in [('version', 'different'), ('archiveUrl', 'https://other/'),
                           ('archiveIntegrity', 'sha512-invalid')]:
            self.manifest = dict(baseline, **{key: value})
            self.write_manifest()
            self.assertEqual(self.check()[0], 2)

    def test_missing_or_malformed_manifest(self):
        target = self.root / 'docs/argon2-provenance.json'
        for data in ('[', '[]'):
            target.write_text(data)
            code, result = self.check()
            self.assertEqual(code, 2)
            self.assertNotEqual(result['state'], 'fingerprints-matched')
        target.unlink()
        self.assertEqual(self.check()[0], 2)

    def test_missing_artifact_preserves_readable_other_row(self):
        (self.root / self.manifest['artifacts'][0]['path']).unlink()
        code, result = self.check()
        self.assertEqual((code, result['state']), (2, 'incomplete'))
        self.assertEqual([r['state'] for r in result['artifacts']], ['unreadable', 'matched'])
        self.assertEqual(result['checkedArtifactCount'], 1)
        self.assertEqual(result['attemptedArtifactCount'], 2)

    def test_changed_tracked_bytes(self):
        (self.root / self.manifest['artifacts'][0]['path']).write_bytes(b'changed')
        code, result = self.check()
        self.assertEqual((code, result['state']), (1, 'mismatch'))
        self.assertFalse(result['artifacts'][0]['fingerprintMatches'])

    def test_timeout_malformed_archive_and_integrity_mismatch(self):
        def timeout(url, timeout):
            raise TimeoutError('fixture timeout')
        self.assertEqual(self.check(distribution=True, fetch=timeout)[0], 2)
        self.archive = b'not a gzip archive'
        self.assertEqual(self.check(distribution=True)[0], 1)
        self.manifest['archiveIntegrity'] = self.integrity(self.archive)
        self.write_manifest()
        code, result = self.check(distribution=True)
        self.assertEqual((code, result['state']), (2, 'distribution-unreadable'))

    def test_partial_duplicate_and_link_archive_entries(self):
        for kind in ('omit', 'duplicate', 'link'):
            with self.subTest(kind=kind):
                self.archive = self.make_archive(**{kind: self.manifest['artifacts'][0]['path']})
                self.manifest['archiveIntegrity'] = self.integrity(self.archive)
                self.write_manifest()
                code, result = self.check(distribution=True)
                self.assertEqual((code, result['state']), (2, 'incomplete'))
                self.assertEqual(result['artifacts'][1]['state'], 'matched')

    def test_readable_distribution_byte_mismatch(self):
        self.archive = self.make_archive(changed=self.manifest['artifacts'][0]['path'])
        self.manifest['archiveIntegrity'] = self.integrity(self.archive)
        self.write_manifest()
        code, result = self.check(distribution=True)
        self.assertEqual((code, result['state']), (1, 'mismatch'))
        self.assertTrue(result['artifacts'][0]['fingerprintMatches'])
        self.assertFalse(result['artifacts'][0]['distributionMatches'])


class SourceRebuildControls(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.addCleanup(self.scratch.cleanup)
        self.root = pathlib.Path(self.scratch.name) / 'lab'
        self.build = pathlib.Path(self.scratch.name) / 'fresh'
        (self.build / 'dist').mkdir(parents=True)
        self.wasm = b'\x00asm\x01\x00\x00\x00' + bytes(1200)
        self.bundle = b'const embedded="' + base64.b64encode(self.wasm) + b'";'
        self.manifest = {'artifacts': []}
        for path, (package_path, active) in CHECKER.EXPECTED.items():
            data = self.bundle if active else self.wasm
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            (self.build / 'dist' / pathlib.PurePosixPath(package_path).name).write_bytes(data)
            self.manifest['artifacts'].append({'path': path, 'packagePath': package_path,
                'active': active, 'sha256': hashlib.sha256(data).hexdigest()})

    def test_all_shipped_and_active_embedded_artifacts_required(self):
        code, rows = CHECKER.compare_rebuild(self.root, self.build, self.manifest)
        self.assertEqual(code, 0)
        self.assertEqual(len(rows), 3)
        self.assertTrue(all(row['state'] == 'matched' for row in rows))

    def test_missing_empty_or_changed_rebuilt_artifact_preserves_other_evidence(self):
        path = self.build / 'dist/argon2-bundled.min.js'
        for value, expected in [(None, 2), (b'', 2), (b'changed', 1)]:
            with self.subTest(value=value):
                if value is None: path.unlink()
                else: path.write_bytes(value)
                code, rows = CHECKER.compare_rebuild(self.root, self.build, self.manifest)
                self.assertEqual(code, expected)
                self.assertEqual(rows[1]['state'], 'matched')
                self.assertEqual(rows[2]['state'], 'matched')

    def test_missing_or_duplicate_embedded_payload_cannot_be_source_success(self):
        path = self.root / 'demos/iron-serpent/public/argon2-bundled.min.js'
        for value in (b'no identifiable payload', self.bundle + self.bundle):
            path.write_bytes(value)
            code, rows = CHECKER.compare_rebuild(self.root, self.build, self.manifest)
            self.assertEqual(code, 2)
            self.assertEqual(rows[-1]['state'], 'unreadable')

    def test_wrong_fingerprint_and_nonregular_output_cannot_pass(self):
        self.manifest['artifacts'][0]['sha256'] = '0' * 64
        self.assertEqual(CHECKER.compare_rebuild(self.root, self.build, self.manifest)[0], 1)
        p = self.build / 'dist/argon2.wasm'
        p.unlink()
        p.symlink_to(self.root / 'demos/iron-serpent/public/argon2.wasm')
        self.assertEqual(CHECKER.compare_rebuild(self.root, self.build, self.manifest)[0], 2)

    def archive(self, name, kind=tarfile.REGTYPE):
        b = io.BytesIO()
        with tarfile.open(fileobj=b, mode='w') as archive:
            entry = tarfile.TarInfo(name)
            entry.type = kind
            if kind == tarfile.REGTYPE:
                entry.size = 6
                archive.addfile(entry, io.BytesIO(b'source'))
            else:
                entry.linkname = '/outside'
                archive.addfile(entry)
        return b.getvalue()

    def test_safe_source_inventory_excludes_committed_distribution(self):
        count = CHECKER.extract_sources(self.archive('src/real.c'), self.build)
        self.assertEqual(count, 1)
        self.assertEqual((self.build / 'src/real.c').read_bytes(), b'source')
        self.assertEqual(CHECKER.extract_sources(self.archive('dist/shipped.wasm'), self.build,
                                               ('dist',)), 0)
        self.assertFalse((self.build / 'dist/shipped.wasm').exists())

    def test_traversal_symlinks_and_existing_source_are_refused(self):
        for name, kind in [('../escape', tarfile.REGTYPE), ('/absolute', tarfile.REGTYPE),
                           ('alias', tarfile.SYMTYPE), ('hard', tarfile.LNKTYPE)]:
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    CHECKER.extract_sources(self.archive(name, kind), self.build)
        CHECKER.extract_sources(self.archive('src/immutable.c'), self.build)
        with self.assertRaises(FileExistsError):
            CHECKER.extract_sources(self.archive('src/immutable.c'), self.build)

    def test_actual_build_stage_capture_requires_complete_unchanged_environment(self):
        commands = [['emcc', '--version'], ['node', '--version'], ['npm', '--version'],
                    ['cmake', '--version'], ['bash', 'build-wasm.sh'],
                    ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund', '--cache', '/src/.build-only-npm-cache'],
                    ['node', 'node_modules/webpack-cli/bin/cli.js']]
        rows = [{'compilerStandardLibraryInputs': {'sysroot/libc.a': 'a' * 64}}]
        for index, command in enumerate(commands):
            output = ['2.0.23 (b15ca40ca02f469de3bf9a4de67a2655aede8974)', 'v14.15.5', '6.14.11'][index] if index < 3 else ''
            rows.append({'command': command, 'exit': 0, 'stdout': output})
        rows.append({'compilerInputsUnchanged': True, 'sourceLockUnchanged': True})
        rows[5]['stdout'] = '\n'.join('Building C object CMakeFiles/argon2.dir/' + name + '.o' for name in [
            'argon2/src/blake2/blake2b.c', 'argon2/src/argon2.c', 'argon2/src/core.c',
            'argon2/src/encoding.c', 'argon2/src/thread.c', 'src/argon2_library.c', 'argon2/src/ref.c'])
        render = lambda value: '\n'.join(json.dumps(x) for x in value)
        CHECKER.validate_build_stages(render(rows))
        bad = [[], rows[:-1], rows + [rows[1]], rows[:5] + rows[6:], [None] + rows[1:]]
        for field, value in [('exit', 1), ('exit', False), ('exit', None), ('stdout', 'wrong compiler'), ('stdout', None)]:
            altered = copy.deepcopy(rows)
            altered[1][field] = value
            bad.append(altered)
        changed = copy.deepcopy(rows)
        changed[-1]['sourceLockUnchanged'] = False
        bad.append(changed)
        missing_compile = copy.deepcopy(rows)
        missing_compile[5]['stdout'] = 'Built target argon2'
        bad.append(missing_compile)
        for value in bad:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    CHECKER.validate_build_stages(render(value))
        with self.assertRaises(ValueError):
            CHECKER.validate_build_stages('{broken')


if __name__ == '__main__':
    unittest.main()
