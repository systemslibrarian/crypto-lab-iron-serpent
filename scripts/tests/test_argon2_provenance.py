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


if __name__ == '__main__':
    unittest.main()
