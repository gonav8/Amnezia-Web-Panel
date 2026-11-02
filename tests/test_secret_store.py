import base64
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from secret_store import (
    ENVELOPE_FIELD,
    SecretStorageError,
    decrypt_secret,
    decode_recovery_snapshot,
    encrypt_secret,
    has_legacy_plaintext_secrets,
    is_envelope,
    seal_panel_state,
    seal_legacy_recovery_snapshots,
    unseal_panel_state,
)


class SecretStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.key_file = Path(self.temp.name) / 'panel.key'
        self.key = os.urandom(32)
        self.key_file.write_bytes(base64.b64encode(self.key) + b'\n')
        self.key_file.chmod(0o400)
        self.env = patch.dict(os.environ, {'SSH_CREDENTIALS_KEY_FILE': str(self.key_file)})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_encrypt_round_trip_and_randomized_nonce(self):
        first = encrypt_secret('sensitive-value', context='field:a')
        second = encrypt_secret('sensitive-value', context='field:a')
        self.assertTrue(is_envelope(first))
        self.assertNotEqual(first['nonce'], second['nonce'])
        self.assertNotIn('sensitive-value', str(first))
        self.assertEqual(decrypt_secret(first, context='field:a'), 'sensitive-value')

    def test_tampering_or_wrong_context_fails_closed(self):
        envelope = encrypt_secret('private-key-text', context='server:key')
        with self.assertRaises(SecretStorageError):
            decrypt_secret(envelope, context='server:password')
        changed = dict(envelope)
        raw = bytearray(base64.b64decode(changed['ciphertext']))
        raw[-1] ^= 1
        changed['ciphertext'] = base64.b64encode(raw).decode('ascii')
        with self.assertRaises(SecretStorageError):
            decrypt_secret(changed, context='server:key')

    def test_missing_or_wrong_key_fails_closed(self):
        envelope = encrypt_secret('secret', context='test')
        self.key_file.chmod(0o600)
        self.key_file.write_bytes(base64.b64encode(os.urandom(32)))
        self.key_file.chmod(0o400)
        with self.assertRaises(SecretStorageError):
            decrypt_secret(envelope, context='test')
        self.key_file.unlink()
        with self.assertRaises(SecretStorageError):
            encrypt_secret('another secret', context='test')

    def test_key_file_permissions_are_checked(self):
        self.key_file.chmod(0o644)
        with self.assertRaises(SecretStorageError):
            encrypt_secret('secret', context='test')

    def test_panel_state_seals_ssh_sudo_and_totp_but_preserves_other_data(self):
        original = {
            'servers': [{'uid': 'server-1', 'password': 'ssh-pass',
                         'private_key': '-----BEGIN PRIVATE KEY-----',
                         'sudo_password': 'sudo-pass', 'host': 'host'}],
            'users': [{'id': 'user-1', 'mfa': {'totp_secret': 'BASE32SECRET',
                                                'recovery_code_hashes': ['hash']}}],
            'settings': {'title': 'panel'},
        }
        sealed = seal_panel_state(original)
        self.assertEqual(original['servers'][0]['password'], 'ssh-pass')
        self.assertTrue(is_envelope(sealed['servers'][0]['password']))
        self.assertTrue(is_envelope(sealed['servers'][0]['private_key']))
        self.assertTrue(is_envelope(sealed['servers'][0]['sudo_password']))
        self.assertTrue(is_envelope(sealed['users'][0]['mfa']['totp_secret']))
        serialized = str(sealed)
        self.assertNotIn('ssh-pass', serialized)
        self.assertNotIn('PRIVATE KEY', serialized)
        self.assertNotIn('sudo-pass', serialized)
        self.assertNotIn('BASE32SECRET', serialized)
        unsealed = unseal_panel_state(sealed)
        self.assertEqual(unsealed, original)

    def test_legacy_plaintext_is_detected_and_empty_fields_need_no_key(self):
        state = {'servers': [{'password': 'legacy', 'private_key': '',
                              'sudo_password': 'legacy-sudo'}], 'users': []}
        self.assertTrue(has_legacy_plaintext_secrets(state))
        self.assertFalse(has_legacy_plaintext_secrets({'servers': [{'password': ''}], 'users': []}))
        self.assertEqual(encrypt_secret('', context='empty'), '')
        self.assertFalse(is_envelope({ENVELOPE_FIELD: 'unknown'}))

    def test_historical_recovery_snapshot_is_encrypted_once_and_remains_recoverable(self):
        recovery = Path(self.temp.name) / 'data.json.recovery'
        recovery.mkdir(mode=0o700)
        recovery.chmod(0o700)
        operation_id = 'a' * 32
        original = json.dumps({'servers': [{'password': 'old-ssh-secret'}],
                               'users': []}).encode()
        record = {'phase': 'committed', 'before_sha256': 'unchanged',
                  'before_base64': base64.b64encode(original).decode('ascii')}
        path = recovery / f'{operation_id}.json'
        path.write_text(json.dumps(record), encoding='utf-8')
        path.chmod(0o600)

        self.assertEqual(seal_legacy_recovery_snapshots(recovery), 1)
        migrated = json.loads(path.read_text(encoding='utf-8'))
        self.assertTrue(is_envelope(migrated['before_base64']))
        self.assertEqual(migrated['before_sha256'], 'unchanged')
        self.assertNotIn('old-ssh-secret', path.read_text(encoding='utf-8'))
        self.assertEqual(decode_recovery_snapshot(migrated, operation_id), original)
        self.assertEqual(seal_legacy_recovery_snapshots(recovery), 0)

    def test_recovery_store_commit_uses_encrypted_state_writer(self):
        from peer_recovery import RecoveryStore

        data_file = Path(self.temp.name) / 'state.json'
        before = json.dumps({'servers': [], 'users': []}).encode()
        data_file.write_bytes(before)
        after = {'servers': [{'uid': 'server-1', 'password': 'committed-secret'}],
                 'users': []}
        result = RecoveryStore(data_file).commit(
            'b' * 32, 'admin-1', 'test', 'intent', before, after)
        stored = json.loads(data_file.read_bytes())
        self.assertEqual(result['status'], 'success')
        self.assertTrue(is_envelope(stored['servers'][0]['password']))
        self.assertNotIn('committed-secret', data_file.read_text(encoding='utf-8'))

    def test_app_state_writer_seals_credentials_and_loader_unseals_in_memory(self):
        import app as panel

        original_path = panel.DATA_FILE
        panel.DATA_FILE = str(Path(self.temp.name) / 'panel-state.json')
        try:
            panel.save_data({'servers': [{'uid': 'server-2', 'host': 'vpn.example',
                                          'username': 'root', 'password': 'ssh-secret',
                                          'private_key': '',
                                          'sudo_password': 'sudo-secret'}], 'users': []})
            raw = Path(panel.DATA_FILE).read_text(encoding='utf-8')
            self.assertNotIn('ssh-secret', raw)
            self.assertNotIn('sudo-secret', raw)
            self.assertTrue(is_envelope(json.loads(raw)['servers'][0]['password']))
            self.assertTrue(is_envelope(json.loads(raw)['servers'][0]['sudo_password']))
            self.assertEqual(panel.load_data()['servers'][0]['password'], 'ssh-secret')
            self.assertEqual(panel.load_data()['servers'][0]['sudo_password'], 'sudo-secret')
        finally:
            panel.DATA_FILE = original_path


if __name__ == '__main__':
    unittest.main()
