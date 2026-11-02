"""Common test-only compatibility defaults.

Production requires administrator MFA unless explicitly overridden. Existing
feature tests predate MFA and should remain focused on their individual feature;
new MFA security tests opt back into the production policy explicitly.
"""
import atexit
import os
import secrets
import shutil
import tempfile

os.environ.setdefault("PANEL_ADMIN_MFA_REQUIRED", "0")

if "SSH_CREDENTIALS_KEY_FILE" not in os.environ:
    _test_key_dir = tempfile.mkdtemp(prefix="prvtpro-test-key-")
    _test_key_file = os.path.join(_test_key_dir, "ssh-credentials.key")
    with open(_test_key_file, "xb") as key_file:
        key_file.write(secrets.token_bytes(32))
    os.chmod(_test_key_file, 0o400)
    os.environ["SSH_CREDENTIALS_KEY_FILE"] = _test_key_file
    atexit.register(shutil.rmtree, _test_key_dir, ignore_errors=True)
