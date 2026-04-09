"""
Tests for the insecure_crypto Python codemod.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from insecure_crypto import InsecureCryptoCodemod


class TestInsecureCryptoCodemod(unittest.TestCase):
    """Test suite for the insecure crypto codemod."""

    def setUp(self):
        """Create a temporary directory for test files."""
        self.temp_dir = tempfile.mkdtemp()
        self.codemod = InsecureCryptoCodemod(dry_run=True)

    def _write_test_file(self, content: str, filename: str = "test_file.py") -> str:
        """Helper to write a test file and return its path."""
        filepath = os.path.join(self.temp_dir, filename)
        with open(filepath, "w") as f:
            f.write(content)
        return filepath

    def test_md5_replacement(self):
        """Test that hashlib.md5() is replaced with hashlib.sha256()."""
        content = """
import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()
"""
        self._write_test_file(content)
        changes = self.codemod.run(self.temp_dir)

        self.assertEqual(len(changes), 1)
        self.assertIn("sha256", changes[0]["fixed"])
        self.assertIn("md5", changes[0]["original"])

    def test_sha1_replacement(self):
        """Test that hashlib.sha1() is replaced with hashlib.sha256()."""
        content = """
import hashlib

def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()
"""
        self._write_test_file(content)
        changes = self.codemod.run(self.temp_dir)

        self.assertEqual(len(changes), 1)
        self.assertIn("sha256", changes[0]["fixed"])

    def test_multiple_replacements(self):
        """Test that multiple insecure calls in one file are all replaced."""
        content = """
import hashlib

def hash_data(data):
    md5_hash = hashlib.md5(data).hexdigest()
    sha1_hash = hashlib.sha1(data).hexdigest()
    return md5_hash, sha1_hash
"""
        self._write_test_file(content)
        changes = self.codemod.run(self.temp_dir)

        self.assertGreaterEqual(len(changes), 2)
        for change in changes:
            self.assertIn("sha256", change["fixed"])

    def test_skips_test_files(self):
        """Test that test files are skipped."""
        content = "import hashlib\nhashlib.md5('test')"
        self._write_test_file(content, "test_crypto.py")
        changes = self.codemod.run(self.temp_dir)

        # Test files should be skipped, so no changes
        self.assertEqual(len(changes), 0)

    def test_skips_migrations(self):
        """Test that migration files are skipped."""
        os.makedirs(os.path.join(self.temp_dir, "migrations"))
        filepath = os.path.join(self.temp_dir, "migrations", "001_add_hash.py")
        with open(filepath, "w") as f:
            f.write("import hashlib\nhashlib.md5('test')")
        
        changes = self.codemod.run(self.temp_dir)
        self.assertEqual(len(changes), 0)

    def test_no_changes_on_safe_code(self):
        """Test that safe code is not modified."""
        content = """
import hashlib

def hash_securely(data):
    return hashlib.sha256(data.encode()).hexdigest()
"""
        self._write_test_file(content)
        changes = self.codemod.run(self.temp_dir)

        self.assertEqual(len(changes), 0)

    def test_cwe_mapping(self):
        """Test that changes include correct CWE identifiers."""
        content = "import hashlib\nhashlib.md5('test')"
        self._write_test_file(content)
        changes = self.codemod.run(self.temp_dir)

        self.assertEqual(len(changes), 1)
        self.assertIn("CWE-327", changes[0]["cwe"])
        self.assertIn("CWE-328", changes[0]["cwe"])

    def test_dry_run_does_not_modify_files(self):
        """Test that dry run reports changes but doesn't modify files."""
        content = "import hashlib\nhashlib.md5('test')"
        filepath = self._write_test_file(content)

        original_content = content
        changes = self.codemod.run(self.temp_dir)

        # Verify file wasn't modified
        with open(filepath) as f:
            actual_content = f.read()
        
        self.assertEqual(actual_content, original_content)
        self.assertGreater(len(changes), 0)

    def test_report_output(self):
        """Test that JSON report is correctly generated."""
        content = "import hashlib\nhashlib.md5('test')"
        self._write_test_file(content)

        report_path = os.path.join(self.temp_dir, "report.json")
        codemod = InsecureCryptoCodemod(dry_run=True)
        changes = codemod.run(self.temp_dir)

        report = {
            "codemod": "insecure_crypto_python",
            "files_scanned": codemod.files_scanned,
            "files_modified": codemod.files_modified,
            "changes": changes,
            "dry_run": True,
        }

        with open(report_path, "w") as f:
            json.dump(report, f)

        with open(report_path) as f:
            loaded = json.load(f)

        self.assertEqual(loaded["codemod"], "insecure_crypto_python")
        self.assertGreater(len(loaded["changes"]), 0)


if __name__ == "__main__":
    unittest.main()
