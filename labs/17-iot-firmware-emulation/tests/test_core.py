import unittest
from scripts.audit_firmware import MOCK_ROOTFS_FILES

class TestIoTFirmware(unittest.TestCase):
    def test_sensitive_files(self):
        paths = [f["path"] for f in MOCK_ROOTFS_FILES]
        self.assertIn("/etc/shadow", paths)

if __name__ == "__main__":
    unittest.main()
