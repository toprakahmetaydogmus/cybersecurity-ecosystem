import unittest
from scripts.ics_traffic_analyzer import parse_modbus_frame

class TestICSHunter(unittest.TestCase):
    def test_read_frame(self):
        read_frame = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x64\x00\x0A"
        res = parse_modbus_frame(read_frame)
        self.assertFalse(res["is_unauthorized_write_risk"])

    def test_unauthorized_write_frame(self):
        write_frame = b"\x00\x02\x00\x00\x00\x06\x01\x05\x00\x01\xFF\x00"
        res = parse_modbus_frame(write_frame)
        self.assertTrue(res["is_unauthorized_write_risk"])

if __name__ == "__main__":
    unittest.main()
