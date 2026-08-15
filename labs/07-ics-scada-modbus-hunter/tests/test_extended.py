# -*- coding: utf-8 -*-
import unittest
from engine.scada_modbus_deep_hunter import ICSThreatHunter, ModbusAPU

class TestSCADAModbusExtended(unittest.TestCase):
    def setUp(self):
        self.hunter = ICSThreatHunter(allowed_masters=["10.10.100.10"])

    def test_modbus_packet_parsing(self):
        pkt = bytes.fromhex("00010000000601030064000a")
        parsed = ModbusAPU.parse_packet(pkt)
        self.assertEqual(parsed["function_code"], 3)
        self.assertEqual(parsed["function_name"], "Read Holding Registers")
        self.assertEqual(parsed["unit_id"], 1)

    def test_unauthorized_master_alert(self):
        pkt = bytes.fromhex("00010000000601030064000a")
        res = self.hunter.evaluate_traffic("192.168.50.99", "10.10.100.50", pkt)
        self.assertEqual(res["verdict"], "MALICIOUS / BLOCKED")
        self.assertTrue(any(a["rule_id"] == "ICS-001" for a in res["anomalies"]))

    def test_critical_write_coil_alert(self):
        pkt = bytes.fromhex("00020000000601050001ff00")
        res = self.hunter.evaluate_traffic("10.10.100.10", "10.10.100.50", pkt)
        self.assertTrue(any(a["rule_id"] == "ICS-002" for a in res["anomalies"]))

if __name__ == "__main__":
    unittest.main()
