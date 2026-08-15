# -*- coding: utf-8 -*-
"""
Industrial Control Systems (ICS) / SCADA Modbus TCP Deep Threat Hunter v3.0
Author: Toprak Ahmet Aydoğmuş
License: MIT
"""

import struct
import time
import json
from typing import Dict, List, Any, Optional

class ModbusAPU:
    """
    Modbus Application Protocol Header (MBAP) and Protocol Data Unit (PDU) Parser
    """
    FUNCTION_NAMES = {
        1: "Read Coils",
        2: "Read Discrete Inputs",
        3: "Read Holding Registers",
        4: "Read Input Registers",
        5: "Write Single Coil",
        6: "Write Single Register",
        7: "Read Exception Status",
        8: "Diagnostic Loopback",
        15: "Write Multiple Coils",
        16: "Write Multiple Registers",
        17: "Report Server ID",
        43: "Encapsulated Interface Transport (Read Device ID)"
    }

    CRITICAL_CONTROL_FUNCTIONS = [5, 6, 15, 16]

    @classmethod
    def parse_packet(cls, raw_bytes: bytes) -> Dict[str, Any]:
        if len(raw_bytes) < 8:
            return {"error": "Malformed packet: Less than 8 bytes"}

        # MBAP Header: TransID (2), ProtoID (2), Length (2), UnitID (1)
        trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", raw_bytes[:7])
        function_code = raw_bytes[7]
        pdu_payload = raw_bytes[8:]

        fc_name = cls.FUNCTION_NAMES.get(function_code, f"Vendor/Proprietary ({function_code})")
        is_write = function_code in cls.CRITICAL_CONTROL_FUNCTIONS

        # Parse specific function data
        parsed_data = {}
        if function_code in [5, 6] and len(pdu_payload) >= 4:
            address, value = struct.unpack(">HH", pdu_payload[:4])
            parsed_data = {"target_address": address, "target_value": hex(value)}
        elif function_code in [1, 2, 3, 4] and len(pdu_payload) >= 4:
            start_addr, count = struct.unpack(">HH", pdu_payload[:4])
            parsed_data = {"start_address": start_addr, "quantity": count}

        return {
            "transaction_id": trans_id,
            "protocol_id": proto_id,
            "length": length,
            "unit_id": unit_id,
            "function_code": function_code,
            "function_name": fc_name,
            "is_critical_control_action": is_write,
            "details": parsed_data,
            "raw_hex": raw_bytes.hex()
        }

class ICSThreatHunter:
    """
    Stateful anomaly and policy violation detector for SCADA operations.
    """
    def __init__(self, allowed_masters: List[str] = None):
        self.allowed_masters = allowed_masters or ["10.10.100.10", "10.10.100.11"]
        self.security_events: List[Dict[str, Any]] = []

    def evaluate_traffic(self, source_ip: str, target_ip: str, raw_payload: bytes) -> Dict[str, Any]:
        parsed = ModbusAPU.parse_packet(raw_payload)
        if "error" in parsed:
            return {"status": "ERROR", "message": parsed["error"]}

        anomalies = []

        # Check 1: Unauthorized SCADA Master
        if source_ip not in self.allowed_masters:
            anomalies.append({
                "rule_id": "ICS-001",
                "severity": "CRITICAL",
                "title": "Unauthorized SCADA Master Node Detected",
                "description": f"IP {source_ip} is communicating with PLC {target_ip} without authorization."
            })

        # Check 2: Unauthorized Coil/Register Modification
        if parsed["is_critical_control_action"]:
            anomalies.append({
                "rule_id": "ICS-002",
                "severity": "HIGH",
                "title": f"Critical ICS State Write Command: {parsed['function_name']}",
                "description": f"Modification attempted on Unit ID {parsed['unit_id']}, details: {parsed['details']}"
            })

        # Check 3: Diagnostic Reset / Loopback
        if parsed["function_code"] == 8:
            anomalies.append({
                "rule_id": "ICS-003",
                "severity": "CRITICAL",
                "title": "Modbus Diagnostic / Restart Attempt (Potential Denial of Service)",
                "description": "Diagnostic loopback/restart function code executed against PLC."
            })

        verdict = "MALICIOUS / BLOCKED" if anomalies else "AUTHORIZED"
        event = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "source_ip": source_ip,
            "target_plc_ip": target_ip,
            "parsed_packet": parsed,
            "anomalies": anomalies,
            "verdict": verdict
        }
        self.security_events.append(event)
        return event

if __name__ == "__main__":
    print("[*] SCADA Modbus Deep Threat Hunter v3.0 Initialized.")
    hunter = ICSThreatHunter(allowed_masters=["10.10.100.10"])
    
    # 1. Normal Read Holding Registers from authorized master
    read_pkt = bytes.fromhex("00010000000601030064000a")
    res1 = hunter.evaluate_traffic("10.10.100.10", "10.10.100.50", read_pkt)
    print(f"[+] Authorized Telemetry: {res1['verdict']}")

    # 2. Rogue master sending Write Single Coil
    rogue_pkt = bytes.fromhex("00020000000601050001ff00")
    res2 = hunter.evaluate_traffic("192.168.1.99", "10.10.100.50", rogue_pkt)
    print(f"[!] Threat Detected: {json.dumps(res2, indent=2)}")
