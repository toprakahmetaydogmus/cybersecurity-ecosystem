#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ICS Modbus/TCP Frame Parser and Threat Hunter
Author: Toprak Ahmet Aydoğmuş
"""

from typing import Dict, Any

FUNCTION_CODES = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers"
}

def parse_modbus_frame(raw_bytes: bytes) -> Dict[str, Any]:
    if len(raw_bytes) < 8:
        return {"error": "Frame too short"}

    trans_id = int.from_bytes(raw_bytes[0:2], "big")
    proto_id = int.from_bytes(raw_bytes[2:4], "big")
    length = int.from_bytes(raw_bytes[4:6], "big")
    unit_id = raw_bytes[6]
    function_code = raw_bytes[7]

    fc_name = FUNCTION_CODES.get(function_code, f"Unknown/Proprietary ({function_code})")
    is_write = function_code in [5, 6, 15, 16]

    return {
        "transaction_id": trans_id,
        "protocol_id": proto_id,
        "unit_id": unit_id,
        "function_code": function_code,
        "function_name": fc_name,
        "is_unauthorized_write_risk": is_write
    }

if __name__ == "__main__":
    print("[*] Running ICS / SCADA Modbus Threat Detection...")
    
    # Normal Read Holding Registers (FC 03)
    read_frame = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x64\x00\x0A"
    # Malicious/Unauthorized Write Single Coil (FC 05)
    write_frame = b"\x00\x02\x00\x00\x00\x06\x01\x05\x00\x01\xFF\x00"

    for frame in [read_frame, write_frame]:
        res = parse_modbus_frame(frame)
        if res.get("is_unauthorized_write_risk"):
            print(f"[!] ALERT: High-Risk Modbus Command Detected -> {res['function_name']} (Unit: {res['unit_id']})")
        else:
            print(f"[+] Legitimate Read Operation -> {res['function_name']}")
