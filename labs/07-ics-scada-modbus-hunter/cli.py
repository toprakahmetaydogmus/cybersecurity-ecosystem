# -*- coding: utf-8 -*-
"""
ICS / SCADA Modbus Protocol Threat Hunter CLI
Author: Toprak Ahmet Aydoğmuş
"""
import argparse
import json
from engine.scada_modbus_deep_hunter import ICSThreatHunter, ModbusAPU

def main():
    parser = argparse.ArgumentParser(description="ICS SCADA Modbus Threat Hunter CLI")
    parser.add_argument("--demo", action="store_true", help="Run live packet inspection demonstration")
    args = parser.parse_args()

    hunter = ICSThreatHunter(allowed_masters=["10.10.100.10"])
    print("[*] ICS / SCADA Modbus Threat Hunter Initialized.")

    read_pkt = bytes.fromhex("00010000000601030064000a")
    res1 = hunter.evaluate_traffic("10.10.100.10", "10.10.100.50", read_pkt)
    print(f"[+] Authorized Traffic Result: {res1['verdict']}")

    write_pkt = bytes.fromhex("00020000000601050001ff00")
    res2 = hunter.evaluate_traffic("192.168.1.99", "10.10.100.50", write_pkt)
    print(f"[!] Unauthorized Write Detected: {json.dumps(res2, indent=2)}")

if __name__ == "__main__":
    main()
