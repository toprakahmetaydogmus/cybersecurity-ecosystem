# -*- coding: utf-8 -*-
"""
Threat Intelligence STIX 2.1 & IOC Normalizer CLI
Author: Toprak Ahmet Aydoğmuş
"""
import argparse
import json
from engine.stix_misp_pipeline import STIXThreatPipeline

def main():
    parser = argparse.ArgumentParser(description="CTI STIX 2.1 Pipeline CLI")
    parser.add_argument("--create-ioc", action="store_true", help="Create a STIX 2.1 indicator object")
    args = parser.parse_args()

    print("[*] Creating and Normalizing Threat Intelligence Indicators...")
    ind1 = STIXThreatPipeline.create_indicator("ipv4", "198.51.100.45", 95, "APT29", "CozyBear C2 node")
    ind2 = STIXThreatPipeline.create_indicator("domain", "c2-beacon-gateway.test", 85, "FIN7", "Financial data exfiltration domain")
    
    print(json.dumps([ind1, ind2], indent=2))
    
    print("\n[*] Generated Automated Firewall Drop Rules:")
    rules = STIXThreatPipeline.generate_firewall_drop_rules([ind1, ind2])
    for r in rules:
        print(f"  {r}")

if __name__ == "__main__":
    main()
