#!/usr/bin/env python3
# Author: Toprak Ahmet Aydoğmuş
import json, uuid, datetime

def generate_indicator():
    return {"type": "indicator", "spec_version": "2.1", "id": "indicator--" + str(uuid.uuid4())}

if __name__ == "__main__":
    print("[*] Generating STIX 2.1 Threat Intel Bundle...")
    print(json.dumps(generate_indicator()))
