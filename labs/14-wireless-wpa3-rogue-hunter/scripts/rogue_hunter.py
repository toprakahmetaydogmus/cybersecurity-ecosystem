#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
802.11 Wireless Rogue AP and Evil Twin Hunter
Author: Toprak Ahmet Aydoğmuş
"""

KNOWN_BASELINES = {
    "Corporate-Secure-WPA3": {"valid_bssid": "00:11:22:33:44:55", "expected_crypto": "WPA3-Enterprise"}
}

def inspect_beacon(ssid: str, bssid: str, crypto: str):
    baseline = KNOWN_BASELINES.get(ssid)
    if not baseline:
        print(f"[+] Unmanaged Guest SSID: {ssid} ({bssid})")
        return

    if bssid != baseline["valid_bssid"]:
        print(f"[!] CRITICAL: Rogue AP / Evil Twin Detected! SSID: {ssid} on Spoofed BSSID: {bssid}")
    elif crypto != baseline["expected_crypto"]:
        print(f"[!] HIGH: Encryption Downgrade Attack Detected on {ssid}! (Expected: {baseline['expected_crypto']}, Got: {crypto})")
    else:
        print(f"[+] Authorized AP Beacon Verified: {ssid} ({bssid})")

if __name__ == "__main__":
    print("[*] Scanning Wireless Beacons...")
    inspect_beacon("Corporate-Secure-WPA3", "00:11:22:33:44:55", "WPA3-Enterprise")
    inspect_beacon("Corporate-Secure-WPA3", "AA:BB:CC:DD:EE:FF", "WPA2-PSK")
