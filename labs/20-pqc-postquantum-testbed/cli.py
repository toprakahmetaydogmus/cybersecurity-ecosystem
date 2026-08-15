# -*- coding: utf-8 -*-
"""
NIST Post-Quantum Cryptography Benchmark CLI
Author: Toprak Ahmet Aydoğmuş
"""
import argparse
import json
from engine.nist_pqc_benchmark_suite import NISTPQCBenchmarkSuite

def main():
    parser = argparse.ArgumentParser(description="NIST FIPS 203 ML-KEM-768 Benchmark CLI")
    parser.add_argument("--benchmark", action="store_true", help="Run ML-KEM-768 cycle benchmark")
    args = parser.parse_args()

    print("[*] Executing NIST FIPS 203 (ML-KEM-768 / Kyber) Cryptographic Benchmark...")
    results = NISTPQCBenchmarkSuite.run_ml_kem_768_cycle()
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
