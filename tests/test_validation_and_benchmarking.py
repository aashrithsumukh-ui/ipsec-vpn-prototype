"""Unit tests for Validation Engine, Benchmarking, Simulation and Downgrade attacks."""
import unittest
from fastapi.testclient import TestClient

from ipsecguard.api.main import app
from ipsecguard.benchmarking import SecurityBenchmarkEngine, run_security_evaluation
from ipsecguard.validation import AttackValidationEngine, compare_sessions
from ipsecguard.attacks.downgrade import simulate_downgrade_attack
from ipsecguard.mode_detector import detect_ipsec_mode
from ipsecguard.pcap_validator import validate_pcap_file, check_pcap_magic_header


class TestValidationAndBenchmarking(unittest.TestCase):

    def setUp(self):
        self.client = TestClient(app)

    def test_validation_engine_downgrade_detection(self):
        baseline = {
            "session": "strong_baseline.pcap",
            "score": 98,
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"traffic_type": "web", "pfs": "on", "mode": "tunnel", "anomaly": False},
        }
        attack = {
            "session": "weak_attack.pcap",
            "score": 35,
            "observed": {"enc_algo": "3des-cbc", "integrity": "md5", "dh_group": 2, "ike_version": 2},
            "inferred": {"traffic_type": "web", "pfs": "off", "mode": "transport", "anomaly": True, "anomaly_conf": 0.88},
        }
        res = compare_sessions(baseline, attack)
        self.assertTrue(res["detected_configuration_changes"]["downgrade_detected"])
        self.assertGreater(res["security_score"]["difference"] * -1, 40)
        self.assertTrue(res["anomaly_detection"]["anomaly_detected"])
        self.assertEqual(res["confidence_level"]["overall"], "high")

    def test_benchmarking_engine_execution(self):
        engine = SecurityBenchmarkEngine()
        res = engine.run_benchmark(n_configs=10)
        self.assertIn("benchmark_summary", res)
        self.assertIn("metrics", res)
        self.assertGreaterEqual(res["benchmark_summary"]["pass_rate_pct"], 90.0)
        self.assertEqual(res["benchmark_summary"]["status"], "PASSED")
        self.assertIn("# Automated Security Evaluation & Benchmarking Report", res["markdown_report"])

    def test_simulate_api_endpoint(self):
        payload = {
            "traffic_type": "voip",
            "enc_algo": "3des-cbc",
            "integrity": "md5",
            "dh_group": 2,
            "pfs": "off",
            "mode": "transport",
            "apply_downgrade": True,
        }
        resp = self.client.post("/api/simulate", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "success")
        self.assertIn("assessment", data)
        self.assertIn("validation", data)
        self.assertIsNotNone(data["validation"])
        self.assertTrue(data["validation"]["detected_configuration_changes"]["downgrade_detected"])

    def test_benchmarking_api_endpoint(self):
        resp = self.client.get("/api/benchmarking")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("benchmark_summary", data)
        self.assertIn("metrics", data)

    def test_downgrade_attack_simulation(self):
        res = simulate_downgrade_attack(
            initial_cipher="AES-256-GCM",
            initial_dh=19,
            downgrade_to_cipher="3DES-CBC",
            downgrade_to_dh=2,
        )
        self.assertEqual(res["attack_type"], "IKE_SA_INIT_PROPOSAL_DOWNGRADE")
        self.assertEqual(res["tampered_parameters"]["enc_algo"], "3des-cbc")
        self.assertEqual(res["tampered_parameters"]["dh_group"], 2)
        self.assertTrue(len(res["vulnerabilities_introduced"]) >= 2)


if __name__ == "__main__":
    unittest.main()
