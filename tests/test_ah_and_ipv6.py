from pathlib import Path
from ipsecguard.models import Finding
from ipsecguard.scoring.rules import score_findings
from ipsecguard.parser.ah import extract_ah_findings
from ipsecguard.pipeline import analyze_capture

BASE_DIR = Path(__file__).resolve().parent.parent


def test_replay_protection_scoring():
    findings = [
        Finding(
            title="Replay protection weakness inferred",
            severity="high",
            category="replay_protection",
            derivation="inferred",
            description="Replay weakness",
            raw_value="monotonic=0.70, gaps=12",
        ),
        Finding(
            title="SA Lifetime excessive",
            severity="medium",
            category="key_management",
            derivation="observed",
            description="Lifetime > 24h",
            source_field="ike.sa_lifetime",
            raw_value=100000,
        ),
    ]
    score, subscores, _ = score_findings(findings)
    assert "replay_protection" in subscores
    assert subscores["replay_protection"] == 75
    assert subscores["key_management"] == 85


def test_ipv6_session_analysis():
    ipv6_sample = BASE_DIR / "data" / "synthetic" / "ipv6_session_1.pcap"
    if ipv6_sample.exists():
        result = analyze_capture(ipv6_sample)
        assert result.score > 0
        assert len(result.findings) > 0
        categories = {f.category for f in result.findings}
        assert "replay_protection" in categories or "crypto_strength" in categories


def test_ah_extraction_on_regular_pcap():
    sample = BASE_DIR / "samples"
    pcaps = list(sample.glob("*.pcap"))
    if pcaps:
        findings = extract_ah_findings(pcaps[0])
        assert isinstance(findings, list)
