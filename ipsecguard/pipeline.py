from __future__ import annotations

from pathlib import Path

from ipsecguard.features.esp import extract_flow_features
from ipsecguard.ml.anomaly import load_or_create_model, score_anomaly
from ipsecguard.ml.explain import top_contributions
from ipsecguard.ml.heuristics import (
    anomaly_to_finding,
    infer_cipher_family,
    infer_mode,
    infer_replay_protection,
)
from ipsecguard.ml.traffic_classifier import LABELS_PATH, MODEL_PATH, load_model, predict_traffic
from ipsecguard.models import AnalysisResult, Finding
from ipsecguard.parser.ah import extract_ah_findings
from ipsecguard.parser.ike import extract_findings
from ipsecguard.reports.render import render_reports
from ipsecguard.scoring.compliance import ComplianceEvaluator
from ipsecguard.scoring.quantum import QuantumResilienceAssessor
from ipsecguard.scoring.remediation import RemediationAdvisor
from ipsecguard.scoring.rules import score_findings
from ipsecguard.scoring.threat_intel import MitreThreatIntel


def _traffic_finding(label: str, confidence: float, shap_values: list[dict]) -> Finding:
    return Finding(
        title="Traffic class inferred",
        severity="info",
        category="traffic",
        derivation="inferred",
        description="Traffic mix inferred from encrypted ESP size and timing metadata.",
        source_field="esp.feature_vector",
        raw_value=label,
        confidence=confidence,
        citation="XGBoost on held-out config split",
        likelihood="medium",
        impact="low",
        metadata={"shap_top_features": shap_values},
    )


def analyze_capture(pcap_path: str | Path) -> AnalysisResult:
    observed_findings, parser_summary = extract_findings(pcap_path)
    ah_findings = extract_ah_findings(pcap_path)
    features = extract_flow_features(pcap_path)
    inferred_findings: list[Finding] = []
    session_summary = {**parser_summary, "flow_count": int(len(features))}
    if not features.empty:
        primary_features = features.iloc[[0]].copy()
        primary = primary_features.iloc[0].to_dict()
        
        # Enhanced mode detection combining direct header evidence + flow heuristics
        try:
            from ipsecguard.mode_detector import detect_ipsec_mode
            mode_info = detect_ipsec_mode(str(pcap_path))
            session_summary["mode_detection"] = mode_info
            if mode_info.get("derivation") == "observed":
                inferred_findings.append(
                    Finding(
                        title=f"IPsec {mode_info['detected_mode'].capitalize()} mode confirmed",
                        severity="info" if mode_info["detected_mode"] == "tunnel" else "medium",
                        category="metadata_exposure",
                        derivation="observed",
                        description=mode_info["evidence"][0] if mode_info.get("evidence") else "Confirmed via packet inspection",
                        source_field="ike.notify / ip.header",
                        raw_value=mode_info["detected_mode"],
                        confidence=mode_info.get("confidence", 0.95),
                        citation="RFC 7296 / RFC 4301",
                        likelihood="low",
                        impact="low" if mode_info["detected_mode"] == "tunnel" else "medium",
                        metadata=mode_info.get("supporting_fields", {})
                    )
                )
            else:
                inferred_findings.append(infer_mode(primary))
        except Exception:
            inferred_findings.append(infer_mode(primary))

        inferred_findings.append(infer_cipher_family(primary))
        inferred_findings.append(infer_replay_protection(primary))
        anomaly_model = load_or_create_model(features)
        anomaly_score = float(score_anomaly(anomaly_model, primary_features))
        inferred_findings.append(anomaly_to_finding(anomaly_score))
        session_summary["anomaly_score"] = anomaly_score
        if MODEL_PATH.exists() and LABELS_PATH.exists():
            model = load_model()
            traffic_label, confidence = predict_traffic(model, primary_features)
            shap_values = top_contributions(model, primary_features)
            inferred_findings.append(_traffic_finding(traffic_label, confidence, shap_values))
            session_summary["traffic_label"] = traffic_label
    findings = observed_findings + ah_findings + inferred_findings
    findings.sort(
        key=lambda finding: {"high": 0, "medium": 1, "low": 2, "info": 3}.get(finding.severity, 4)
    )
    score, subscores, threat_matrix = score_findings(findings)
    compliance_report = ComplianceEvaluator.evaluate(findings, session_summary)
    remediations = RemediationAdvisor.generate_recommendations(findings)
    threat_intel = MitreThreatIntel.enrich_findings(findings)
    quantum_resilience = QuantumResilienceAssessor.assess(findings)
    flow_stats = primary if not features.empty else {}

    placeholder = AnalysisResult(
        score=score,
        subscores=subscores,
        findings=findings,
        threat_matrix=threat_matrix,
        reports=None,  # type: ignore[arg-type]
        session_summary=session_summary,
        compliance=compliance_report,
        remediations=remediations,
        flow_statistics=flow_stats,
        threat_intel=threat_intel,
        quantum_resilience=quantum_resilience,
    )
    artifacts = render_reports(placeholder)
    return AnalysisResult(
        score=score,
        subscores=subscores,
        findings=findings,
        threat_matrix=threat_matrix,
        reports=artifacts,
        session_summary=session_summary,
        compliance=compliance_report,
        remediations=remediations,
        flow_statistics=flow_stats,
        threat_intel=threat_intel,
        quantum_resilience=quantum_resilience,
    )
