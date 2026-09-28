from __future__ import annotations

from pathlib import Path
from tempfile import NamedTemporaryFile
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel

from ipsecguard.attacks.downgrade import simulate_downgrade_attack
from ipsecguard.benchmarking import SecurityBenchmarkEngine, run_security_evaluation
from ipsecguard.db.repository import AnalysisRepository
from ipsecguard.errors import IPsecGuardError, PCAPValidationError, format_error_response
from ipsecguard.mode_detector import detect_ipsec_mode
from ipsecguard.models import Finding
from ipsecguard.parser.frames import extract_packet_frames, generate_synthetic_frames
from ipsecguard.pcap_validator import validate_pcap_file
from ipsecguard.pipeline import analyze_capture
from ipsecguard.scoring.compliance import ComplianceEvaluator
from ipsecguard.scoring.quantum import QuantumResilienceAssessor
from ipsecguard.scoring.remediation import RemediationAdvisor
from ipsecguard.scoring.rules import score_findings
from ipsecguard.scoring.threat_intel import MitreThreatIntel
from ipsecguard.sniffer.live import live_sniffer
from ipsecguard.tunnel.peer import peer_node
from ipsecguard.utils import REPORTS_DIR
from ipsecguard.validation import AttackValidationEngine, compare_sessions

app = FastAPI(title="IPsecGuard AI")
repository = AnalysisRepository()
BASE_DIR = Path(__file__).resolve().parent.parent.parent
INDEX_PATH = BASE_DIR / "frontend" / "index.html"


@app.exception_handler(IPsecGuardError)
async def ipsecguard_exception_handler(request: Request, exc: IPsecGuardError):
    status_code = 400 if isinstance(exc, PCAPValidationError) else 500
    return JSONResponse(status_code=status_code, content=exc.to_dict())


def _report_paths(executive_id: str, technical_id: str) -> list[Path]:
    executive_html = REPORTS_DIR / f"{executive_id}-executive.html"
    technical_html = REPORTS_DIR / f"{technical_id}-technical.html"
    return [
        executive_html,
        executive_html.with_suffix(".pdf"),
        technical_html,
        technical_html.with_suffix(".pdf"),
    ]


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/interfaces")
def list_network_interfaces() -> list[dict]:
    try:
        from scapy.all import get_if_list
        interfaces = []
        for iface in get_if_list():
            interfaces.append({
                "id": str(iface),
                "name": str(iface),
                "description": f"Network Adapter ({iface})"
            })
        if not interfaces:
            interfaces = [{"id": "default", "name": "Default Network Adapter", "description": "Auto-detect"}]
        return interfaces
    except Exception:
        return [{"id": "default", "name": "Default Network Adapter", "description": "Auto-detect"}]


@app.get("/api/samples")
def list_samples() -> list[str]:
    samples_dir = BASE_DIR / "samples"
    if not samples_dir.exists():
        return []
    return [p.name for p in sorted(samples_dir.glob("*.pcap"))]


@app.post("/api/analyze-sample/{sample_name}")
def analyze_sample(sample_name: str) -> dict:
    samples_dir = BASE_DIR / "samples"
    sample_path = samples_dir / sample_name
    if not sample_path.exists() or not sample_name.endswith(".pcap"):
        raise HTTPException(status_code=404, detail="Sample not found")
    result = analyze_capture(sample_path)
    report_paths = _report_paths(
        result.reports.executive_report_id,
        result.reports.technical_report_id,
    )
    executive_html, _, technical_html, _ = report_paths
    payload = result.to_dict()
    payload["packet_frames"] = extract_packet_frames(sample_path)
    repository.save_reports(
        [
            (
                result.reports.executive_report_id,
                "executive",
                str(executive_html),
                payload,
            ),
            (
                result.reports.technical_report_id,
                "technical",
                str(technical_html),
                payload,
            ),
        ]
    )
    return payload


@app.post("/api/compare")
async def compare_captures(
    file_a: UploadFile = File(None),
    file_b: UploadFile = File(None),
    sample_a: str = Form(""),
    sample_b: str = Form("")
) -> dict:
    samples_dir = BASE_DIR / "samples"
    temp_a, temp_b = None, None
    try:
        if file_a and file_a.filename:
            with NamedTemporaryFile(suffix=".pcap", delete=False) as h:
                h.write(await file_a.read())
                path_a = Path(h.name)
                temp_a = path_a
        elif sample_a:
            path_a = samples_dir / sample_a
        else:
            raise HTTPException(status_code=400, detail="Primary capture (Capture A) is missing.")

        if file_b and file_b.filename:
            with NamedTemporaryFile(suffix=".pcap", delete=False) as h:
                h.write(await file_b.read())
                path_b = Path(h.name)
                temp_b = path_b
        elif sample_b:
            path_b = samples_dir / sample_b
        else:
            raise HTTPException(status_code=400, detail="Comparison capture (Capture B) is missing.")

        if not path_a.exists() or not path_b.exists():
            raise HTTPException(status_code=404, detail="One or both capture files could not be found.")

        result_a = analyze_capture(path_a)
        result_b = analyze_capture(path_b)

        score_delta = result_b.score - result_a.score
        subscore_deltas = {
            k: result_b.subscores.get(k, 0) - result_a.subscores.get(k, 0)
            for k in result_a.subscores
        }

        titles_a = {f.title for f in result_a.findings}
        titles_b = {f.title for f in result_b.findings}

        resolved_findings = [f.to_dict() for f in result_a.findings if f.title not in titles_b]
        new_findings = [f.to_dict() for f in result_b.findings if f.title not in titles_a]

        return {
            "capture_a": result_a.to_dict(),
            "capture_b": result_b.to_dict(),
            "comparison": {
                "score_delta": score_delta,
                "subscore_deltas": subscore_deltas,
                "resolved_count": len(resolved_findings),
                "resolved_findings": resolved_findings,
                "new_count": len(new_findings),
                "new_findings": new_findings,
            }
        }
    finally:
        if temp_a is not None:
            temp_a.unlink(missing_ok=True)
        if temp_b is not None:
            temp_b.unlink(missing_ok=True)


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return INDEX_PATH.read_text(encoding="utf-8")


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)) -> dict:
    filename = file.filename or ""
    if not (filename.endswith(".pcap") or filename.endswith(".pcapng") or filename.endswith(".cap")):
        raise HTTPException(status_code=400, detail="Please upload a .pcap/.pcapng file")
    temp_path: Path | None = None
    with NamedTemporaryFile(suffix=".pcap", delete=False) as handle:
        handle.write(await file.read())
        temp_path = Path(handle.name)
    try:
        validation_result = validate_pcap_file(temp_path, min_packets=1, require_ipsec=False)
        result = analyze_capture(temp_path)
        report_paths = _report_paths(
            result.reports.executive_report_id,
            result.reports.technical_report_id,
        )
        executive_html, _, technical_html, _ = report_paths
        payload = result.to_dict()
        payload["pcap_validation"] = validation_result
        payload["packet_frames"] = extract_packet_frames(temp_path)
        repository.save_reports(
            [
                (
                    result.reports.executive_report_id,
                    "executive",
                    str(executive_html),
                    payload,
                ),
                (
                    result.reports.technical_report_id,
                    "technical",
                    str(technical_html),
                    payload,
                ),
            ]
        )
        return payload
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)


@app.get("/reports/{report_id}/{kind}")
def get_report(report_id: str, kind: Literal["executive", "technical"]) -> FileResponse:
    record = repository.get_report(report_id, kind)
    if record is None:
        raise HTTPException(status_code=404, detail="Report not found")
    path = Path(record.path)
    pdf_path = path.with_suffix(".pdf")
    target = pdf_path if pdf_path.exists() else path
    media_type = "application/pdf" if target.suffix == ".pdf" else "text/html"
    return FileResponse(target, media_type=media_type, filename=target.name)


@app.get("/api/history")
def get_history() -> list[dict]:
    return repository.list_recent_reports()


@app.get("/api/history/{report_id}")
def get_history_detail(report_id: str) -> dict:
    import json
    record = repository.get_report(report_id, "technical")
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return json.loads(record.payload_json)


@app.get("/api/export/{report_id}/json")
def export_json(report_id: str) -> dict:
    import json
    record = repository.get_report(report_id, "technical")
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return json.loads(record.payload_json)


@app.get("/api/export/{report_id}/csv")
def export_csv(report_id: str):
    import csv
    import io
    import json
    from fastapi.responses import Response

    record = repository.get_report(report_id, "technical")
    if record is None:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    payload = json.loads(record.payload_json)
    findings = payload.get("findings", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Title", "Severity", "Category", "Derivation", "Value", "Confidence", "Citation", "Description"])
    for f in findings:
        writer.writerow([
            f.get("title", ""),
            f.get("severity", ""),
            f.get("category", ""),
            f.get("derivation", ""),
            f.get("raw_value", ""),
            f.get("confidence_pct", "N/A"),
            f.get("citation", ""),
            f.get("description", ""),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=ipsecguard_findings_{report_id}.csv"}
    )


@app.get("/api/demo/scenarios")
def get_demo_scenarios() -> dict:
    return {
        "scenarios": [
            {
                "id": "cnsa2_quantum",
                "title": "CNSA 2.0 / Post-Quantum Ready",
                "badge": "RECOMMENDED",
                "score": 98,
                "enc_algo": "aes256-gcm",
                "integrity": "none",
                "dh_group": 20,
                "pfs": "on",
                "mode": "tunnel",
                "traffic_type": "web",
                "description": "Commercial National Security Algorithm (CNSA 2.0) compliant tunnel with AES-256-GCM, ECP-384, and Perfect Forward Secrecy."
            },
            {
                "id": "sweet32_logjam_downgrade",
                "title": "Sweet32 & Logjam Exploitation",
                "badge": "VULNERABLE",
                "score": 24,
                "enc_algo": "3des-cbc",
                "integrity": "md5",
                "dh_group": 2,
                "pfs": "off",
                "mode": "tunnel",
                "traffic_type": "bulk",
                "description": "Legacy cipher suite vulnerable to Sweet32 (CVE-2016-2183), Logjam discrete logarithm precomputation (CVE-2015-4000), and MD5 collisions."
            },
            {
                "id": "transport_leakage",
                "title": "Transport Mode Address Leakage",
                "badge": "LEAKAGE",
                "score": 52,
                "enc_algo": "aes128-cbc",
                "integrity": "sha1",
                "dh_group": 14,
                "pfs": "off",
                "mode": "transport",
                "traffic_type": "voip",
                "description": "Host-to-Host transport mode exposing inner IP source and destination headers in cleartext with SHA-1 legacy integrity."
            },
            {
                "id": "chatgpt_sse_stream",
                "title": "ChatGPT Token Stream / AI Flow",
                "badge": "AI CLASSIFIED",
                "score": 92,
                "enc_algo": "aes256-gcm",
                "integrity": "none",
                "dh_group": 19,
                "pfs": "on",
                "mode": "tunnel",
                "traffic_type": "web",
                "description": "Encrypted Web / ChatGPT Server-Sent Events token stream with XGBoost timing-profile classification and SHAP explainability."
            }
        ]
    }


# ---------------------------------------------------------
# Live Packet Sniffing & Stream Analysis Endpoints
# ---------------------------------------------------------

@app.post("/api/sniffer/start")
def start_sniffer(
    filter_bpf: str = Form("ip or ip6"),
    iface: str = Form(None),
    mode: str = Form("auto"),
    virtual_flow_type: str = Form("web")
) -> dict:
    return live_sniffer.start(
        filter_bpf=filter_bpf,
        iface=iface if iface and iface != "default" else None,
        mode=mode,
        virtual_flow_type=virtual_flow_type
    )


@app.post("/api/sniffer/pulse")
def pulse_synthetic_packets(
    traffic_type: str = Form("web"),
    count: int = Form(5)
) -> list[dict]:
    return live_sniffer.pulse_synthetic_burst(traffic_type=traffic_type, count=count)


@app.post("/api/sniffer/stop")
def stop_sniffer() -> dict:
    return live_sniffer.stop()


@app.get("/api/sniffer/status")
def sniffer_status() -> dict:
    return {
        "is_running": live_sniffer.is_running,
        "mode": live_sniffer.mode,
        "packet_count": len(live_sniffer.packet_details),
        "start_time": live_sniffer.start_time,
        "virtual_flow": live_sniffer.virtual_flow_type
    }


@app.get("/api/sniffer/packets")
def sniffer_packets(limit: int = 100) -> list[dict]:
    return live_sniffer.get_recent_packets(limit=limit)


@app.post("/api/sniffer/analyze")
def analyze_sniffer() -> dict:
    try:
        result = live_sniffer.analyze_live_capture()
        report_paths = _report_paths(
            result.reports.executive_report_id,
            result.reports.technical_report_id,
        )
        executive_html, _, technical_html, _ = report_paths
        payload = result.to_dict()
        payload["packet_frames"] = live_sniffer.get_recent_packets(100)
        repository.save_reports(
            [
                (
                    result.reports.executive_report_id,
                    "executive",
                    str(executive_html),
                    payload,
                ),
                (
                    result.reports.technical_report_id,
                    "technical",
                    str(technical_html),
                    payload,
                ),
            ]
        )
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------
# Peer-to-Peer Live IPsec VPN Tunnel & Audit Endpoints
# ---------------------------------------------------------

@app.post("/api/tunnel/start-listener")
def start_tunnel_listener(port: int = Form(8500)) -> dict:
    return peer_node.start_listener(port=port)


@app.post("/api/tunnel/stop-listener")
def stop_tunnel_listener() -> dict:
    return peer_node.stop_listener()


@app.post("/api/tunnel/connect")
def connect_tunnel(
    peer_host: str = Form(...),
    peer_port: int = Form(8500),
    cipher_preset: str = Form("AES-256-GCM")
) -> dict:
    return peer_node.initiate_tunnel(
        peer_host=peer_host,
        peer_port=peer_port,
        cipher_preset=cipher_preset
    )


@app.post("/api/tunnel/send")
def send_tunnel_payload(message: str = Form(...)) -> dict:
    return peer_node.send_secure_payload(text_message=message)


@app.get("/api/tunnel/status")
def tunnel_status() -> dict:
    return {
        "is_running": peer_node._running,
        "is_connected": peer_node.is_connected,
        "bind_port": peer_node.bind_port,
        "peer_host": peer_node.peer_host,
        "peer_port": peer_node.peer_port,
        "cipher_preset": peer_node.cipher_preset,
        "packets_exchanged": len(peer_node.exchanged_packets),
        "messages": peer_node.message_log[-20:]  # latest 20 messages
    }


@app.get("/api/tunnel/packets")
def tunnel_packets() -> list[dict]:
    return peer_node.get_packet_logs()


@app.post("/api/tunnel/audit")
def audit_tunnel() -> dict:
    try:
        result = peer_node.audit_live_tunnel()
        report_paths = _report_paths(
            result.reports.executive_report_id,
            result.reports.technical_report_id,
        )
        executive_html, _, technical_html, _ = report_paths
        payload = result.to_dict()
        repository.save_reports(
            [
                (
                    result.reports.executive_report_id,
                    "executive",
                    str(executive_html),
                    payload,
                ),
                (
                    result.reports.technical_report_id,
                    "technical",
                    str(technical_html),
                    payload,
                ),
            ]
        )
        return payload
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ---------------------------------------------------------
# Interactive Simulation, Benchmarking & Attack Endpoints
# ---------------------------------------------------------

class SimulateRequest(BaseModel):
    traffic_type: str = "web"
    enc_algo: str = "aes256-gcm"
    integrity: str = "none"
    dh_group: int = 20
    pfs: str = "on"
    mode: str = "tunnel"
    apply_downgrade: bool = False


@app.post("/api/simulate")
def simulate_session(req: SimulateRequest) -> dict:
    enc_algo = req.enc_algo.lower()
    integrity = "none" if "gcm" in enc_algo else req.integrity.lower()
    dh_group = req.dh_group
    pfs = req.pfs.lower()
    mode = req.mode.lower()
    traffic_type = req.traffic_type.lower()
    ike_version = 2 if dh_group >= 14 else 1

    observed = {
        "enc_algo": enc_algo,
        "integrity": integrity,
        "dh_group": dh_group,
        "ike_version": ike_version,
    }
    inferred = {
        "traffic_type": traffic_type,
        "traffic_conf": 0.94,
        "pfs": pfs,
        "pfs_conf": 0.90 if pfs == "on" else 0.85,
        "mode": mode,
        "mode_conf": 0.95 if mode == "tunnel" else 0.88,
        "anomaly": False,
        "anomaly_conf": 0.05,
    }

    findings = []
    # 1. Cipher Finding
    if enc_algo in ("3des-cbc", "des-cbc", "3des", "des"):
        findings.append(Finding(
            title=f"Vulnerable cipher: {enc_algo.upper()}",
            severity="high",
            category="crypto_strength",
            derivation="observed",
            description=f"{enc_algo.upper()} uses a 64-bit block size vulnerable to Sweet32 collision attacks (CVE-2016-2183).",
            source_field="ike.sa.encryption",
            raw_value=enc_algo,
            confidence=1.0,
            citation="NIST SP 800-77 Rev. 1 Sec 3.2 / CVE-2016-2183",
            likelihood="high",
            impact="high"
        ))
    else:
        findings.append(Finding(
            title=f"Robust cipher: {enc_algo.upper()}",
            severity="info",
            category="crypto_strength",
            derivation="observed",
            description=f"{enc_algo.upper()} provides quantum-resistant 256-bit / modern authenticated encryption.",
            source_field="ike.sa.encryption",
            raw_value=enc_algo,
            confidence=1.0,
            citation="NIST SP 800-77 Rev. 1",
            likelihood="low",
            impact="low"
        ))

    # 2. Integrity Finding
    if integrity in ("md5", "hmac-md5"):
        findings.append(Finding(
            title="Weak integrity hash: MD5",
            severity="high",
            category="crypto_strength",
            derivation="observed",
            description="MD5 is cryptographically broken and vulnerable to practical collision attacks.",
            source_field="ike.sa.integrity",
            raw_value="md5",
            confidence=1.0,
            citation="RFC 6151 / NIST SP 800-77",
            likelihood="high",
            impact="high"
        ))
    elif integrity in ("sha1", "hmac-sha1"):
        findings.append(Finding(
            title="Deprecated integrity hash: SHA-1",
            severity="medium",
            category="crypto_strength",
            derivation="observed",
            description="SHA-1 is deprecated by NIST and susceptible to theoretical collision attacks.",
            source_field="ike.sa.integrity",
            raw_value="sha1",
            confidence=1.0,
            citation="NIST SP 800-131A",
            likelihood="medium",
            impact="medium"
        ))

    # 3. DH Group Finding
    if dh_group in (1, 2, 5):
        findings.append(Finding(
            title=f"Legacy Diffie-Hellman Group {dh_group}",
            severity="high",
            category="key_management",
            derivation="observed",
            description=f"Group {dh_group} (MODP <= 1024) is vulnerable to discrete logarithm precomputations (Logjam attack, CVE-2015-4000).",
            source_field="ike.sa.dh_group",
            raw_value=f"Group {dh_group}",
            confidence=1.0,
            citation="RFC 8247 / CVE-2015-4000",
            likelihood="high",
            impact="high"
        ))
    else:
        findings.append(Finding(
            title=f"Modern Diffie-Hellman Group {dh_group}",
            severity="info",
            category="key_management",
            derivation="observed",
            description=f"Group {dh_group} provides robust key exchange protection adhering to NIST recommendations.",
            source_field="ike.sa.dh_group",
            raw_value=f"Group {dh_group}",
            confidence=1.0,
            citation="RFC 8247",
            likelihood="low",
            impact="low"
        ))

    # 4. PFS Finding
    if pfs == "off":
        findings.append(Finding(
            title="Perfect Forward Secrecy disabled",
            severity="high",
            category="forward_secrecy",
            derivation="inferred",
            description="PFS is disabled (Quick Mode does not perform new DH exchange). Long-term private key compromise exposes all captured historical traffic.",
            source_field="ike.quick_mode.dh",
            raw_value="off",
            confidence=0.85,
            citation="NIST SP 800-77 Sec. 4",
            likelihood="high",
            impact="high"
        ))

    # 5. Mode Finding
    if mode == "transport":
        findings.append(Finding(
            title="IPsec Transport Mode active",
            severity="medium",
            category="metadata_exposure",
            derivation="observed",
            description="Transport mode encrypts payload only, leaving original IP source and destination headers visible in cleartext.",
            source_field="ike.notify.use_transport_mode",
            raw_value="transport",
            confidence=0.95,
            citation="RFC 4301 / RFC 7296",
            likelihood="medium",
            impact="medium"
        ))

    # 6. Traffic class
    findings.append(Finding(
        title="Traffic class inferred",
        severity="info",
        category="traffic",
        derivation="inferred",
        description=f"Traffic mix inferred as '{traffic_type}' based on encrypted packet size and inter-arrival timing profile.",
        source_field="esp.feature_vector",
        raw_value=traffic_type,
        confidence=0.94,
        citation="XGBoost 8-Class Traffic Model",
        likelihood="low",
        impact="low"
    ))

    findings.sort(key=lambda f: {"high": 0, "medium": 1, "low": 2, "info": 3}.get(f.severity, 4))
    score, subscores, threat_matrix = score_findings(findings)
    session_summary = {
        "flow_count": 1,
        "traffic_label": traffic_type,
        "enc_algo": enc_algo,
        "integrity": integrity,
        "dh_group": dh_group,
        "pfs": pfs,
        "mode": mode,
    }
    compliance = ComplianceEvaluator.evaluate(findings, session_summary)
    remediations = RemediationAdvisor.generate_recommendations(findings)
    threat_intel = MitreThreatIntel.enrich_findings(findings)
    quantum = QuantumResilienceAssessor.assess(findings)

    simulated_session = {
        "session": f"sim_{mode}_{enc_algo}_dh{dh_group}_pfs-{pfs}_{traffic_type}.pcap",
        "score": score,
        "subscores": subscores,
        "findings": [f.to_dict() for f in findings],
        "threat_matrix": threat_matrix,
        "session_summary": session_summary,
        "compliance": compliance,
        "remediations": remediations,
        "threat_intel": threat_intel,
        "quantum_resilience": quantum,
        "observed": observed,
        "inferred": inferred,
        "packet_frames": generate_synthetic_frames(cipher=enc_algo.upper(), dh_group=dh_group, count=12),
    }

    validation_result = None
    if req.apply_downgrade or enc_algo in ("3des-cbc", "des-cbc", "3des", "des") or dh_group in (1, 2, 5) or pfs == "off":
        strong_baseline = {
            "session": f"sim_baseline_tunnel_aes256-gcm_dh20_pfs-on_{traffic_type}.pcap",
            "score": 98,
            "subscores": {"crypto_strength": 100, "key_management": 95, "forward_secrecy": 100, "metadata_exposure": 95, "authentication": 100},
            "observed": {"enc_algo": "aes256-gcm", "integrity": "none", "dh_group": 20, "ike_version": 2},
            "inferred": {"traffic_type": traffic_type, "pfs": "on", "mode": "tunnel", "anomaly": False},
            "findings": []
        }
        validation_result = compare_sessions(strong_baseline, simulated_session)

    return {
        "status": "success",
        "simulation_parameters": req.model_dump(),
        "assessment": simulated_session,
        "validation": validation_result,
    }


@app.get("/api/evaluation")
@app.get("/api/benchmarking")
def get_benchmarking() -> dict:
    return run_security_evaluation()


@app.post("/api/attack/downgrade")
def trigger_downgrade(
    initial_cipher: str = Form("AES-256-GCM"),
    initial_dh: int = Form(19),
    downgrade_to_cipher: str = Form("3DES-CBC"),
    downgrade_to_dh: int = Form(2)
) -> dict:
    return simulate_downgrade_attack(
        initial_cipher=initial_cipher,
        initial_dh=initial_dh,
        downgrade_to_cipher=downgrade_to_cipher,
        downgrade_to_dh=downgrade_to_dh
    )

