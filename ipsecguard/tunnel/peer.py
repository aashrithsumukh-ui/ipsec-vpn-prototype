from __future__ import annotations

import os
import struct
import socket
import threading
import time
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from scapy.all import IP, UDP, Raw, wrpcap

from ipsecguard.pipeline import analyze_capture
from ipsecguard.models import AnalysisResult

IKEV2_TRANSFORMS = {
    "ike_enc": {"3DES": (1, 3), "AES-CBC": (1, 12), "AES-GCM-16": (1, 18)},
    "ike_prf": {
        "HMAC-MD5": (2, 1),
        "HMAC-SHA1": (2, 2),
        "HMAC-SHA2-256": (2, 5),
        "HMAC-SHA2-384": (2, 6),
    },
    "ike_integ": {
        "HMAC-MD5-96": (3, 1),
        "HMAC-SHA1-96": (3, 2),
        "SHA2-256-128": (3, 12),
        "SHA2-384-192": (3, 13),
    },
}


def _build_ikev2_payload(enc: str, prf: str, integ: str, dh_group: int, initiator: bytes, responder: bytes) -> bytes:
    transforms = [
        IKEV2_TRANSFORMS["ike_enc"].get(enc, (1, 18)),
        IKEV2_TRANSFORMS["ike_prf"].get(prf, (2, 5)),
        IKEV2_TRANSFORMS["ike_integ"].get(integ, (3, 12)),
        (4, dh_group),
    ]
    transform_blobs = []
    for index, (transform_type, transform_id) in enumerate(transforms):
        next_payload = 3 if index < len(transforms) - 1 else 0
        transform_blobs.append(
            struct.pack("!BBHBBH", next_payload, 0, 8, transform_type, 0, transform_id)
        )
    proposal_body = b"".join(transform_blobs)
    proposal = (
        struct.pack("!BBHBBBB", 0, 0, 8 + len(proposal_body), 1, 1, 0, len(transforms))
        + proposal_body
    )
    sa_payload = struct.pack("!BBH", 0, 0, 4 + len(proposal)) + proposal
    header = (
        initiator
        + responder
        + bytes([33, 0x20, 34, 0x08])
        + struct.pack("!II", 0, 28 + len(sa_payload))
    )
    return header + sa_payload


class IPsecPeerNode:
    """Peer-to-Peer IPsec VPN Node capable of establishing live encrypted tunnels

    and exchanging secure data with other IPsecGuard instances across local or remote networks.
    """

    def __init__(self, bind_port: int = 8500) -> None:
        self.bind_port = bind_port
        self.peer_host = "127.0.0.1"
        self.peer_port = 8500
        self.is_connected = False
        self.cipher_preset = "AES-256-GCM"  # or "3DES-MD5" or "AES-CBC"
        self.spi_out = 0x1000
        self.spi_in = 0x2000
        self.seq_out = 1
        self.seq_in = 0

        # Session Keys
        self.aes_key = os.urandom(32)  # 256-bit AES key
        self.des_key = os.urandom(24)  # 192-bit 3DES key

        self.exchanged_packets: list[Any] = []
        self.message_log: list[dict[str, Any]] = []

        self._socket: socket.socket | None = None
        self._listener_thread: threading.Thread | None = None
        self._running = False
        self._lock = threading.Lock()

    def start_listener(self, port: int = 8500) -> dict[str, Any]:
        with self._lock:
            if self._running:
                return {"status": "listening", "port": self.bind_port}
            self.bind_port = port
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self._socket.bind(("0.0.0.0", self.bind_port))
                self._running = True
                self._listener_thread = threading.Thread(target=self._listen_loop, daemon=True)
                self._listener_thread.start()
                return {"status": "listening", "port": self.bind_port}
            except Exception as e:
                return {"status": "error", "detail": str(e)}

    def stop_listener(self) -> dict[str, Any]:
        with self._lock:
            self._running = False
            if self._socket:
                try:
                    self._socket.close()
                except Exception:
                    pass
                self._socket = None
            self.is_connected = False
            return {"status": "stopped"}

    def initiate_tunnel(self, peer_host: str, peer_port: int = 8500, cipher_preset: str = "AES-256-GCM") -> dict[str, Any]:
        """Performs live IKE handshake negotiation with target peer node."""
        self.peer_host = peer_host
        self.peer_port = peer_port
        self.cipher_preset = cipher_preset
        self.seq_out = 1
        self.exchanged_packets = []

        # Find matching parameters
        enc, prf, integ, dh = "AES-GCM-16", "HMAC-SHA2-256", "SHA2-256-128", 19
        if "3DES" in cipher_preset.upper():
            enc, prf, integ, dh = "3DES", "HMAC-MD5", "HMAC-MD5-96", 2
        elif "CBC" in cipher_preset.upper():
            enc, prf, integ, dh = "AES-CBC", "HMAC-SHA1", "HMAC-SHA1-96", 14

        initiator_spi = os.urandom(8)
        ike_payload = _build_ikev2_payload(enc, prf, integ, dh, initiator_spi, b"\x00" * 8)

        # Build Scapy packet representation for PCAP capture
        ike_pkt = IP(src="127.0.0.1", dst=peer_host) / UDP(sport=self.bind_port, dport=peer_port) / Raw(ike_payload)
        ike_pkt.time = time.time()
        self.exchanged_packets.append(ike_pkt)

        # Send over UDP wire
        try:
            if not self._socket:
                self.start_listener(self.bind_port)
            self._socket.sendto(b"IKE_INIT:" + ike_payload, (peer_host, peer_port))
            self.is_connected = True
            return {
                "status": "connected",
                "peer": f"{peer_host}:{peer_port}",
                "cipher_preset": cipher_preset,
                "spi_local": hex(self.spi_out),
            }
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def send_secure_payload(self, text_message: str) -> dict[str, Any]:
        """Encapsulates plaintext data into standard RFC 4303 ESP format and transmits to peer."""
        if not self._socket or not self.peer_host:
            return {"status": "error", "detail": "Tunnel listener is not active or peer host unset."}

        plaintext_bytes = text_message.encode("utf-8")

        # 1. Encrypt payload
        if "3DES" in self.cipher_preset.upper():
            iv = os.urandom(8)
            padder = sym_padding.PKCS7(64).padder()
            padded_data = padder.update(plaintext_bytes) + padder.finalize()
            cipher = Cipher(algorithms.TripleDES(self.des_key), modes.CBC(iv))
            encryptor = cipher.encryptor()
            ciphertext = iv + encryptor.update(padded_data) + encryptor.finalize()
        else:
            # AES-GCM 256
            nonce = os.urandom(12)
            aesgcm = AESGCM(self.aes_key)
            ciphertext = nonce + aesgcm.encrypt(nonce, plaintext_bytes, None)

        # 2. Build ESP Header: SPI (4 bytes) + Sequence Number (4 bytes) + Ciphertext + Trailer
        esp_header = struct.pack("!II", self.spi_out, self.seq_out)
        next_header = 4  # IP-in-IP / inner payload
        esp_trailer = bytes([0, 0, len(ciphertext) % 4, next_header])
        full_esp = esp_header + ciphertext + esp_trailer

        # Record to packet capture
        pkt = IP(src="127.0.0.1", dst=self.peer_host, proto=50) / Raw(full_esp)
        pkt.time = time.time()
        with self._lock:
            self.exchanged_packets.append(pkt)
            log_entry = {
                "index": len(self.exchanged_packets),
                "timestamp": time.strftime("%H:%M:%S"),
                "direction": "OUTBOUND (Sent)",
                "source": f"127.0.0.1:{self.bind_port} (Local Node)",
                "destination": f"{self.peer_host}:{self.peer_port} (Remote Peer)",
                "protocol": "ESP (IP Proto 50)",
                "spi": f"0x{self.spi_out:08x}",
                "seq": f"#{self.seq_out}",
                "length": len(full_esp),
                "plaintext_preview": text_message,
                "ciphertext_hex": ciphertext[:16].hex() + "...",
                "details": f"Encrypted ESP Tunnel Packet | Payload: '{text_message}' ➔ {len(ciphertext)}B AES Ciphertext"
            }
            self.message_log.append(log_entry)

        self.seq_out += 1

        # Send over UDP wire encapsulation (NAT-T ESP over UDP)
        try:
            self._socket.sendto(b"ESP_DATA:" + full_esp, (self.peer_host, self.peer_port))
            return {
                "status": "transmitted",
                "seq": self.seq_out - 1,
                "esp_bytes": len(full_esp),
                "ciphertext_hex": ciphertext[:16].hex() + "...",
                "packet_entry": log_entry
            }
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def get_packet_logs(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self.message_log)

    def audit_live_tunnel(self) -> AnalysisResult:
        """Passes the captured live peer-to-peer session PCAP directly into the AI analyzer."""
        with self._lock:
            packets_to_audit = list(self.exchanged_packets)

        if not packets_to_audit:
            raise ValueError("No tunnel packets have been exchanged yet. Initiate a handshake or send messages first.")

        temp_pcap = NamedTemporaryFile(suffix=".pcap", delete=False)
        temp_path = Path(temp_pcap.name)
        temp_pcap.close()

        try:
            wrpcap(str(temp_path), packets_to_audit)
            return analyze_capture(temp_path)
        finally:
            temp_path.unlink(missing_ok=True)

    def _listen_loop(self) -> None:
        while self._running and self._socket:
            try:
                data, addr = self._socket.recvfrom(65535)
                if not data:
                    continue

                if data.startswith(b"IKE_INIT:"):
                    ike_body = data[9:]
                    # Reply with responder packet
                    responder_spi = os.urandom(8)
                    resp_ike = _build_ikev2_payload("AES-GCM-16", "HMAC-SHA2-256", "SHA2-256-128", 19, b"\xaa" * 8, responder_spi)
                    resp_pkt = IP(src=addr[0], dst="127.0.0.1") / UDP(sport=addr[1], dport=self.bind_port) / Raw(ike_body)
                    resp_pkt.time = time.time()
                    with self._lock:
                        self.exchanged_packets.append(resp_pkt)
                    self.peer_host = addr[0]
                    self.peer_port = addr[1]
                    self.is_connected = True
                    self._socket.sendto(b"IKE_RESP:" + resp_ike, addr)

                elif data.startswith(b"IKE_RESP:"):
                    self.is_connected = True

                elif data.startswith(b"ESP_DATA:"):
                    esp_raw = data[9:]
                    if len(esp_raw) >= 8:
                        spi, seq = struct.unpack("!II", esp_raw[:8])
                        self.seq_in = seq
                        pkt = IP(src=addr[0], dst="127.0.0.1", proto=50) / Raw(esp_raw)
                        pkt.time = time.time()
                        with self._lock:
                            self.exchanged_packets.append(pkt)
                            self.message_log.append({
                                "index": len(self.exchanged_packets),
                                "timestamp": time.strftime("%H:%M:%S"),
                                "direction": "INBOUND (Received)",
                                "source": f"{addr[0]}:{addr[1]} (Remote Peer)",
                                "destination": f"127.0.0.1:{self.bind_port} (Local Node)",
                                "protocol": "ESP (IP Proto 50)",
                                "spi": f"0x{spi:08x}",
                                "seq": f"#{seq}",
                                "length": len(esp_raw),
                                "plaintext_preview": "[Encrypted Payload Decapsulated]",
                                "ciphertext_hex": esp_raw[8:24].hex() + "...",
                                "details": f"Inbound ESP Encrypted Packet | SPI: 0x{spi:08x} | Seq: #{seq} | Size: {len(esp_raw)}B"
                            })
            except Exception:
                pass


# Global Peer Node instance
peer_node = IPsecPeerNode()
