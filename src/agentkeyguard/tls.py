# -*- coding: utf-8 -*-
"""本地 CA、服务器证书与 iOS 根证书描述文件。

只做单向 HTTPS：服务端只证明"我是谁"，从不索要客户端证书。
mTLS 整体不做（REQ-303），因此没有客户端证书、没有 PKCS#12。
仅依赖 cryptography（已在 requirements）与 stdlib。
"""
from __future__ import annotations

import datetime
import ipaddress
import plistlib
import ssl
import uuid
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

_CA_DAYS = 3650
_LEAF_DAYS = 825
_TLS_MIN = ssl.TLSVersion.TLSv1_2


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def _key_usage(cert_sign: bool = False) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=True,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def cert_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def cert_der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def key_pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def generate_ca(cn: str = "AgentKeyGuard Local CA"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(_name(cn))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=_CA_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(_key_usage(cert_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue_server_cert(ca_key, ca_cert, ips, dns=None, cn="AgentKeyGuard"):
    key = ec.generate_private_key(ec.SECP256R1())
    now = _now()
    san = [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    san += [x509.DNSName(d) for d in (dns or [])]
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(cn))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=_LEAF_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(_key_usage(), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                       critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
            ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert


def save_ca(key, cert: x509.Certificate, tls_dir: Path) -> None:
    _write(tls_dir / "ca.crt", cert_pem(cert), 0o644)
    _write(tls_dir / "ca.key", key_pem(key), 0o600)


def load_ca(tls_dir: Path):
    cert = x509.load_pem_x509_certificate((tls_dir / "ca.crt").read_bytes())
    key = serialization.load_pem_private_key((tls_dir / "ca.key").read_bytes(), password=None)
    return key, cert


def save_server(key, cert: x509.Certificate, tls_dir: Path) -> None:
    _write(tls_dir / "server.crt", cert_pem(cert), 0o644)
    _write(tls_dir / "server.key", key_pem(key), 0o600)


def ensure_ca(ca_dir: Path):
    """持久 CA：存在就复用，不存在才生成一次。"""
    ca_dir.mkdir(parents=True, exist_ok=True)
    crt, key = ca_dir / "ca.crt", ca_dir / "ca.key"
    if crt.exists() and key.exists():
        return load_ca(ca_dir)
    ca_key, ca_cert = generate_ca()
    save_ca(ca_key, ca_cert, ca_dir)
    return ca_key, ca_cert


def migrate_ca(old_dir: Path, ca_dir: Path) -> bool:
    """把旧 DATA_DIR/tls/ca.* 迁移到持久 CA_DIR；已存在目标则不覆盖。"""
    old_crt, old_key = old_dir / "ca.crt", old_dir / "ca.key"
    new_crt, new_key = ca_dir / "ca.crt", ca_dir / "ca.key"
    if new_crt.exists() and new_key.exists():
        return False
    if not (old_crt.exists() and old_key.exists()):
        return False
    ca_dir.mkdir(parents=True, exist_ok=True)
    _write(new_crt, old_crt.read_bytes(), 0o644)
    _write(new_key, old_key.read_bytes(), 0o600)
    return True


def reissue_server_cert(ca_dir: Path, cert_dir: Path, ips, dns) -> x509.Certificate:
    """加/改 DNS SAN 后重签服务器证书；CA 复用，服务器证书写入 cert_dir。"""
    ca_key, ca_cert = load_ca(ca_dir)
    key, cert = issue_server_cert(ca_key, ca_cert, ips, dns)
    save_server(key, cert, cert_dir)
    return cert


def ca_status(ca_dir: Path, cert_file: Path, host: str, ca_url: str) -> dict:
    """证书诊断：CA 指纹、服务器证书 SAN、当前 Host。"""
    out = {"host": host, "ca_url": ca_url, "ca_fingerprint": "",
           "san": [], "error": ""}
    try:
        ca_cert = x509.load_pem_x509_certificate((ca_dir / "ca.crt").read_bytes())
        out["ca_fingerprint"] = fingerprint(ca_cert)
    except Exception as e:  # noqa: BLE001
        out["error"] = f"ca: {type(e).__name__}: {e}"
        return out
    try:
        cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        out["san"] = ([f"IP:{v}" for v in ext.value.get_values_for_type(x509.IPAddress)] +
                      [f"DNS:{v}" for v in ext.value.get_values_for_type(x509.DNSName)])
    except Exception as e:  # noqa: BLE001
        out["error"] = f"server: {type(e).__name__}: {e}"
    return out


def root_mobileconfig(ca_der: bytes) -> bytes:
    """iPhone 根证书描述文件：只含 CA，不含客户端身份。"""
    payload = [{
        "PayloadType": "com.apple.security.root",
        "PayloadVersion": 1,
        "PayloadIdentifier": "local.agentkeyguard.root",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadDisplayName": "AgentKeyGuard Root CA",
        "PayloadDescription": "AgentKeyGuard 本地根证书（仅用于 HTTPS/Face ID）",
        "PayloadContent": ca_der,
    }]
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "local.agentkeyguard.root.profile",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadDisplayName": "AgentKeyGuard Root CA",
        "PayloadRemovalDisallowed": False,
        "PayloadContent": payload,
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def tls_context(cert_file: Path, key_file: Path) -> ssl.SSLContext:
    """单向 TLS：只出示服务器证书，不向客户端索要证书。

    历史坑：这里曾经默认 ssl.CERT_OPTIONAL，导致握手时发出 CertificateRequest，
    Windows/Chrome 立刻弹出「选择用于身份验证的证书」，随便选一张就握手失败。
    mTLS 已明确不做（REQ-303），固定 CERT_NONE 后不再有这个弹窗。
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = _TLS_MIN
    ctx.load_cert_chain(str(cert_file), str(key_file))
    ctx.verify_mode = ssl.CERT_NONE
    return ctx
