#!/usr/bin/env python3
"""Valida los YAML del repo y las garantias de privacidad de la fortaleza.

Se ejecuta en CI (job "config") y a mano:

    python tools/validate_fortress_config.py

Falla con codigo 1 si:
  - algun YAML no parsea,
  - AdGuardHome.template.yaml pierde alguna garantia del diseno,
  - el torrc no incluye el puerto SOCKS/DNS esperado.

Solo ASCII en el codigo; los mensajes pueden ir en espanol sin tildes.
"""

from __future__ import annotations

import pathlib
import sys

try:
    import yaml
except ImportError:  # pragma: no cover
    print("ERROR: falta pyyaml (python -m pip install pyyaml)")
    sys.exit(1)

ROOT = pathlib.Path(__file__).resolve().parent.parent
AGH = ROOT / "config" / "AdGuardHome.template.yaml"
TORRC = ROOT / "config" / "torrc.template"
UNBOUND = ROOT / "config" / "unbound.conf.template"

errors: list[str] = []


def check(condition: bool, message: str) -> None:
    if not condition:
        errors.append(message)


def load_yaml(path: pathlib.Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        return yaml.safe_load(handle) or {}


def validate_all_yaml() -> None:
    patterns = ["**/*.yml", "**/*.yaml"]
    seen = set()
    for pattern in patterns:
        for path in ROOT.glob(pattern):
            if ".git" in path.parts or path in seen:
                continue
            seen.add(path)
            rel = path.relative_to(ROOT)
            try:
                load_yaml(path)
                print(f"  OK   yaml  {rel}")
            except Exception as exc:  # noqa: BLE001
                errors.append(f"YAML invalido en {rel}: {exc}")


def validate_fortress() -> None:
    if not AGH.exists():
        errors.append("Falta config/AdGuardHome.template.yaml")
        return

    cfg = load_yaml(AGH)
    dns = cfg.get("dns", {}) or {}

    check(
        int(cfg.get("schema_version", 0) or 0) >= 35,
        "falta schema_version: 35; sin el, AdGuard Home migra la plantilla "
        "y rechaza bootstrap_dns como lista anidada",
    )
    check(dns.get("enable_dnssec") is True, "dns.enable_dnssec debe ser true")
    check(
        dns.get("upstream_mode") in ("parallel", "fastest_addr"),
        "dns.upstream_mode debe ser parallel o fastest_addr",
    )

    upstreams = dns.get("upstream_dns") or []
    check(len(upstreams) >= 2, "dns.upstream_dns necesita al menos 2 resolutores")
    for up in upstreams:
        up_str = str(up)
        # Los corchetes son upstreams por dominio ("[/onion/]127.0.0.1:5350").
        if up_str.startswith("[/") or up_str.startswith("[/*"):
            continue
        # El perfil privacy usa el recursivo propio en loopback: no hay tercero
        # al que cifrar y el trafico no sale del equipo hasta la raiz DNS.
        is_loopback_recursive = up_str.startswith("127.0.0.1:5335") or up_str.startswith("[::1]:5335")
        check(
            up_str.startswith("https://")
            or up_str.startswith("tls://")
            or up_str.startswith("quic://")
            or up_str.startswith("h3://")
            or is_loopback_recursive,
            f"upstream sin cifrar: {up_str}",
        )

    # El tunel a Tor puede ir por http_proxy (cliente HTTP de DoH) o por
    # dns.proxy_config (proxy especifico de upstreams, versiones nuevas).
    http_proxy = str(cfg.get("http_proxy", ""))
    proxy = dns.get("proxy_config") or {}
    tor_by_http = "127.0.0.1:9050" in http_proxy and "socks5" in http_proxy
    tor_by_proxy_config = (
        proxy.get("enabled") is True and "127.0.0.1:9050" in str(proxy.get("url", ""))
    )
    check(
        tor_by_http or tor_by_proxy_config,
        "no hay tunel a Tor: configura http_proxy: socks5://127.0.0.1:9050 "
        "o dns.proxy_config con url socks5://127.0.0.1:9050",
    )
    check(
        http_proxy == "" or "socks5://127.0.0.1:9050" in http_proxy,
        f"http_proxy inesperado: {http_proxy!r}",
    )

    bootstrap = dns.get("bootstrap_dns") or []
    check(len(bootstrap) > 0, "dns.bootstrap_dns no puede estar vacio")

    raw_cfg = AGH.read_text(encoding="utf-8-sig")
    check(
        "# >>> FORTRESS-UPSTREAM >>>" in raw_cfg
        and "# <<< FORTRESS-UPSTREAM <<<" in raw_cfg,
        "faltan los marcadores FORTRESS-UPSTREAM que usa apply-dns-profile.ps1",
    )

    http = cfg.get("http", {}) or {}
    bind = http.get("address", "")
    check(
        bind.startswith("127.0.0.1") or bind.startswith("localhost"),
        f"http.address debe escuchar solo en loopback, ahora: {bind!r}",
    )

    querylog = cfg.get("querylog", {}) or {}
    check(
        querylog.get("enabled") is True,
        "querylog.enabled debe ser true (el centinela AI lo necesita)",
    )

    print("  OK   garantias de AdGuardHome.template.yaml")


def validate_torrc() -> None:
    if not TORRC.exists():
        errors.append("Falta config/torrc.template")
        return

    text = TORRC.read_text(encoding="utf-8-sig")
    lowered = text.lower()

    for directive, why in [
        ("socksport", "sin SocksPort no hay proxy para DoH"),
        ("dnsport", "sin DNSPort no se resuelven .onion"),
        ("isolatesocksauth", "sin aislamiento de circuitos las apps comparten circuito"),
        ("safelogging", "SafeLogging evita volcar dominios en el log de Tor"),
    ]:
        check(directive in lowered, f"torrc: falta {directive.upper()} ({why})")

    print("  OK   garantias de torrc.template")


def validate_unbound() -> None:
    if not UNBOUND.exists():
        errors.append("Falta config/unbound.conf.template")
        return
    text = UNBOUND.read_text(encoding="utf-8-sig")
    for needle, why in [
        ("interface: 127.0.0.1", "Unbound debe escuchar solo en loopback"),
        ("port: 5335", "el puerto del recursivo debe ser 5335"),
        ("access-control: 127.0.0.0/8 allow", "falta la ACL de loopback"),
        ("auto-trust-anchor-file", "sin ancla de confianza no hay DNSSEC"),
        ("qname-minimisation: yes", "falta qname minimisation"),
        ("hide-version: yes", "Unbound no debe revelar su version"),
    ]:
        check(needle in text, f"unbound.conf: falta '{needle}' ({why})")
    check("port: 53\n" not in text, "Unbound no debe ocupar el puerto 53: AdGuard es el unico resolutor local")
    print("  OK   garantias de unbound.conf.template")


def main() -> int:
    print("Validando YAML del repositorio...")
    validate_all_yaml()

    print("Validando garantias de la fortaleza...")
    validate_fortress()
    validate_torrc()
    validate_unbound()

    if errors:
        print("")
        print("FALLOS:")
        for item in errors:
            print(f"  - {item}")
        return 1

    print("")
    print("Todo correcto: YAML parseable y garantias de privacidad intactas.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
