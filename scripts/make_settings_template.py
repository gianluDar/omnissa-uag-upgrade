#!/usr/bin/env python3
"""
make_settings_template.py - Trasforma l'export JSON di una UAG nel
template Jinja usato dal playbook, sostituendo i segreti con variabili vault.

Uso:
  scripts/make_settings_template.py files/backup/<data>/uag1/settings.json \
      > templates/settings/uag1.json.j2

Cosa fa:
  - cerca ricorsivamente le chiavi "sensibili" (password, sharedSecret, ...)
  - le sostituisce con il placeholder Jinja corrispondente
  - stampa a video il JSON risultante (indentato)

Dopo averlo lanciato esegui scripts/inspect_export.py sul template:
ti dice cosa e' coperto dal JSON, cosa arriva dal vault e cosa resta manuale.
"""
import json
import sys

# chiave JSON -> variabile vault
SECRET_MAP = {
    # OPSWAT (devicePolicySettingsList -> name=OPSWAT)
    "password": "{{ vault_opswat_password }}",
    "userName": None,   # gestito sotto: solo dentro OPSWAT
    # RADIUS
    "sharedSecret": "{{ vault_radius_shared_secret | default('') }}",
    "sharedSecret_2": "{{ vault_radius_shared_secret | default('') }}",
}

def walk(node, ctx=None):
    if isinstance(node, dict):
        name = node.get("name", "")
        is_opswat = (name == "OPSWAT") or ctx == "OPSWAT"
        for k, v in list(node.items()):
            if k == "password" and is_opswat:
                node[k] = SECRET_MAP["password"]
            elif k == "userName" and is_opswat:
                node[k] = "{{ vault_opswat_username }}"
            elif k in ("sharedSecret", "sharedSecret_2"):
                node[k] = SECRET_MAP[k]
            elif k == "privateKeyPem" and ("spName" in node or "serviceProviderName" in node):
                # certificato SP SAML custom: la chiave privata non viene mai esportata
                node[k] = "{{ vault_saml_sp_key | default('') }}"
            else:
                walk(v, "OPSWAT" if is_opswat else ctx)
    elif isinstance(node, list):
        for item in node:
            walk(item, ctx)

def fix_for_2609(data):
    """Adattamenti noti per l'import su UAG 2609 (verificati sui log admin.log del 2026-11-05)."""
    # a) generalSettings = rete/deploy (IP, DNS...): e' read-only, la PUT risponde
    #    "General Settings could not be modified". Inutile e rumoroso: via.
    # b) OPSWAT: l'export 25.03 scrive gli intervalli (300) con timeunit MINUTES, ma la 2609
    #    li valida come minuti (initial delay max 60 min) e rifiuta TUTTO il provider OPSWAT
    #    -> a cascata fallisce anche l'edge service Horizon ("device policy provider not configured").
    #    Con SECONDS i valori 300 (= 5 min) sono validi (interval 300-86400, delay 5-3600, fast 5-86400).
    for dp in (data.get("devicePolicySettingsList") or {}).get("devicePolicySettingsList", []):
        if dp.get("complianceCheckTimeunit") == "MINUTES":
            vals = [dp.get(k, 0) for k in ("complianceCheckInterval", "complianceCheckInitialDelay", "complianceCheckFastInterval")]
            if any(v > 60 for v in vals):
                dp["complianceCheckTimeunit"] = "SECONDS"
                print(f"# {dp.get('name')}: complianceCheckTimeunit MINUTES -> SECONDS (valori {vals})", file=sys.stderr)
    # c) Blast host header allow list (2609: il BSG valida l'Host header; sulla 25.03 no).
    #    Verificato il 2026-11-05: senza "<host esterno>:<porta Blast>" e "localhost:8443"
    #    (hop interno esmanager -> BSG) il client fallisce con VDPCONNECT_REJECTED e in
    #    bsg.log compare 'Unmatched Host header "localhost:8443"'. Il campo vuoto NON basta:
    #    la lista automatica aggiunge solo :443.
    from urllib.parse import urlparse
    uag_name = (data.get("systemSettings") or {}).get("uagName", "").lower()
    ip0 = (data.get("generalSettings") or {}).get("ip0") or ""
    for es in (data.get("edgeServiceSettingsList") or {}).get("edgeServiceSettingsList", []):
        if es.get("identifier") != "VIEW":
            continue
        entries = []
        for key in ("blastExternalUrl", "tunnelExternalUrl"):
            u = urlparse(es.get(key) or "")
            if u.hostname:
                entries += [f"{u.hostname}:{u.port}" if u.port else u.hostname, u.hostname, f"{u.hostname}:443"]
        if uag_name:
            entries += [uag_name, f"{uag_name}:443"]
        if ip0:
            entries += [ip0, f"{ip0}:443"]
        entries.append("localhost:8443")
        existing = [x.strip() for x in (es.get("blastAllowedHostHeaderValues") or "").split(",") if x.strip()]
        merged = list(dict.fromkeys(entries + existing))
        es["blastAllowedHostHeaderValues"] = ",".join(merged)
        print(f"# VIEW: blastAllowedHostHeaderValues = {es['blastAllowedHostHeaderValues']}", file=sys.stderr)
    # d) header di sicurezza deprecato: la 2609 lo ignora con un WARN
    for es in (data.get("edgeServiceSettingsList") or {}).get("edgeServiceSettingsList", []):
        (es.get("securityHeaders") or {}).pop("X-XSS-Protection", None)
    data.pop("generalSettings", None)   # letto sopra per ip0, poi via (read-only sulla UAG)

def main():
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1]) as f:
        data = json.load(f)
    walk(data)
    fix_for_2609(data)
    print(json.dumps(data, indent=2, ensure_ascii=False))

if __name__ == "__main__":
    main()
