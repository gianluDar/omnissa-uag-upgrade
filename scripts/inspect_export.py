#!/usr/bin/env python3
"""
inspect_export.py - Analizza l'export JSON di una UAG (o il template .j2 derivato)
e dice cosa c'e', cosa manca e cosa va completato prima dell'upgrade.

Uso:
  scripts/inspect_export.py files/backup/<data>/uag1/settings.json
  scripts/inspect_export.py templates/settings/uag1.json.j2          # accetta anche il template
  scripts/inspect_export.py <file> --strict                          # exit 1 se ci sono blocchi

Controlla:
  - edge service Horizon: proxy URL, thumbprint (sha1 vs sha256), auth method, host header allow list
  - SAML: metadati IdP inline (metadataXml), certificato di firma presente, scadenza; SP custom cert
  - OPSWAT: provider presente, hostName, credenziali (password -> vault), custom executable (URL vs hosted)
  - RADIUS: shared secret -> vault
  - keytab: mai esportati (rilevante solo per identity bridging Kerberos)

Legenda output:
  [OK]      presente e completo
  [VAULT]   manca nel JSON per design: va riempito nel template con una variabile vault
            (sul template un VAULT ancora aperto diventa BLOCK)
  [MANUAL]  non puo' essere portato via JSON/API: azione manuale dopo il deploy
  [WARN]    da controllare
  [BLOCK]   va risolto prima di lanciare 02_upgrade.yml
"""
import base64
import json
import re
import sys
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

try:
    from cryptography import x509  # opzionale, per la scadenza del cert IdP
    HAVE_CRYPTO = True
except Exception:
    HAVE_CRYPTO = False

PLACEHOLDER = "__VAULT__"
findings = []  # (level, msg)


def add(level, msg):
    findings.append((level, msg))


IS_TEMPLATE = False


def load(path):
    global IS_TEMPLATE
    raw = open(path, encoding="utf-8").read()
    # Se e' un template Jinja, sostituisco {{ ... }} con un placeholder per poter parsare
    IS_TEMPLATE = bool(re.search(r"\{\{[^}]*\}\}", raw)) or path.endswith(".j2")
    raw = re.sub(r"\{\{[^}]*\}\}", PLACEHOLDER, raw)
    return json.loads(raw)


def walk(node, pred, path="$"):
    """Yield (path, node) per ogni dict che soddisfa pred."""
    if isinstance(node, dict):
        if pred(node):
            yield path, node
        for k, v in node.items():
            yield from walk(v, pred, f"{path}.{k}")
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from walk(v, pred, f"{path}[{i}]")


def is_secret_filled(v):
    return v == PLACEHOLDER or (isinstance(v, str) and v.strip() != "")


# --------------------------------------------------------------------- Horizon
def check_horizon(data):
    views = [n for _, n in walk(data, lambda d: d.get("identifier") == "VIEW")]
    if not views:
        add("BLOCK", "Nessun edge service Horizon (identifier=VIEW) nel JSON")
        return
    v = views[0]
    add("OK", f"Horizon edge: proxyDestinationUrl={v.get('proxyDestinationUrl')}")
    tp = v.get("proxyDestinationUrlThumbprints", "") or ""
    if not tp:
        add("WARN", "proxyDestinationUrlThumbprints vuoto: la UAG richiedera' un cert CS valido (catena completa, 2609)")
    elif "sha256" not in tp.lower():
        add("BLOCK", f"Thumbprint CS non in sha256: '{tp[:40]}...' -> rigeneralo in sha256")
    else:
        add("OK", "Thumbprint Connection Server in sha256")
    add("OK", f"authMethods={v.get('authMethods')}  samlSP={v.get('samlSP')}  idpEntityID={v.get('idpEntityID')}")
    # 2609: il BSG valida l'Host header del client contro blastAllowedHostHeaderValues.
    # Servono "<host>:<porta>" di blastExternalUrl e "localhost:8443" (hop interno
    # esmanager -> BSG), altrimenti VDPCONNECT_REJECTED (verificato 2026-11-05).
    from urllib.parse import urlparse
    hh = [x.strip() for x in (v.get("blastAllowedHostHeaderValues") or "").split(",") if x.strip()]
    need = ["localhost:8443"]
    u = urlparse(v.get("blastExternalUrl") or "")
    if u.hostname:
        need.insert(0, f"{u.hostname}:{u.port or 443}")
    missing = [n for n in need if n not in hh]
    if missing:
        add("BLOCK", f"blastAllowedHostHeaderValues: mancano {missing} -> senza, il client Blast fallisce con VDPCONNECT_REJECTED sulla 2609 (make_settings_template.py li aggiunge da solo; il campo vuoto NON basta)")
    else:
        add("OK", f"Blast host header allow list: {','.join(hh)}")
    dp = v.get("devicePolicyServiceProvider")
    if dp:
        add("OK", f"Endpoint compliance provider sull'edge Horizon: {dp}")
    ce = v.get("customExecutableList") or []
    if ce:
        add("OK", f"Custom executables referenziati dall'edge Horizon: {ce}")
    return v


# ------------------------------------------------------------------------ SAML
def check_saml(data, view):
    # L'export reale (2503+) usa "metadata" = XML in base64; versioni vecchie/template usano "metadataXml"
    idps = [n for _, n in walk(data, lambda d: "metadataXml" in d or ("metadata" in d and "entityID" in d))]
    uses_saml = bool(view) and "saml" in (view.get("authMethods") or "").lower()
    if not idps:
        if uses_saml:
            add("BLOCK", "authMethods usa SAML ma nel JSON non c'e' nessun metadata/metadataXml dell'IdP")
        else:
            add("OK", "Nessun IdP SAML configurato")
        return
    for idp in idps:
        xml = idp.get("metadataXml") or ""
        ent = idp.get("entityID") or idp.get("entityId") or "?"
        if not xml and idp.get("metadata"):
            try:
                import base64
                xml = base64.b64decode(idp["metadata"]).decode("utf-8")
            except Exception as e:
                add("BLOCK", f"IdP {ent}: campo 'metadata' non e' base64 valido ({e})")
                continue
        if not xml.strip():
            add("BLOCK", f"IdP {ent}: metadataXml vuoto")
            continue
        add("OK", f"IdP {ent}: metadati inline nel JSON ({len(xml)} byte), encryptionCertificateType={idp.get('encryptionCertificateType')}")
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as e:
            add("BLOCK", f"IdP {ent}: metadataXml non e' XML valido ({e})")
            continue
        ns = {"md": "urn:oasis:names:tc:SAML:2.0:metadata", "ds": "http://www.w3.org/2000/09/xmldsig#"}
        signing = root.findall(".//md:KeyDescriptor", ns)
        certs = []
        for kd in signing:
            use = kd.get("use", "signing+encryption")
            for c in kd.findall(".//ds:X509Certificate", ns):
                certs.append((use, (c.text or "").strip()))
        if not certs:
            add("BLOCK", f"IdP {ent}: nessun X509Certificate nei metadati (la 2609 richiede il cert leaf di firma)")
            continue
        for use, b64 in certs:
            exp = ""
            if HAVE_CRYPTO:
                try:
                    cert = x509.load_der_x509_certificate(base64.b64decode(b64))
                    nva = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") else cert.not_valid_after.replace(tzinfo=timezone.utc)
                    days = (nva - datetime.now(timezone.utc)).days
                    exp = f", scade {nva:%Y-%m-%d} ({days} gg)"
                    if days < 0:
                        add("BLOCK", f"IdP {ent}: certificato '{use}' SCADUTO -> riscarica i metadati freschi (scripts/refresh_idp_metadata.py)")
                    elif days < 60:
                        add("WARN", f"IdP {ent}: certificato '{use}' scade tra {days} giorni")
                except Exception:
                    pass
            add("OK", f"IdP {ent}: cert '{use}' presente{exp}. Confronta con l'IdP live se hai ruotato le chiavi")

    # SP custom cert?
    sps = [n for _, n in walk(data, lambda d: "spName" in d or "serviceProviderName" in d)]
    for sp in sps:
        name = sp.get("spName") or sp.get("serviceProviderName")
        has_cert = bool(sp.get("certChainPem"))
        key = sp.get("privateKeyPem")
        if has_cert and not is_secret_filled(key):
            add("VAULT", f"SAML SP '{name}': certificato custom presente ma chiave privata assente -> vault_saml_sp_key")
        elif has_cert:
            add("OK", f"SAML SP '{name}': cert custom + chiave (placeholder) presenti")
        else:
            add("WARN", f"SAML SP '{name}': nessun cert custom -> la UAG ne genera uno self-signed al deploy; se l'IdP valida la firma SP, riregistra i metadati SP (README sez. 11)")


# ---------------------------------------------------------------------- OPSWAT
def check_opswat(data):
    ops = [n for _, n in walk(data, lambda d: d.get("name") == "OPSWAT" and ("hostName" in d or "userName" in d or "allowedStatuses" in d))]
    if not ops:
        add("OK", "Nessun provider OPSWAT configurato")
        return
    o = ops[0]
    add("OK", f"OPSWAT: hostName={o.get('hostName')}  allowedStatuses={o.get('allowedStatuses')}")
    if o.get("complianceCheckTimeunit") == "MINUTES" and any((o.get(k) or 0) > 60 for k in ("complianceCheckInterval", "complianceCheckInitialDelay", "complianceCheckFastInterval")):
        add("BLOCK", f"OPSWAT: intervalli {o.get('complianceCheckInterval')}/{o.get('complianceCheckInitialDelay')}/{o.get('complianceCheckFastInterval')} con timeunit MINUTES: la 2609 li rifiuta (initial delay max 60 min) e salta TUTTO l'import OPSWAT+Horizon -> metti complianceCheckTimeunit=SECONDS (make_settings_template.py lo fa da solo)")
    if not is_secret_filled(o.get("userName")):
        add("VAULT", "OPSWAT userName vuoto -> vault_opswat_username")
    if not is_secret_filled(o.get("password")):
        add("VAULT", "OPSWAT password assente (mai esportata) -> vault_opswat_password")
    elif o.get("password") == PLACEHOLDER:
        add("OK", "OPSWAT password: placeholder vault presente")

    # custom executable / agent on-demand
    hosted = [n for _, n in walk(data, lambda d: "sha256Sum" in d or "sha256sum" in d or "isObtainedfromURL" in d)]
    for h in hosted:
        name = h.get("name")
        if h.get("isObtainedfromURL"):
            add("OK", f"Custom executable '{name}': ottenuto da URL, nessun upload necessario")
        else:
            sha = h.get("sha256Sum") or h.get("sha256sum") or "?"
            add("MANUAL", f"Custom executable '{name}' ({h.get('fileType') or h.get('path', '?').rsplit('/', 1)[-1]}): binario hostato sulla UAG, NON e' nel JSON -> ricaricalo da Admin UI dopo il deploy (sha256 attesa {sha[:16]}...)")


# ---------------------------------------------------------------------- RADIUS
def check_radius(data):
    rad = [n for _, n in walk(data, lambda d: "sharedSecret" in d)]
    for r in rad:
        if r.get("enabled") is False:
            continue
        if not is_secret_filled(r.get("sharedSecret")):
            add("VAULT", f"RADIUS {r.get('hostName')}: sharedSecret assente -> vault_radius_shared_secret")
        else:
            add("OK", f"RADIUS {r.get('hostName')}: sharedSecret placeholder presente")


# ---------------------------------------------------------------------- keytab
def check_general(data):
    if "generalSettings" in data:
        add("WARN", "generalSettings (rete/deploy) presente: la PUT lo rifiuta con 'General Settings could not be modified' (innocuo). make_settings_template.py lo toglie")

def check_keytab(data):
    kt = [n for _, n in walk(data, lambda d: "keyTabFilePath" in d or "principalName" in d)]
    kt += [v for _, n in walk(data, lambda d: "kerberosKeyTabSettings" in d) for v in (n.get("kerberosKeyTabSettings") or [])]
    if kt:
        add("MANUAL", "Configurazione keytab presente: i file keytab non vengono MAI esportati -> ricarica da Admin UI (solo identity bridging Kerberos)")


# ------------------------------------------------------------------------ main
def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    strict = "--strict" in sys.argv
    if len(args) != 1:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    data = load(args[0])
    view = check_horizon(data)
    check_saml(data, view)
    check_opswat(data)
    check_radius(data)
    check_keytab(data)
    check_general(data)
    add("MANUAL", "Certificato TLS Internet/Admin: mai nel JSON -> gestito dal playbook via files/certs/*.pem (OK se presenti)")

    # Su un TEMPLATE un segreto ancora mancante e' un errore: il playbook lo manderebbe vuoto
    if IS_TEMPLATE:
        for i, (level, msg) in enumerate(findings):
            if level == "VAULT":
                findings[i] = ("BLOCK", msg + "  (manca il placeholder nel template)")

    order = {"BLOCK": 0, "VAULT": 1, "MANUAL": 2, "WARN": 3, "OK": 4}
    width = max(len(l) for l, _ in findings)
    for level, msg in sorted(findings, key=lambda f: order[f[0]]):
        print(f"[{level:<{width}}] {msg}")
    blocks = [m for l, m in findings if l == "BLOCK"]
    print()
    print(f"Riepilogo: {len(blocks)} BLOCK, "
          f"{sum(1 for l,_ in findings if l=='VAULT')} VAULT, "
          f"{sum(1 for l,_ in findings if l=='MANUAL')} MANUAL, "
          f"{sum(1 for l,_ in findings if l=='WARN')} WARN")
    if strict and blocks:
        sys.exit(1)


if __name__ == "__main__":
    main()
