#!/usr/bin/env python3
"""
refresh_idp_metadata.py - Sostituisce il metadataXml dell'IdP dentro un template
settings (.json.j2) con un file XML scaricato fresco dall'IdP.
Serve SOLO se l'IdP ha ruotato il certificato di firma dopo l'ultimo export.

Uso:
  scripts/refresh_idp_metadata.py templates/settings/uag1.json.j2 files/idp/idp-metadata.xml [entityID]

Se entityID e' omesso e c'e' un solo IdP nel template, aggiorna quello.
Il file viene riscritto in place (fai prima git diff/commit).
"""
import re
import sys

def main():
    if len(sys.argv) < 3:
        print(__doc__, file=sys.stderr); sys.exit(2)
    tpl_path, xml_path = sys.argv[1], sys.argv[2]
    entity = sys.argv[3] if len(sys.argv) > 3 else None
    raw = open(tpl_path, encoding="utf-8").read()
    xml = open(xml_path, encoding="utf-8").read().strip()
    # Lavoro sul testo per non perdere i placeholder Jinja: il template non e' JSON puro.
    # Pattern: "metadataXml": "<...escaped...>"  (template vecchio stile)
    #      oppure "metadata": "<base64>"       (export reale 2503+)
    pat = re.compile(r'("(metadataXml|metadata)"\s*:\s*")((?:[^"\\]|\\.)*)(")')
    matches = [m for m in pat.finditer(raw) if m.group(2) == "metadataXml" or "entityID" in raw[max(0, m.start()-1500):m.end()+1500]]
    if not matches:
        print("Nessun metadata/metadataXml trovato nel template", file=sys.stderr); sys.exit(1)
    if entity:
        # restringo al blocco che contiene l'entityID richiesto
        matches = [m for m in matches if entity in raw[max(0, m.start()-2000):m.end()+2000]]
        if not matches:
            print(f"Nessun IdP con entityID contenente '{entity}'", file=sys.stderr); sys.exit(1)
    if len(matches) > 1 and not entity:
        print("Piu' IdP nel template: specifica entityID", file=sys.stderr); sys.exit(1)
    m = matches[0]
    import json, base64
    if m.group(2) == "metadata":
        escaped = base64.b64encode(xml.encode("utf-8")).decode("ascii")
    else:
        escaped = json.dumps(xml)[1:-1]  # escape JSON senza le virgolette esterne
    new = raw[:m.start(3)] + escaped + raw[m.end(3):]
    open(tpl_path, "w", encoding="utf-8").write(new)
    print(f"Aggiornato {m.group(2)} in {tpl_path} ({len(xml)} byte)")

if __name__ == "__main__":
    main()
