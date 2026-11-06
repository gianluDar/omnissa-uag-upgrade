#!/usr/bin/env bash
# =====================================================================
#  ovf_props.sh - Elenca reti, deployment option e proprieta' OVF
#  dichiarate dentro una OVA UAG. Da lanciare su OGNI nuova OVA prima
#  dell'upgrade, per confermare che i nomi usati in 02_upgrade.yml
#  (networks:, properties:, deployment_option:) siano ancora validi.
#
#  Uso: scripts/ovf_props.sh files/ova/euc-unified-access-gateway-XXXX.ova
# =====================================================================
set -euo pipefail
OVA="${1:?Indica il path della OVA}"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Una OVA e' un tar: estraggo solo il descrittore .ovf (compatibile GNU tar e bsdtar/macOS)
OVF_NAME=$(tar -tf "$OVA" | grep -m1 '\.ovf$')
tar -xf "$OVA" -C "$TMP" "$OVF_NAME"
OVF="$TMP/$OVF_NAME"

echo "== Descrittore: $(basename "$OVF")"
echo
echo "== Reti (usa questi nomi in networks:)"
grep -o '<Network ovf:name="[^"]*"' "$OVF" | sed 's/.*name="\([^"]*\)"/  \1/'
echo
echo "== Deployment option (usa uno di questi in deployment_option:)"
grep -o '<Configuration ovf:id="[^"]*"' "$OVF" | sed 's/.*id="\([^"]*\)"/  \1/'
echo
echo "== Proprieta' OVF (usa queste chiavi in properties:)"
# (awk invece di sed: il "t" con ";" non funziona sul sed BSD di macOS)
grep -o '<Property[^>]*ovf:key="[^"]*"[^>]*' "$OVF" \
  | awk '{
      k=""; t="";
      if (match($0, /ovf:key="[^"]*"/))  { k=substr($0, RSTART+9, RLENGTH-10) }
      if (match($0, /ovf:type="[^"]*"/)) { t=substr($0, RSTART+10, RLENGTH-11) }
      if (t != "") print "  " k "  (" t ")"; else print "  " k
    }' \
  | sort -u
