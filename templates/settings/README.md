# templates/settings/

Qui stanno i template `<host>.json.j2` (uno per UAG dell'inventory): l'export JSON della UAG con i
segreti sostituiti da variabili vault (`{{ vault_opswat_password }}` ecc.) e con i fix per la 2609.

**Non serve crearli a mano**: `playbooks/02_upgrade.yml` li genera nel pre-check dall'export più recente
di quell'host (`files/backup/<data>/<host>/settings.json`, prodotto da `01_export.yml`) usando
`scripts/make_settings_template.py`. Un template già presente non viene sovrascritto (può contenere
modifiche a mano, es. `ntpServers` o metadati IdP aggiornati); per rigenerarlo:
`-e uag_regenerate_template=true`.

A mano, per controllarlo prima del lancio:

    scripts/make_settings_template.py files/backup/<data>/<host>/settings.json > templates/settings/<host>.json.j2
    scripts/inspect_export.py templates/settings/<host>.json.j2 --strict      # deve dare 0 BLOCK

Questi file NON contengono segreti in chiaro e possono stare nel repo.
