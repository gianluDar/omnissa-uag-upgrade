# uag-automation

Ansible automation for upgrading **Omnissa Unified Access Gateway** (UAG) appliances used
with Horizon 8: export the running configuration, deploy the new OVA on vSphere, re-apply
certificates and settings through the UAG admin REST API, verify. Written for the
25.03 → 2609 upgrade; for later releases you change the OVA and a couple of variables.

> UAG is not upgraded in place: a new appliance is deployed and the configuration is
> re-applied. These playbooks make the second step automatic and the first a single command,
> **one UAG at a time**, with the old VM kept for rollback.

Comments inside playbooks and scripts are in Italian.

## Disclaimer

This is an independent, community project. It is **not** an official Omnissa product, it is not
affiliated with, endorsed or supported by Omnissa, VMware or Broadcom, and it is not covered by any
vendor support contract. "Omnissa", "Unified Access Gateway", "Horizon", "VMware" and "vSphere" are
trademarks of their respective owners and are used here only to identify the products the playbooks
work with. The playbooks drive the publicly documented UAG admin REST API and vSphere OVF deployment;
behaviour described in this README was observed on specific releases (UAG 25.03 → 2609, Horizon 2503.1)
and may differ on other versions.

The software is provided "as is", without warranty of any kind (see `LICENSE`). It powers off, renames
and replaces virtual machines and rewrites the full configuration of network appliances: **test it in a
non-production environment first**, read the playbooks before running them, keep the `_OLD_` VMs until
you are sure, and always run one appliance at a time behind a load balancer. You are responsible for
what it does in your environment.

## What it does

| Playbook | Purpose | Changes anything? |
|---|---|---|
| `01_export.yml` | Backup of settings (JSON + INI), certificate details and log archive from each UAG | No |
| `02_upgrade.yml` | Pre-check → deploy new OVA as `<name>_NEW` (powered off) → quiesce → power off and rename old VM to `<name>_OLD_<date>` → rename/power on the new one → TLS certificates (Internet + Admin) → full settings (IdP metadata included) → verify | **Yes** |
| `03_verify.yml` | Health check: edge service, quiesce state, certificates | No |
| `04_cert_renew.yml` | Upload a renewed certificate on the Internet **and** Admin interface | Yes (cert only) |

Everything runs from a control node (macOS / Linux / WSL) and talks to vCenter (443), the ESXi
host chosen for the OVA upload (443) and the admin API of each UAG (9443).

Design choices worth knowing:

- The new VM is deployed **before** touching the running appliance, so a deploy error
  (wrong port group, datastore, OVF property, upload failure) has no service impact.
- vCPU/RAM of the new VM are inherited from the old one (override with `uag_vm_cpus` / `uag_vm_memory_mb`).
- The settings template is generated automatically from the latest export, with the fixes the
  2609 import needs (see below). Secrets never live in the template: they come from Ansible Vault.
- The settings `PUT` returns 200 even when a section is rejected: the playbook parses the
  response for errors and then checks that the Horizon edge service really exists.
- One environment = one inventory group with its own vCenter, networks, vault and certificates.

## Layout

```
inventory/
  hosts.yml                    one group per environment under "uag"
  group_vars/uag/main.yml      common: OVA path/version, deployment option, behaviour
  group_vars/<env>/main.yml    per environment: vCenter, port groups, DNS, uag_env, OS user
  group_vars/<env>/vault.yml   per environment secrets (ansible-vault) — see vault.yml.example
  host_vars/<host>.yml         VM name, appliance name, IP, gateway, template name
templates/settings/<host>.json.j2   generated from the export (ignored by git)
files/ova/      the UAG OVA (non-FIPS)
files/certs/<uag_env>/   internet-fullchain.pem internet-key.pem admin-fullchain.pem admin-key.pem
files/backup/   output of 01_export.yml
files/idp/      fresh IdP SAML metadata, only if the IdP rotated its keys
scripts/        inspect_export.py, make_settings_template.py, refresh_idp_metadata.py, ovf_props.sh
```

## Quick start

```bash
python3 -m venv ~/.venv/uag && source ~/.venv/uag/bin/activate
pip install -r requirements.txt && ansible-galaxy collection install -r requirements.yml
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES          # macOS only

# 1. environment: copy inventory/group_vars/env_example to group_vars/<env>, fill main.yml,
#    create vault.yml from vault.yml.example and encrypt it; put the certificates in files/certs/<uag_env>/
echo '<vault password>' > .vault_pass && chmod 600 .vault_pass
ansible-vault encrypt inventory/group_vars/<env>/vault.yml

# 2. host_vars/<host>.yml: at least uag_mgmt_ip and the EXACT VM name in vCenter

# 3. backup of the running appliance
ansible-playbook playbooks/01_export.yml -l <host>
scripts/inspect_export.py files/backup/<date>/<host>/settings.json

# 4. check the OVA properties once per release
scripts/ovf_props.sh files/ova/euc-unified-access-gateway-<version>_OVF10.ova

# 5. dry run: generates the template, validates it, looks the VM up in vCenter, changes nothing
ansible-playbook playbooks/02_upgrade.yml -l <host> --check

# 6. upgrade (two confirmations: before the deploy, and before quiescing the old appliance)
ansible-playbook playbooks/02_upgrade.yml -l <host>
ansible-playbook playbooks/03_verify.yml -l <host>
```

Useful tags and overrides:

```bash
ansible-playbook playbooks/02_upgrade.yml -l <host> --tags settings            # re-apply settings only
ansible-playbook playbooks/02_upgrade.yml -l <host> --tags cert                # certificates only (on a freshly deployed UAG)
ansible-playbook playbooks/04_cert_renew.yml -l <host>                         # certificate renewal on a running UAG (see below)
ansible-playbook playbooks/02_upgrade.yml -l <host> -e uag_vm_cpus=4 -e uag_vm_memory_mb=8192
ansible-playbook playbooks/02_upgrade.yml -l <host> -e uag_deployment_option=onenic-large
ansible-playbook playbooks/02_upgrade.yml -l <host> --check -e uag_regenerate_template=true
```

## Certificate renewal (no redeploy)

When the public certificate expires you don't need a new appliance: `04_cert_renew.yml` uploads a
renewed certificate on the Internet interface (443, seen by Horizon clients) and on the Admin
interface (9443) of each UAG, one at a time, with no appliance reboot. The UAG has **two**
separate TLS certificates; the playbook pushes both, but you can limit it with tags.

```bash
# 1. prepare the PEM files in files/certs/<uag_env>/
#    fullchain = leaf certificate followed by the intermediate(s); 2609 wants the full chain.
cat cert.pem intermediate.pem > files/certs/<uag_env>/internet-fullchain.pem
cp key.pem files/certs/<uag_env>/internet-key.pem            # unencrypted key (BEGIN PRIVATE KEY / BEGIN RSA PRIVATE KEY)
openssl verify -CAfile intermediate.pem cert.pem             # must say OK
# same certificate on the admin interface? copy the files (or set uag_cert_admin_enabled: false to skip it)
cp files/certs/<uag_env>/internet-fullchain.pem files/certs/<uag_env>/admin-fullchain.pem
cp files/certs/<uag_env>/internet-key.pem       files/certs/<uag_env>/admin-key.pem

# 2. renew, one UAG at a time (the playbook checks that key and certificate match first)
ansible-playbook playbooks/04_cert_renew.yml -l <host>           # Internet + Admin
ansible-playbook playbooks/04_cert_renew.yml -l <group>          # every UAG of an environment, serially
ansible-playbook playbooks/04_cert_renew.yml -l <host> --tags internet   # Internet interface only
ansible-playbook playbooks/04_cert_renew.yml -l <host> --tags admin      # Admin interface only

# 3. verify what the appliance now serves
ansible-playbook playbooks/03_verify.yml -l <host>
openssl s_client -connect <uag-fqdn>:443 </dev/null | openssl x509 -noout -subject -enddate
```

Notes: the upload on the Admin interface restarts the admin service on 9443 for a few seconds
(the playbook waits for it to come back); no user session is affected. If the key is encrypted,
decrypt it first with `openssl pkey -in key-enc.pem -out files/certs/<uag_env>/internet-key.pem`.
Check the expiry of the IdP signing certificate too: it lives inside the SAML metadata in the
settings, not in these files (`scripts/inspect_export.py` reports it; `scripts/refresh_idp_metadata.py`
updates it in the template).

## What the export does not contain

The UAG export has everything except passwords/shared secrets, keytabs, the TLS certificates
and the binaries of custom executables hosted on the appliance (e.g. the OPSWAT on-demand agent).
Passwords come from the vault, certificates from `files/certs/`, custom executables must be
re-uploaded from the Admin UI after the deploy (`inspect_export.py` lists them as `MANUAL`).
Network settings (IP, DNS, gateway) are OVF properties, not settings.

## Lessons learned on 25.03 → 2609 (handled by `make_settings_template.py`)

- **OPSWAT intervals**: the 25.03 export stores `complianceCheckInterval/InitialDelay/FastInterval`
  as `300` with `complianceCheckTimeunit: MINUTES`; 2609 validates them as minutes and rejects the
  whole OPSWAT provider, and with it the Horizon edge service that references it. The import
  still answers 200. Fix: `SECONDS`.
- **Blast host header allow list**: the 2609 Blast Secure Gateway validates the client `Host`
  header against `blastAllowedHostHeaderValues`; the automatic list only covers `:443`. Without
  `<external host>:<blast port>` and `localhost:8443` (internal esmanager → BSG hop) clients fail
  with `VDPCONNECT_REJECTED` and `bsg.log` shows `Unmatched Host header "localhost:8443"`.
- `generalSettings` (network) is read-only on import; `X-XSS-Protection` is deprecated. Both removed.
- Boolean OVF properties (`ceipEnabled`, `sshEnabled`) must be passed as `True`/`False`.
- `ntpServers` is not an OVF property of the 2609 OVA: it has to be in `systemSettings` of the template.
- After the settings `PUT` the tunnel process takes ~50 s to start and the edge service may stay
  "Degraded" (`startup configuration not yet complete`) until the edge service is restarted once
  the tunnel is up; the playbook waits and re-applies the settings if needed.
- The `osLoginUsername` OVF property creates a sudo user and disables root login
  (`uag_os_login_username`).

## Rollback

The old VM is still in vCenter as `<name>_OLD_<date>`, powered off, with its IP and configuration.
Power off the new one, rename, power on the old one, disable quiesce mode in the Admin UI,
re-enable it on the load balancer.

## Requirements

Ansible ≥ 2.15, `community.vmware`, Python `pyvmomi` and `requests` (see `requirements.*`),
`openssl` on the control node, a vCenter service account allowed to deploy OVF, create/remove,
power and rename VMs in the target folder/cluster.

## License

MIT
