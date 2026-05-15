# SigWaz CLI

Convert [Sigma](https://github.com/SigmaHQ/sigma) detection rules to production-ready [Wazuh](https://wazuh.com) XML — from the command line.

SigWaz supports single-rule conversion, recursive batch directory processing, ZIP archives, and full metadata filtering, all scriptable with no interactive prompts.

---

## Features

- **Single & batch conversion** — one file, a directory tree, a multi-doc YAML, or a ZIP archive
- **Recursive directory scanning** — walks subdirectories automatically, skips `deprecated/` folders
- **Advanced metadata filtering** — filter by status (`experimental`, `deprecated`…), minimum severity level, or allowed products
- **XML splitting** — automatically split large outputs into chunks to prevent Wazuh OOM on import
- **Stable rule IDs** — optional ID tracker persists Sigma GUID → Wazuh ID mappings across re-runs
- **Config file support** — store all parameters in a YAML or JSON profile; CLI flags override when needed
- **ZIP output** — bundle all split XML files into a single `.zip` for easy deployment
- **XML validation** — built-in structural validation after every conversion
- **Field mapping tables** — inspect all Sigma → Wazuh decoder path mappings
- **No TUI, fully scriptable** — designed for automation and CI pipelines

---

## Prerequisites

- Python 3.11 or later
- pip

---

## Installation

```bash
git clone https://github.com/your-org/sigwaz-cli.git
cd sigwaz-cli
pip install -r requirements.txt
```

Verify:

```bash
python sigwaz.py --help
```

Or, if installed as a package:

```bash
pip install -e .
sigwaz --help
```

---

## Usage

### Convert a single rule

```bash
# Print XML to stdout
python sigwaz.py convert rule.yml

# Save to a file
python sigwaz.py convert rule.yml -o output/rule_rules.xml

# Dry-run (analyse without writing)
python sigwaz.py convert rule.yml --dry-run

# Custom rule ID base, skip experimental
python sigwaz.py convert rule.yml -r 910000 --excluded-statuses experimental
```

### Batch-convert a directory

```bash
# Recursive scan of a directory, output to output/
python sigwaz.py batch rules/windows/ -o output/

# Split into chunks of 100 rules max
python sigwaz.py batch rules/ -o output/ --split 100

# Filter: only medium+ severity, skip experimental and deprecated
python sigwaz.py batch rules/ -o output/ \
  --min-level medium \
  --excluded-statuses experimental,deprecated

# Only Windows and Linux rules
python sigwaz.py batch rules/ -o output/ --allowed-products windows,linux

# Bundle output into a ZIP archive
python sigwaz.py batch rules/ -o output/ --zip

# From a ZIP archive of YAML files
python sigwaz.py batch sigma-rules.zip -o output/ --split 50
```

### Using a config file

For complex setups, store all parameters in a config file to avoid long command lines:

```bash
python sigwaz.py batch rules/ -o output/ --config config.yaml
```

CLI flags always override the config file when explicitly provided:

```bash
# Uses config.yaml but forces min-level to high
python sigwaz.py batch rules/ -o output/ --config config.yaml --min-level high
```

#### Example `config.yaml`

```yaml
rule_id_start: 900000
no_full_log: true
email_alert: false
email_levels:
  - critical
  - high
excluded_statuses:
  - experimental
  - deprecated
min_level: medium
allowed_products:
  - windows
  - linux
  - aws
split_size: 50
level_informational: 5
level_low: 7
level_medium: 10
level_high: 12
level_critical: 15
# Optional: field path overrides per product
field_overrides:
  windows:
    CommandLine: win.eventdata.commandLine
# Optional: stable rule IDs across re-runs
id_file: ~/.sigwaz/ids.json
```

#### Example `config.json`

```json
{
  "rule_id_start": 900000,
  "excluded_statuses": ["experimental", "deprecated"],
  "min_level": "medium",
  "split_size": 100
}
```

### Validate an existing XML file

```bash
python sigwaz.py check output/windows_rules.xml
python sigwaz.py check /var/ossec/etc/rules/sigma_rules.xml
```

### Inspect field mappings

```bash
# All products
python sigwaz.py fieldmaps

# One product
python sigwaz.py fieldmaps windows

# JSON output (pipe to jq, etc.)
python sigwaz.py fieldmaps aws --json
```

### Show version and supported products

```bash
python sigwaz.py info
python sigwaz.py sidmaps
```

---

## All CLI options

| Flag | Default | Description |
|------|---------|-------------|
| `--config / -c` | — | YAML or JSON config file |
| `--rule-id-start / -r` | `900000` | Starting Wazuh rule ID |
| `--no-full-log / --full-log` | enabled | Append `no_full_log` option to rules |
| `--email-alert / --no-email` | disabled | Append `alert_by_email` to qualifying rules |
| `--email-levels` | `critical,high` | Comma-separated levels that trigger email |
| `--excluded-statuses` | — | Sigma statuses to skip (CSV) |
| `--min-level` | — | Minimum Sigma severity (low/medium/high/critical) |
| `--allowed-products` | — | Whitelist of logsource products (CSV) |
| `--split / -s` | `50` | Max rules per XML file (0 = no split) |
| `--zip` | disabled | Bundle output XML files into a ZIP |
| `--id-file` | — | Path to ID persistence JSON file |
| `--field-overrides` | — | JSON: per-product field map overrides |
| `--if-sid-overrides` | — | JSON: per-product if_sid overrides |
| `--if-group-overrides` | — | JSON: per-product if_group overrides |
| `--level-informational` | `5` | Wazuh level for Sigma informational rules |
| `--level-low` | `7` | Wazuh level for Sigma low rules |
| `--level-medium` | `10` | Wazuh level for Sigma medium rules |
| `--level-high` | `12` | Wazuh level for Sigma high rules |
| `--level-critical` | `15` | Wazuh level for Sigma critical rules |
| `--dry-run` | disabled | Parse and report without writing files |
| `--validate / --no-validate` | enabled | Run XML validation after conversion |

---

## Supported products

Run `sigwaz info` for the full list. Core coverage includes:

Windows, Sysmon, SysmonForLinux, Linux Auditd, SSH, PAM, Sudo, ClamAV, Apache, Nginx, IIS, AWS CloudTrail, Azure AD, GCP, Office 365, Okta, GitHub, Kubernetes, DNS, Network/Firewall, Palo Alto PAN-OS, Cisco ASA/FTD, Fortinet FortiGate, Check Point, OSQuery, Zeek/Bro.

---

## License

MIT
