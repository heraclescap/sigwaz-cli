"""
SigWaz SID/Group Maps — Wazuh parent rule IDs per product/service.

if_sid  → parent rules by numeric ID (most specific)
if_group → parent rules by group name (broader match)

Service lookup takes precedence over product lookup (mirrors legacy behavior).
"""
from __future__ import annotations
from typing import Dict, Optional, Tuple

# ---------------------------------------------------------------------------
# if_sid — numeric parent rule IDs
# ---------------------------------------------------------------------------
IF_SID_MAP: Dict[str, str] = {
    # ── Windows ─────────────────────────────────────────────────────────
    "windows": (
        "18100, 60000, 60001, 60002, 60003, 60004, "
        "60006, 60007, 60008, 60009, 60010, 60011, 60012"
    ),
    # ── Sysmon (Windows) ────────────────────────────────────────────────
    "sysmon": (
        "184665, 185000, 185001, 185002, 185003, 185004, 185005, "
        "185006, 185007, 185008, 185009, 185010, 185011, 185012, 185013, "
        "184666, 184667, 184676, 184677, 184678, 184686, 184687, "
        "184696, 184697, 184698, 184706, 184707, 184716, 184717, "
        "184726, 184727, 184736, 184737, 184746, 184747, "
        "184766, 184767, 184776"
    ),
    # ── Windows Defender ────────────────────────────────────────────────
    "windefend": "60005",
    "windows_defender": "60005",
    "microsoft windows defender": "60005",
    # ── Sysmon for Linux ────────────────────────────────────────────────
    "sysmon_linux": (
        "185100, 185101, 185102, 185103, 185104, 185105, "
        "185106, 185107, 185108, 185109, 185110"
    ),
    "sysmonforlinux": (
        "185100, 185101, 185102, 185103, 185104, 185105, "
        "185106, 185107, 185108, 185109, 185110"
    ),
    "sysmon-linux": (
        "185100, 185101, 185102, 185103, 185104, 185105, "
        "185106, 185107, 185108, 185109, 185110"
    ),
    # ── Linux Auditd ────────────────────────────────────────────────────
    "auditd": (
        "80700, 80701, 80702, 80703, 80704, 80705, 80706, 80707, "
        "80708, 80709, 80710, 80711, 80784, 80785, 80788, "
        "80789, 80790, 80791, 80792"
    ),
    # ── Generic Linux (kernel, syslog) ───────────────────────────────────
    "linux": "5100, 5400, 5500, 5700, 7100, 11100",
    # ── SSH ─────────────────────────────────────────────────────────────
    "ssh": "5700, 5710, 5711, 5712, 5713, 5714, 5715, 5716",
    # ── PAM ─────────────────────────────────────────────────────────────
    "pam": "5500, 5501, 5502, 5503, 5504",
    # ── Sudo ────────────────────────────────────────────────────────────
    "sudo": "5400, 5401, 5402, 5403",
    # ── Apache HTTP Server ───────────────────────────────────────────────
    "apache": "30100, 30101, 30105, 30107, 30108, 30109, 30302",
    "apache-httpd": "30100, 30101, 30105, 30107, 30108, 30109, 30302",
    "apache2": "30100, 30101, 30105, 30107, 30108, 30109, 30302",
    "httpd": "30100, 30101, 30105, 30107, 30108, 30109, 30302",
    # ── Nginx ────────────────────────────────────────────────────────────
    "nginx": "31101, 31102, 31106, 31107, 31108",
    # ── IIS ─────────────────────────────────────────────────────────────
    "iis": "62100, 62101, 62102, 62103, 62104, 62105",
    # ── AWS CloudTrail ───────────────────────────────────────────────────
    "aws": (
        "80200, 80202, 80250, 80251, 80252, 80253, 80254, 80255, "
        "80256, 80257, 80258, 80259, 80260, 80261, 80262, 80265, "
        "80267, 80268, 80269, 80270, 80271, 80272, 80274, 80276, "
        "80278, 80280, 80281, 80282, 80283, 80284, 80285, 80286, "
        "80287, 80288, 80289, 80290, 80291, 80292, 80293, 80294"
    ),
    # ── Azure Activity / Azure AD ────────────────────────────────────────
    "azure": (
        "87500, 87501, 87502, 87503, 87504, 87505, "
        "87506, 87507, 87508, 87509, 87510"
    ),
    "azuread": (
        "87500, 87501, 87502, 87503, 87504, 87505, "
        "87506, 87507, 87508, 87509, 87510"
    ),
    "azure_ad": (
        "87500, 87501, 87502, 87503, 87504, 87505, "
        "87506, 87507, 87508, 87509, 87510"
    ),
    # ── Microsoft 365 / Office 365 ───────────────────────────────────────
    "office365": (
        "91500, 91501, 91502, 91503, 91504, 91505, 91506, 91507, "
        "91508, 91509, 91510, 91511, 91512, 91513, 91514, 91515, "
        "91516, 91517, 91518, 91519, 91520"
    ),
    "o365": (
        "91500, 91501, 91502, 91503, 91504, 91505, 91506, 91507, "
        "91508, 91509, 91510, 91511, 91512, 91513, 91514, 91515"
    ),
    "m365": (
        "91500, 91501, 91502, 91503, 91504, 91505, 91506, 91507, "
        "91508, 91509, 91510, 91511, 91512, 91513, 91514, 91515"
    ),
    # ── GCP (Google Cloud) ────────────────────────────────────────────────
    "gcp": "65000, 65001, 65002, 65003, 65004, 65005, 65006",
    "googleworkspace": "65000, 65001, 65002, 65003, 65004, 65005, 65006",
    # ── Okta ─────────────────────────────────────────────────────────────
    "okta": "92800, 92801, 92802, 92803, 92804, 92805",
    # ── GitHub ───────────────────────────────────────────────────────────
    "github": "92900, 92901, 92902, 92903",
    # ── Kubernetes ───────────────────────────────────────────────────────
    "kubernetes": "86000, 86001, 86002, 86003, 86004, 86005",
    "k8s": "86000, 86001, 86002, 86003, 86004, 86005",
    # ── Zeek (Bro) ───────────────────────────────────────────────────────
    "zeek": "100200, 100201, 100202, 100203, 100210, 100211, 100212",
    "bro": "100200, 100201, 100202, 100203, 100210, 100211, 100212",
    # ── DNS ──────────────────────────────────────────────────────────────
    "dns": "64000, 64001, 64002, 64003",
    # ── Firewall / Network ────────────────────────────────────────────────
    "firewall": "4100, 4101, 4102, 4103, 4104",
    "network": "4100, 4101, 4102, 4103",
    # ── Palo Alto Networks PAN-OS ────────────────────────────────────────
    "palo_alto": "64430, 64431, 64432, 64433, 64434, 64435, 64440, 64450",
    "palo-alto": "64430, 64431, 64432, 64433, 64434, 64435, 64440, 64450",
    "pan-os": "64430, 64431, 64432, 64433, 64434, 64435, 64440, 64450",
    # ── Cisco ASA / FTD / IOS ───────────────────────────────────────────
    "cisco": "4300, 4301, 4302, 4303, 4304, 4305, 4306, 4307",
    "cisco-asa": "4300, 4301, 4302, 4303, 4304, 4305, 4306, 4307",
    "cisco-ftd": "4300, 4301, 4302, 4303, 4304, 4305, 4306, 4307",
    # ── Fortinet FortiGate ──────────────────────────────────────────────
    "fortinet": "81500, 81501, 81502, 81503, 81504, 81505",
    "fortigate": "81500, 81501, 81502, 81503, 81504, 81505",
    # ── Check Point ────────────────────────────────────────────────────
    "checkpoint": "64100, 64101, 64102, 64103, 64104, 64105",
    # ── ClamAV ───────────────────────────────────────────────────────────
    "clamav": "52000, 52001, 52002",
    # ── OSQuery ──────────────────────────────────────────────────────────
    "osquery": "24000, 24001, 24002, 24003, 24004",
}

# ---------------------------------------------------------------------------
# if_group — group-name parent rules (optional, used when group-based routing)
# ---------------------------------------------------------------------------
IF_GROUP_MAP: Dict[str, str] = {
    # Uncomment to enable group-based routing (can cause OOM on large rulesets)
    # "sysmon":       "sysmon",
    "clamav":       "clamav",
    "osquery":      "osquery",
    # "windows":    "windows",
}

# ---------------------------------------------------------------------------
# Service-to-product normalization (Sigma logsource.service overrides product)
# ---------------------------------------------------------------------------
SERVICE_ALIASES: Dict[str, str] = {
    "security": "windows",
    "system": "windows",
    "application": "windows",
    "microsoft-windows-sysmon/operational": "sysmon",
    "sysmon": "sysmon",
    "microsoft-windows-windows defender/operational": "windefend",
    "windefend": "windefend",
    "clamav": "clamav",
    "auth": "pam",
    "authpriv": "pam",
    "sshd": "ssh",
    "sudo": "sudo",
    "auditd": "auditd",
    "kern": "linux",
    "kernel": "linux",
    "syslog": "linux",
    "apache_access": "apache",
    "apache_error": "apache",
    "nginx_access": "nginx",
    "nginx_error": "nginx",
    "iis": "iis",
    "aws": "aws",
    "azure": "azure",
    "azuread": "azure",
    "o365": "office365",
    "office365": "office365",
    "okta": "okta",
    "github": "github",
    "kubernetes": "kubernetes",
    "gcp": "gcp",
    "gsuite": "gcp",
    "googleworkspace": "gcp",
    "dns": "dns",
    "osquery": "osquery",
    "zeek": "zeek",
    # Firewall / network appliances
    "pan-os": "palo_alto",
    "paloalto": "palo_alto",
    "cisco-asa": "cisco",
    "cisco-ftd": "cisco",
    "fortigate": "fortinet",
    "checkpoint": "checkpoint",
}


def _normalize_override_val(val) -> str:
    if isinstance(val, list):
        return ", ".join(str(v) for v in val)
    return str(val)


def get_if_sid(
    logsource: dict,
    overrides: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """
    Resolve the if_sid value for a given logsource dict.

    Two-pass lookup so that any override always wins over built-in values:
      Pass 1 — scan all candidates against overrides (service → product order)
      Pass 2 — scan all candidates against IF_SID_MAP (service → product order)
    This means an override on the product key (e.g. "zeek") applies to ALL
    services of that product, even when a service key has a built-in entry.
    """
    service = (logsource.get("service") or "").lower().strip()
    product = (logsource.get("product") or "").lower().strip()

    svc_product = SERVICE_ALIASES.get(service, service) if service else ""
    candidates = [c for c in [service, svc_product, product] if c]

    if overrides:
        for key in candidates:
            if key in overrides:
                return _normalize_override_val(overrides[key])

    for key in candidates:
        if key in IF_SID_MAP:
            return IF_SID_MAP[key]

    return None


def get_if_group(
    logsource: dict,
    overrides: Optional[Dict[str, str]] = None,
) -> Optional[str]:
    """
    Resolve the if_group value for a given logsource dict.
    Only used when IF_GROUP_MAP has an entry for the product/service.
    Same two-pass strategy as get_if_sid.
    """
    service = (logsource.get("service") or "").lower().strip()
    product = (logsource.get("product") or "").lower().strip()

    svc_product = SERVICE_ALIASES.get(service, service) if service else ""
    candidates = [c for c in [service, svc_product, product] if c]

    if overrides:
        for key in candidates:
            if key in overrides:
                return _normalize_override_val(overrides[key])

    for key in candidates:
        if key in IF_GROUP_MAP:
            return IF_GROUP_MAP[key]

    return None


def resolve_product(logsource: dict) -> str:
    """
    Return the effective product string from a Sigma logsource.
    Service aliases take precedence over the raw product field.
    """
    service = (logsource.get("service") or "").lower().strip()
    product = (logsource.get("product") or "").lower().strip()
    if service and service in SERVICE_ALIASES:
        return SERVICE_ALIASES[service]
    return product or service
