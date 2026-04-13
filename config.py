from __future__ import annotations

import os
from zoneinfo import ZoneInfo

from dotenv import load_dotenv

# Load .env file if present.
load_dotenv()


def _env_bool(key: str, default: bool) -> bool:
    raw = os.getenv(key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


ENABLE_CERT_SE = _env_bool("ENABLE_CERT_SE", True)
AUTO_CREATE_CATEGORIES = _env_bool("AUTO_CREATE_CATEGORIES", True)
AUTO_CREATE_CHANNELS = _env_bool("AUTO_CREATE_CHANNELS", True)
AUTO_SET_CHANNEL_PERMISSIONS = _env_bool("AUTO_SET_CHANNEL_PERMISSIONS", True)
ITSEC_LOG_READ_ONLY = _env_bool("ITSEC_LOG_READ_ONLY", True)

TZ_STOCKHOLM = ZoneInfo("Europe/Stockholm")

ITSEC_MANAGED_STRUCTURE = [
    {
        "category_name": "ITSEC ALERTS",
        "channels": [
            {"key": "critical", "name": "cve-critical", "read_only": True},
            {"key": "high", "name": "cve-high", "read_only": True},
            {"key": "weekly", "name": "weekly-summary", "read_only": True},
        ],
    },
    {
        "category_name": "ITSEC NEWS",
        "channels": [
            {"key": "news", "name": "security-news", "read_only": True},
            {"key": "cert_se", "name": "cert-se-alerts", "read_only": True, "enabled": ENABLE_CERT_SE},
        ],
    },
    {
        "category_name": "ITSEC VENDORS",
        "channels": [
            {"key": "vendor_microsoft", "name": "vendor-microsoft", "read_only": True},
            {"key": "vendor_linux", "name": "vendor-linux", "read_only": True},
            {"key": "vendor_google", "name": "vendor-google", "read_only": True},
            {"key": "vendor_apple", "name": "vendor-apple", "read_only": True},
            {"key": "vendor_cisco", "name": "vendor-cisco", "read_only": True},
            {"key": "vendor_fortinet", "name": "vendor-fortinet", "read_only": True},
            {"key": "vendor_vmware", "name": "vendor-vmware", "read_only": True},
            {"key": "vendor_oracle", "name": "vendor-oracle", "read_only": True},
            {"key": "vendor_adobe", "name": "vendor-adobe", "read_only": True},
            {"key": "vendor_apache", "name": "vendor-apache", "read_only": True},
            {"key": "vendor_nginx", "name": "vendor-nginx", "read_only": True},
            {"key": "vendor_openssl", "name": "vendor-openssl", "read_only": True},
            {"key": "vendor_docker", "name": "vendor-docker", "read_only": True},
            {"key": "vendor_kubernetes", "name": "vendor-kubernetes", "read_only": True},
            {"key": "vendor_postgresql", "name": "vendor-postgresql", "read_only": True},
            {"key": "vendor_mysql", "name": "vendor-mysql", "read_only": True},
        ],
    },
    {
        "category_name": "ITSEC BOT",
        "channels": [
            {"key": "ask", "name": "ask-itsec", "read_only": False},
            {"key": "log", "name": "itsec-log", "read_only": ITSEC_LOG_READ_ONLY},
        ],
    },
]

DEFAULT_CHANNELS = {
    channel["key"]: channel["name"]
    for section in ITSEC_MANAGED_STRUCTURE
    for channel in section["channels"]
    if channel.get("enabled", True)
}

MANAGED_CATEGORY_NAMES = tuple(section["category_name"] for section in ITSEC_MANAGED_STRUCTURE)
MANAGED_CHANNEL_NAMES = tuple(
    channel["name"]
    for section in ITSEC_MANAGED_STRUCTURE
    for channel in section["channels"]
    if channel.get("enabled", True)
)
MANAGED_CHANNEL_NAMES_BY_KEY = {
    channel["key"]: channel["name"]
    for section in ITSEC_MANAGED_STRUCTURE
    for channel in section["channels"]
    if channel.get("enabled", True)
}
MANAGED_CHANNELS_BY_NAME = {
    channel["name"]: {
        "key": channel["key"],
        "category_name": section["category_name"],
        "read_only": bool(channel["read_only"]),
    }
    for section in ITSEC_MANAGED_STRUCTURE
    for channel in section["channels"]
    if channel.get("enabled", True)
}

NEWS_VENDOR_MATCHERS = {
    "vendor_microsoft": {
        "microsoft",
        "windows",
        "sharepoint",
        "exchange",
        "azure",
        "msrc",
        "microsoft 365",
        "m365",
        "outlook",
        "teams",
        "onedrive",
        "entra",
        "azure ad",
        "active directory",
        "defender for endpoint",
    },
    "vendor_linux": {
        "linux",
        "kernel",
        "ubuntu",
        "debian",
        "red hat",
        "rhel",
        "centos",
        "rocky linux",
        "almalinux",
        "suse",
        "opensuse",
        "fedora",
        "debian security",
    },
    "vendor_google": {
        "google",
        "android",
        "chrome",
        "chromium",
        "gcp",
        "google cloud",
        "google workspace",
        "gmail",
        "pixel",
        "chromeos",
    },
    "vendor_apple": {
        "apple",
        "ios",
        "macos",
        "iphone",
        "ipad",
        "safari",
        "icloud",
        "xcode",
        "webkit",
        "airdrop",
    },
    "vendor_cisco": {
        "cisco",
        "catalyst",
        "secure firewall",
        "fmc",
        "asa",
        "ios xe",
        "ios-xe",
        "firepower",
        "ise",
        "meraki",
        "webex",
    },
    "vendor_fortinet": {
        "fortinet",
        "fortigate",
        "fortios",
        "fortimanager",
        "fortiproxy",
        "fortiweb",
        "forticlient",
        "fortianalyzer",
        "fortisiem",
        "fortisandbox",
    },
    "vendor_vmware": {
        "vmware",
        "aria",
        "esxi",
        "vcenter",
        "vsphere",
        "nsx",
        "horizon",
        "tanzu",
        "vrealize",
        "workstation pro",
    },
    "vendor_oracle": {
        "oracle",
        "weblogic",
        "identity manager",
        "java",
        "oracle cloud",
        "oci",
        "peoplesoft",
        "oracle linux",
    },
    "vendor_adobe": {
        "adobe",
        "acrobat",
        "reader",
        "photoshop",
        "illustrator",
        "acrobat reader",
        "coldfusion",
        "adobe experience manager",
        "aem",
        "premiere pro",
    },
    "vendor_apache": {
        "apache",
        "http server",
        "tomcat",
        "struts",
        "httpd",
        "apache kafka",
        "apache solr",
        "apache hadoop",
        "apache flink",
    },
    "vendor_nginx": {
        "nginx",
        "nginx plus",
        "ingress-nginx",
        "openresty",
    },
    "vendor_openssl": {
        "openssl",
        "openssl project",
        "libssl",
    },
    "vendor_docker": {
        "docker",
        "containerd",
        "docker desktop",
        "docker engine",
        "docker hub",
        "moby",
        "buildkit",
    },
    "vendor_kubernetes": {
        "kubernetes",
        "k8s",
        "kubelet",
        "kube-apiserver",
        "kubectl",
        "kubeadm",
        "helm",
        "etcd",
        "openshift",
    },
    "vendor_postgresql": {
        "postgresql",
        "postgres",
        "pgadmin",
        "postgis",
    },
    "vendor_mysql": {
        "mysql",
        "mariadb",
        "percona",
        "mysql server",
        "mysql workbench",
    },
}

NEWS_FEEDS = [
    "https://www.bleepingcomputer.com/feed/",
    "https://therecord.media/feed",
    "https://krebsonsecurity.com/feed/",
    "https://www.cisa.gov/cybersecurity-advisories/all.xml",
    "https://isc.sans.edu/rssfeed.xml",
    "https://googleprojectzero.blogspot.com/feeds/posts/default?alt=rss",
    "https://security.googleblog.com/atom.xml",
    "https://msrc.microsoft.com/blog/feed",
    "https://www.rapid7.com/blog/rss/",
    "https://blog.talosintelligence.com/rss/",
    "https://unit42.paloaltonetworks.com/feed/",
    "https://www.schneier.com/feed/atom/",
]

if ENABLE_CERT_SE:
    NEWS_FEEDS.append("https://www.cert.se/feed/")

BROAD_IMPACT_KEYWORDS = {
    "microsoft",
    "windows",
    "linux",
    "linux kernel",
    "apache",
    "nginx",
    "openssl",
    "cisco",
    "fortinet",
    "vmware",
    "oracle",
    "postgresql",
    "mysql",
    "adobe",
    "google chrome",
    "firefox",
    "android",
    "ios",
    "kubernetes",
    "docker",
}


def get_setting(key: str, default=None):
    """Hamta en installning fran miljo med fallback."""
    return os.getenv(key, default)


def get_int_setting(key: str, default: int) -> int:
    """Hamta heltalsinstallning med fallback vid parse-fel."""
    raw = os.getenv(key)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def get_optional_guild_id() -> int | None:
    """Returnera guild-id om satt, annars None."""
    raw = get_setting("GUILD_ID")
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


if not get_setting("DISCORD_TOKEN"):
    raise ValueError("DISCORD_TOKEN maste anges i .env-filen")
