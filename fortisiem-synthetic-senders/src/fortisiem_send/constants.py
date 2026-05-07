from __future__ import annotations

DEFAULT_TARGET = "10.255.9.3"
DEFAULT_PORT = 514
DEFAULT_RATE = 5
DEFAULT_DOMAIN = "age.local"
DEFAULT_FORTIEDR_TENANT = "default"
DEFAULT_FORTIEDR_SITE = "onprem-site"

SUPPORTED_SOURCES = frozenset({"fortigate", "fortimail", "windows", "linux", "fortiedr", "vmware"})
