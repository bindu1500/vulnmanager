"""
A small local copy of CISA's Known Exploited Vulnerabilities (KEV) catalog.

CISA publishes the KEV catalog as the authoritative list of CVEs that are being
actively exploited in the wild. A vulnerability being on this list is one of the
strongest signals to patch it first, no matter its CVSS score. In production you
would pull the live feed from cisa.gov; here we keep a static subset so the tool
runs offline and the results are reproducible.
"""
KNOWN_EXPLOITED = {
    "CVE-2021-44228", "CVE-2014-0160", "CVE-2017-0144", "CVE-2019-0708",
    "CVE-2021-34527", "CVE-2023-23397", "CVE-2022-1388", "CVE-2023-34362",
    "CVE-2020-1472", "CVE-2021-26855", "CVE-2022-30190", "CVE-2018-13379",
    "CVE-2023-4863", "CVE-2021-3156", "CVE-2024-3094", "CVE-2017-5638",
    "CVE-2019-11510", "CVE-2016-5195", "CVE-2012-1823", "CVE-2021-41773",
    "CVE-2014-6271", "CVE-2022-26134", "CVE-2023-0669",
}


def is_known_exploited(cve: str) -> bool:
    return cve in KNOWN_EXPLOITED
