"""The security-product classifier: the curated tables behave as the
module docstring promises — wholesale vendors, keyword vendors, and the
documented exclusions (MOVEit is transfer, not security)."""
from __future__ import annotations

from pipeline.security_products import (CLASSIFIER_VERSION, PRODUCT_RULES,
                                        SECURITY_VENDORS,
                                        is_security_product,
                                        normalize_vendor, rule_count)


def test_wholesale_vendor_counts_regardless_of_product():
    assert is_security_product("Fortinet", "FortiOS")
    assert is_security_product("Fortinet", "Some Future Product")
    assert is_security_product("Palo Alto Networks", "Expedition")


def test_vendor_match_is_trimmed_and_case_insensitive():
    # the live feed carries stray whitespace ("SimpleHelp ") and the
    # classifier must not depend on the feed's capitalization
    assert is_security_product("  fortinet  ", "FortiOS")
    assert is_security_product("SONICWALL", "SonicOS")
    assert not is_security_product("SimpleHelp ", "SimpleHelp")


def test_mixed_vendor_needs_a_product_keyword():
    assert is_security_product("Cisco", "Adaptive Security Appliance (ASA)")
    assert is_security_product(
        "Cisco", "Secure Firewall Adaptive Security Appliance and Secure "
                 "Firewall Threat Defense")
    assert is_security_product("Cisco", "AnyConnect Secure")
    assert is_security_product("Cisco", "Identity Services Engine")
    assert not is_security_product("Cisco", "IOS XE Software")
    assert not is_security_product("Cisco", "Small Business RV Series Routers")
    assert not is_security_product("Cisco", "Unified Communications Manager")


def test_citrix_netscaler_estate_yes_sharefile_no():
    assert is_security_product("Citrix", "NetScaler ADC and NetScaler Gateway")
    assert is_security_product(
        "Citrix", "Application Delivery Controller (ADC), Gateway, and "
                  "SD-WAN WANOP Appliance")
    assert not is_security_product("Citrix", "ShareFile")
    assert not is_security_product("Citrix", "StoreFront Server")


def test_ivanti_secure_access_yes_desktop_management_no():
    assert is_security_product("Ivanti", "Pulse Connect Secure")
    assert is_security_product("Ivanti", "Endpoint Manager Mobile (EPMM)")
    assert is_security_product("Ivanti", "Cloud Services Appliance (CSA)")
    assert not is_security_product("Ivanti", "Endpoint Manager (EPM)")
    assert not is_security_product("Ivanti", "Virtual Traffic Manager")


def test_documented_exclusions_hold():
    # MOVEit is transfer, NOT security (module docstring, judgment calls)
    assert not is_security_product("Progress", "MOVEit Transfer")
    assert not is_security_product("Progress", "Kemp LoadMaster")
    assert not is_security_product("Microsoft", "Exchange Server")
    assert not is_security_product("Zoho", "ManageEngine")
    assert not is_security_product("Veeam", "Backup & Replication")
    assert not is_security_product("ConnectWise", "ScreenConnect")
    # unknown vendors never classify, whatever the product says
    assert not is_security_product("Acme", "Firewall Deluxe")


def test_microsoft_defender_yes_exchange_no():
    assert is_security_product("Microsoft", "Defender")
    assert is_security_product("Microsoft",
                               "Forefront Threat Management Gateway (TMG)")
    assert not is_security_product("Microsoft", "Windows")


def test_normalize_vendor_collapses_whitespace():
    assert normalize_vendor("SimpleHelp ") == "SimpleHelp"
    assert normalize_vendor("  Palo  Alto   Networks ") == \
        "Palo Alto Networks"


def test_tables_are_normalized_and_versioned():
    # lookups casefold the vendor, so the tables must already be casefolded
    for name in SECURITY_VENDORS:
        assert name == name.casefold().strip()
    for vendor, keywords in PRODUCT_RULES.items():
        assert vendor == vendor.casefold().strip()
        assert keywords, f"{vendor}: empty keyword rule"
        for kw in keywords:
            assert kw == kw.casefold()
    assert CLASSIFIER_VERSION >= 1
    assert rule_count() == len(SECURITY_VENDORS) + len(PRODUCT_RULES)
