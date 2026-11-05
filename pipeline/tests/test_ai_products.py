"""Module 27 (AI Product CVEs): the classifier table, the corpus-pass
observer and the ai_products.json contract."""
from __future__ import annotations

import copy

import pytest

# contracts must load before ai_products_contracts: the coordinator
# registers module contracts at the bottom of contracts.py.
from pipeline import contracts  # noqa: F401
from pipeline import ai_products as ap
from pipeline import ai_products_contracts as contract
from pipeline import ai_products_metrics as apm
from pipeline.contracts import ContractViolation
from pipeline.metrics import extract_facts

GENERATED_AT = "2026-11-05T06:00:00Z"


# ------------------------------------------------------------- classifier

@pytest.mark.parametrize("vendor,product,key", [
    ("tensorflow", "tensorflow", "tensorflow"),
    ("Google", "Tensorflow", "tensorflow"),
    ("tensorflow", "keras", "keras"),          # Keras tried before TF
    ("gradio-app", "gradio-app/gradio", "gradio"),
    ("mintplex-labs", "mintplex-labs/anything-llm", "anythingllm"),
    ("vllm-project", "vLLM", "vllm"),
    ("NVIDIA", "Triton Inference Server", "triton"),
    ("NVIDIA", "TensorRT-LLM", "tensorrt"),
    ("NVIDIA", "Megatron-LM", "nvidia_nemo"),
    ("Microsoft", "Microsoft 365 Copilot", "ms_copilot"),
    ("Microsoft", "ONNX Runtime", "onnxruntime"),
    ("IBM", "Langflow OSS", "langflow"),
    ("Red Hat", "Red Hat OpenShift AI 3.4", "openshift_ai"),
    ("Red Hat", "Red Hat AI Inference Server 3.2", "rh_inference"),
    ("pytorch", "serve", "torchserve"),
    ("n/a", "PyTorch", "pytorch"),             # placeholder vendor
    ("n/a", "Intel(R) Neural Compressor software", "intel_ai"),
    ("n/a", "Intel Extension for TensorFlow software", "intel_ai"),
    ("Ollama AI", "Ollama", "ollama"),          # exact bare name
    ("modelcontextprotocol", "python-sdk", "mcp_sdk"),
    ("OpenClaw", "OpenClaw", "openclaw"),
])
def test_named_products_classify(vendor, product, key):
    assert ap.classify(vendor, product) == key


@pytest.mark.parametrize("vendor,product", [
    ("IBM", "AIX"),                          # "ai" inside a word
    ("h2o", "h2o"),                          # the HTTP server, not H2O.ai
    ("Kazuho Oku", "H2O"),
    ("socfortress", "CoPilot"),              # a SOC tool, not an LLM
    ("aws", "copilot-cli"),                  # ECS deploy tool
    ("ServiceNow", "ServiceNow AI Platform"),  # renamed platform
    ("GFI Software", "MailEssentials AI"),
    ("AMD", "AMD Ryzen™ AI 300 Series Processors"),  # hardware
    ("NVIDIA", "CUDA Toolkit"),              # general GPU compute
    ("Microsoft", "Windows 11 Version 24H2"),
    ("Microsoft", "Visual Studio Code"),
    ("Red Hat", "Red Hat Enterprise Linux 9"),
    ("Apache Software Foundation", "Apache Airflow"),
    ("tigroumeow", "AI Engine – The Chatbot, AI Framework & MCP for WordPress"),
    ("ail project", "ail framework"),
    ("labring", "sealos"),                   # FastGPT's vendor, not FastGPT
    ("thoda-dev", "nuxt-ollama"),            # bare names need the exact name
    ("OpenStack", "Mistral"),
    ("n/a", "n/a"),
])
def test_traps_stay_out(vendor, product):
    assert ap.classify(vendor, product) is None


def test_every_rule_points_at_a_known_product():
    keys = {k for rules in ap.RULES.values() for k, _ in rules}
    keys |= {k for _, k in ap.BARE_NAMES}
    assert keys <= set(ap.PRODUCTS)
    assert {p.category for p in ap.PRODUCTS.values()} == set(ap.CATEGORIES)
    # vendor keys are stored normalised, or they could never match
    assert all(v == ap.normalize(v) for v in ap.RULES)
    assert all(kw == ap.normalize(kw)
               for rules in ap.RULES.values() for _, kws in rules for kw in kws)


def _record(cve_id="CVE-2026-0001", affected=None, published="2026-03-01",
            state="PUBLISHED", cwe="CWE-22", cna="GitHub_M", adp_cwe=None):
    cna_block: dict = {
        "problemTypes": [{"descriptions": [
            {"lang": "en", "type": "CWE", "cweId": cwe}]}] if cwe else [],
    }
    if affected is not None:
        cna_block["affected"] = affected
    record = {
        "cveMetadata": {"cveId": cve_id, "state": state,
                        "assignerShortName": cna,
                        "datePublished": f"{published}T00:00:00.000Z"},
        "containers": {"cna": cna_block},
    }
    if adp_cwe:
        record["containers"]["adp"] = [{"problemTypes": [{"descriptions": [
            {"lang": "en", "type": "CWE", "cweId": adp_cwe}]}]}]
    return record


def test_first_usable_entry_only():
    # a distribution CNA lists the AI product after its OS: not counted
    rec = _record(affected=[
        {"vendor": "Red Hat", "product": "Red Hat Enterprise Linux 9"},
        {"vendor": "Red Hat", "product": "Red Hat OpenShift AI 3.4"}])
    assert ap.classify_record(rec) == (None, True)
    # placeholders are skipped to reach the first usable entry
    rec = _record(affected=[{"vendor": "n/a", "product": "n/a"},
                            {"vendor": "ollama", "product": "ollama"}])
    assert ap.classify_record(rec) == ("ollama", True)
    # nothing usable: not classifiable either way
    assert ap.classify_record(_record(affected=[
        {"vendor": "n/a", "product": "n/a"}])) == (None, False)
    assert ap.classify_record(_record()) == (None, False)


# --------------------------------------------------------------- collector

def _collect(records, *, kev=(), poc=(), nuclei=()):
    col = apm.AiProductCollector(kev_ids=kev, poc_ids=poc, nuclei_ids=nuclei)
    for rec in records:
        facts = extract_facts(rec)
        col(facts, rec)
    return col


GRADIO = [{"vendor": "gradio-app", "product": "gradio"}]
OLLAMA = [{"vendor": "ollama", "product": "ollama"}]
OTHER = [{"vendor": "Acme", "product": "Widget"}]


def _corpus():
    return [
        _record("CVE-2025-0001", GRADIO, "2025-02-01", cwe="CWE-22"),
        _record("CVE-2025-0002", OTHER, "2025-02-02", cwe="CWE-79"),
        _record("CVE-2025-0003", OTHER, "2025-02-03", cwe="CWE-22"),
        _record("CVE-2025-0004", None, "2025-02-04", cwe="CWE-89"),
        _record("CVE-2026-0001", OLLAMA, "2026-01-05", cwe="CWE-918",
                adp_cwe="CWE-1427"),
        _record("CVE-2026-0002", OLLAMA, "2026-01-06", cwe="CWE-918"),
        _record("CVE-2026-0003", OTHER, "2026-01-07", cwe="CWE-79"),
        _record("CVE-2026-0004", OTHER, "2026-01-08", cwe="CWE-918"),
        _record("CVE-2026-0005", OTHER, "2026-01-09", state="REJECTED"),
        _record("CVE-2018-0001", [{"vendor": "tensorflow",
                                   "product": "tensorflow"}], "2018-05-05"),
    ]


def test_years_are_gap_filled_and_partition_by_category():
    obj = apm.build_ai_products(_collect(_corpus()), GENERATED_AT)
    contract.VALIDATORS["ai_products.json"](obj)
    years = {r["year"]: r for r in obj["years"]}
    assert sorted(years) == list(range(2018, 2027))
    assert years[2018]["by_category"]["frameworks"] == 1
    assert years[2020] == {"year": 2020, "published": 0, "named": 0, "ai": 0,
                           "by_category": dict.fromkeys(ap.CATEGORIES, 0),
                           "top_product": None}
    # the rejected record is not published; the record with no affected
    # list is published but not named
    assert years[2025] == {"year": 2025, "published": 4, "named": 3,
                           "ai": 1, "by_category": {
                               "frameworks": 0, "serving": 0,
                               "platforms": 0, "apps": 1},
                           "top_product": {"label": "Gradio", "n": 1}}
    assert years[2026]["ai"] == 2 and years[2026]["published"] == 4


def test_cwe_baseline_is_year_matched_and_excludes_ai_records():
    obj = apm.build_ai_products(_collect(_corpus()), GENERATED_AT)
    cwe = obj["cwe"]
    # window 2023-2026 holds 3 AI CVEs: 1 in 2025, 2 in 2026
    assert cwe["n"] == 3
    assert obj["window"]["weights"] == [{"year": 2025, "pct": 33.3},
                                        {"year": 2026, "pct": 66.7}]
    top = {t["cwe"]: t for t in cwe["top"]}
    assert top["CWE-918"]["n"] == 2 and top["CWE-918"]["pct"] == 66.7
    # other CVEs: 2025 -> 0 of 3 SSRF; 2026 -> 1 of 2 SSRF.
    # weighted: 1/3 * 0 + 2/3 * 0.5 = 33.3%
    assert top["CWE-918"]["baseline_pct"] == 33.3
    # CWE-22: 2025 -> 1 of 3 (CVE-2025-0003); 2026 -> 0 of 2
    assert top["CWE-22"]["baseline_pct"] == 11.1
    assert top["CWE-22"]["name"] == "Path traversal"
    # the ADP container's prompt-injection CWE counts as AI-specific
    assert cwe["ai_specific"]["n"] == 1


def test_exploited_rates_and_kev_list():
    col = _collect(_corpus(), kev={"CVE-2026-0001", "CVE-2026-0003"},
                   poc={"CVE-2025-0001", "CVE-2025-0002"},
                   nuclei={"CVE-2026-0002"})
    obj = apm.build_ai_products(col, GENERATED_AT)
    ex = obj["exploited"]
    assert (ex["kev"], ex["poc"], ex["nuclei"]) == (1, 1, 1)
    assert ex["kev_pct"] == 33.3
    # KEV baseline: 2025 -> 0 of 3; 2026 -> 1 of 2 (CVE-2026-0003)
    assert ex["kev_baseline_pct"] == 33.3
    # 3 AI-product CVEs at the year-matched baseline rate
    assert ex["kev_expected"] == 1.0
    # exploit-code baseline: 2025 -> 1 of 3; 2026 -> 0 of 2
    assert ex["poc_baseline_pct"] == 11.1
    assert ex["kev_cves"] == [{"cve": "CVE-2026-0001", "product": "Ollama"}]
    assert ex["baseline_n"] == 5


def test_board_cnas_and_headline():
    obj = apm.build_ai_products(_collect(_corpus()), GENERATED_AT)
    board = obj["products"]
    assert [b["key"] for b in board] == ["ollama", "gradio"]
    assert board[0]["top_cna"] == "GitHub_M" and board[0]["top_cna_pct"] == 100.0
    assert obj["cnas"]["top"] == [{"cna": "GitHub_M", "n": 3, "pct": 100.0}]
    h = obj["headline"]
    assert (h["latest_year"], h["latest_ai"], h["latest_share_pct"]) == \
        (2025, 1, 25.0)
    assert (h["current_ai"], h["lead_label"], h["lead_pct"]) == \
        (2, "Ollama", 66.7)


def test_empty_corpus_is_valid():
    obj = apm.build_ai_products(_collect([_record(affected=OTHER)]),
                                GENERATED_AT)
    contract.VALIDATORS["ai_products.json"](obj)
    assert obj["years"] == [] and obj["products"] == []
    assert obj["cwe"]["n"] == 0 and obj["exploited"]["kev_cves"] == []


def test_post_dated_records_are_dropped():
    recs = _corpus() + [_record("CVE-2027-0001", OLLAMA, "2027-01-02")]
    obj = apm.build_ai_products(_collect(recs), GENERATED_AT)
    assert obj["years"][-1]["year"] == 2026


@pytest.mark.parametrize("mutate", [
    lambda o: o["years"][-1]["by_category"].update(apps=99),
    lambda o: o["years"].pop(3),
    lambda o: o["cwe"].update(n=99),
    lambda o: o["exploited"].update(kev=1),
    lambda o: o.update(categories=["apps"]),
    lambda o: o["products"].reverse(),
])
def test_contract_rejects_broken_payloads(mutate):
    obj = apm.build_ai_products(_collect(_corpus()), GENERATED_AT)
    bad = copy.deepcopy(obj)
    mutate(bad)
    with pytest.raises(ContractViolation):
        contract.VALIDATORS["ai_products.json"](bad)
