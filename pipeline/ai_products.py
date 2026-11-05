"""AI-product classifier for cvelistV5 affected[] vendor/product strings.

THE decision rule (also stated in the on-page methodology): a published CVE
record counts as an **AI-product CVE** when the first usable entry of its
CNA container's ``affected`` list names a product whose primary function
is to build, train, serve or run machine-learning models, or to give
people or programs an interface to them. Four categories:

* **frameworks** — ML frameworks and model libraries (TensorFlow, PyTorch,
  Keras, ONNX, ONNX Runtime, PaddlePaddle, MindSpore, Hugging Face
  Transformers, NVIDIA NeMo and Megatron, Intel's OpenVINO and Neural
  Compressor);
* **serving** — model serving and inference engines (vLLM, Ollama, NVIDIA
  Triton and TensorRT-LLM, llama.cpp, SGLang, LMDeploy, LocalAI, BentoML,
  Ray, TorchServe, LiteLLM's model gateway);
* **platforms** — ML platforms and MLOps (MLflow, Kubeflow, ClearML, ZenML,
  Aim, H2O-3, Label Studio, CVAT, Red Hat OpenShift AI, Azure Machine
  Learning, SageMaker's SDK, LLM tracing such as Lunary and Langfuse);
* **apps** — LLM applications, agents and their toolkits (LangChain,
  LlamaIndex, Langflow, Flowise, Dify, open-webui, Gradio, ComfyUI,
  AnythingLLM, LibreChat, OpenClaw, coding agents such as Claude Code and
  Cursor, Microsoft's Copilot products, Model Context Protocol SDKs and
  servers).

The classifier reads ONLY ``containers.cna.affected[].vendor`` and
``.product`` — never descriptions, never ADP containers. Keyword-matching
descriptions over-matches ("machine learning" in a changelog), and
keyword-matching product names over-matches too: "ai" is in AIX, "agent"
is every endpoint agent, "copilot" is also AWS's ECS deploy tool and a SOC
product, "h2o" is also an HTTP server, "ray" and "triton" name other
software, and the CIRCL "AIL framework" is a leak analyser. So every rule
below names a vendor, and every product keyword is a whole-word phrase
scoped to that vendor.

Judgment calls, drawn once and applied consistently (the table is data,
reviewable in this repo; disagreements welcome):

* **First usable entry.** Only the first affected entry with a
  non-placeholder vendor or product is read, the same entry the Field and
  AI Credits read. A distribution CNA (Red Hat, IBM) lists every product
  that ships a vulnerable component, so a generic Go or Python library
  flaw names "Red Hat OpenShift AI" somewhere in a long list; reading any
  entry would count those library bugs as AI-product bugs. The cost: a
  record that lists an AI product second is missed.
* **General products with an AI feature are out** unless the CNA lists
  the AI component as its own product. "Microsoft 365 Copilot", "Copilot
  Studio", "GitHub Copilot Plugin for JetBrains IDEs", "Azure Machine
  Learning", "Splunk AI Toolkit" and "GitLab AI Gateway" count; Windows,
  Edge, Office, VS Code, Jira and Elastic do not, even when the flaw is in
  their AI feature, because the record names the host product.
* **AI branding is not an AI product.** "ServiceNow AI Platform" (the
  renamed Now Platform), "GFI MailEssentials AI", IBM "OpenPages with
  Watson", IBM "watsonx.data" (a lakehouse) and every "AI-powered"
  WordPress plugin name are out.
* **CMS plugins are out as a class** (WordPress, Drupal, Joomla), even
  when the plugin wraps a model API ("AI Engine", "AI ChatBot", Drupal's
  "AI" module). They extend a CMS, and the plugin-scanning CNAs publish
  thousands a year; naming a few would make the count depend on which
  ones the list happened to name.
* **Hardware and firmware are out** (AMD "Ryzen AI" processors, NVIDIA
  DGX Spark, Ubiquiti "AI Key"). AMD's Ryzen AI *Software* counts.
* **General compute and data tooling is out**: GPU drivers and CUDA,
  Jupyter, Apache Spark and Airflow, Prefect, Kedro, NumPy, pandas,
  Streamlit, general-purpose databases. Vector databases built for
  embeddings (Chroma, Milvus, Qdrant) count as serving infrastructure.
* **Model Context Protocol**: the official SDKs (vendor
  ``modelcontextprotocol``) and the MCP servers listed by name count;
  MCP servers the list does not name are missed like any other unlisted
  product.
* **Curation rule.** The 2026-11-05 review named every product with at
  least three published records that meets the rule above and that the
  review could identify from its vendor and product strings, plus the
  core frameworks and serving stacks regardless of count. Utilities
  around an AI tool that do not themselves call a model (a usage meter,
  a status line) are out. Products first
  appearing after the last review are missed until the list is updated,
  so the newest months undercount the most.

Recall limits (stated on the page): records whose CNA wrote "n/a" or
nothing for vendor and product cannot be classified (most MITRE-assigned
records before 2024); records that name an AI product only in the
description, a CPE, or an ADP container are missed; and the long tail of
small AI projects the list does not name is missed. Every count here is a
lower bound on CVEs in AI software.

Mechanics: both strings are normalised (:func:`normalize` — casefolded,
every run of non-alphanumerics to one space). :data:`RULES` maps a
normalised vendor to ``(product key, keywords)`` pairs tried in table
order; an empty keyword tuple takes every product of that vendor, else a
keyword must occur in the normalised product as a whole-word phrase.
:data:`BARE_NAMES` are distinctive product names for entries no vendor rule
covers: anywhere in the product string under a placeholder vendor ("n/a" /
"PyTorch"), the whole product string under any other vendor. Bump
:data:`CLASSIFIER_VERSION` on any change to either table so the published
data file carries the revision that produced it.
"""
from __future__ import annotations

import re
from typing import NamedTuple

# Bump on ANY change to PRODUCTS, RULES or BARE_NAMES (ai_products.json
# carries it, so a published number is traceable to the table revision).
CLASSIFIER_VERSION = 1
# The date the table was last checked against the corpus (see "Curation
# rule" above). Published beside the version.
REVIEWED = "2026-11-05"

CATEGORIES = ("frameworks", "serving", "platforms", "apps")

_PLACEHOLDERS = frozenset({"", "n a", "na", "unknown", "unspecified",
                           "none", "not applicable", "various"})
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize(text: object) -> str:
    """Casefold and collapse every run of non-alphanumerics to one space
    ("gradio-app/gradio" -> "gradio app gradio", "OpenVINO™" ->
    "openvino")."""
    if not isinstance(text, str):
        return ""
    return _NON_ALNUM.sub(" ", text.casefold()).strip()


class Product(NamedTuple):
    label: str
    category: str


# Product key -> (label, category). The label is what the page's product
# table prints; a key groups every vendor spelling of one product family.
PRODUCTS: dict[str, Product] = {
    # ------------------------------------------------------- frameworks
    "tensorflow": Product("TensorFlow", "frameworks"),
    "keras": Product("Keras", "frameworks"),
    "pytorch": Product("PyTorch (incl. ExecuTorch, Lightning)", "frameworks"),
    "onnx": Product("ONNX", "frameworks"),
    "onnxruntime": Product("ONNX Runtime", "frameworks"),
    "paddle": Product("PaddlePaddle", "frameworks"),
    "mindspore": Product("MindSpore", "frameworks"),
    "mxnet": Product("Apache MXNet", "frameworks"),
    "opennlp": Product("Apache OpenNLP", "frameworks"),
    "hf_libs": Product("Hugging Face libraries (Transformers, Diffusers, "
                       "Datasets, smolagents)", "frameworks"),
    "nvidia_nemo": Product("NVIDIA NeMo, Megatron and Merlin", "frameworks"),
    "intel_ai": Product("Intel AI software (OpenVINO, Neural Compressor, "
                        "framework extensions)", "frameworks"),
    "amd_ryzen_ai": Product("AMD Ryzen AI Software", "frameworks"),
    "deepspeed": Product("DeepSpeed", "frameworks"),
    "nltk": Product("NLTK", "frameworks"),
    "ml_libs": Product("Other ML libraries (scikit-learn, LightGBM, "
                       "DeepPavlov)", "frameworks"),
    "llava": Product("LLaVA", "frameworks"),
    "llama_factory": Product("LLaMA-Factory", "frameworks"),
    # ---------------------------------------------------------- serving
    "vllm": Product("vLLM", "serving"),
    "ollama": Product("Ollama", "serving"),
    "triton": Product("NVIDIA Triton Inference Server", "serving"),
    "tensorrt": Product("NVIDIA TensorRT and TensorRT-LLM", "serving"),
    "llamacpp": Product("llama.cpp and ggml ports", "serving"),
    "sglang": Product("SGLang", "serving"),
    "lmdeploy": Product("LMDeploy", "serving"),
    "lightllm": Product("LightLLM", "serving"),
    "mooncake": Product("Mooncake / KTransformers", "serving"),
    "localai": Product("LocalAI", "serving"),
    "tgi": Product("Hugging Face Text Generation Inference", "serving"),
    "torchserve": Product("TorchServe", "serving"),
    "bentoml": Product("BentoML", "serving"),
    "ray": Product("Ray", "serving"),
    "xinference": Product("Xinference", "serving"),
    "fastchat": Product("FastChat", "serving"),
    "litellm": Product("LiteLLM", "serving"),
    "rh_inference": Product("Red Hat AI Inference Server", "serving"),
    "chatrtx": Product("NVIDIA ChatRTX", "serving"),
    "watson_speech": Product("IBM Watson Speech Services", "serving"),
    "vector_db": Product("Vector databases (Chroma, Milvus, Qdrant)",
                         "serving"),
    "ai_gateway": Product("AI gateways (GitLab AI Gateway, Portkey)",
                          "serving"),
    "xgrammar": Product("XGrammar", "serving"),
    # -------------------------------------------------------- platforms
    "mlflow": Product("MLflow", "platforms"),
    "kubeflow": Product("Kubeflow", "platforms"),
    "clearml": Product("ClearML", "platforms"),
    "zenml": Product("ZenML", "platforms"),
    "aim": Product("Aim and ml-logger", "platforms"),
    "h2o3": Product("H2O-3", "platforms"),
    "labelstudio": Product("Label Studio", "platforms"),
    "cvat": Product("CVAT", "platforms"),
    "feast": Product("Feast", "platforms"),
    "polyaxon": Product("Polyaxon", "platforms"),
    "modeldb": Product("ModelDB", "platforms"),
    "lunary": Product("Lunary", "platforms"),
    "langfuse": Product("Langfuse", "platforms"),
    "uptrain": Product("UpTrain and Giskard", "platforms"),
    "openshift_ai": Product("Red Hat OpenShift AI and RHEL AI", "platforms"),
    "azure_ml": Product("Azure Machine Learning and AI Foundry", "platforms"),
    "sagemaker": Product("Amazon SageMaker Python SDK", "platforms"),
    "splunk_ai": Product("Splunk AI Toolkit", "platforms"),
    "backendai": Product("Backend.AI", "platforms"),
    "fedml": Product("FedML", "platforms"),
    "ibm_ai": Product("IBM Maximo AI Service and Engineering AI Hub",
                      "platforms"),
    # ------------------------------------------------------------- apps
    "openclaw": Product("OpenClaw", "apps"),
    "claw_family": Product("Other OpenClaw-style agents (NemoClaw, "
                           "PicoClaw, GoClaw, NanoClaw)", "apps"),
    "langchain": Product("LangChain (incl. LangGraph, LangSmith SDK)", "apps"),
    "llamaindex": Product("LlamaIndex", "apps"),
    "langflow": Product("Langflow", "apps"),
    "flowise": Product("Flowise", "apps"),
    "dify": Product("Dify", "apps"),
    "open_webui": Product("Open WebUI", "apps"),
    "gradio": Product("Gradio", "apps"),
    "comfyui": Product("ComfyUI", "apps"),
    "sd_webui": Product("Stable Diffusion web UIs (AUTOMATIC1111, "
                        "InvokeAI, stable-diffusion.cpp)", "apps"),
    "tg_webui": Product("text-generation-webui", "apps"),
    "anythingllm": Product("AnythingLLM", "apps"),
    "librechat": Product("LibreChat", "apps"),
    "lollms": Product("LoLLMs", "apps"),
    "lobechat": Product("Lobe Chat", "apps"),
    "nextchat": Product("NextChat", "apps"),
    "chuanhu": Product("ChuanhuChatGPT", "apps"),
    "gpt_academic": Product("GPT Academic", "apps"),
    "fastgpt": Product("FastGPT", "apps"),
    "ragflow": Product("RAGFlow", "apps"),
    "lightrag": Product("HKUDS projects (LightRAG, nanobot, OpenHarness)",
                        "apps"),
    "dbgpt": Product("DB-GPT", "apps"),
    "qanything": Product("QAnything and LobsterAI", "apps"),
    "chatchat": Product("Langchain-Chatchat", "apps"),
    "quivr": Product("Quivr", "apps"),
    "privategpt": Product("PrivateGPT and localGPT", "apps"),
    "danswer": Product("Danswer / Onyx", "apps"),
    "khoj": Product("Khoj", "apps"),
    "vanna": Product("Vanna", "apps"),
    "pandasai": Product("PandasAI", "apps"),
    "docsgpt": Product("DocsGPT", "apps"),
    "r2r": Product("R2R", "apps"),
    "pipeshub": Product("PipesHub", "apps"),
    "autogpt": Product("AutoGPT", "apps"),
    "superagi": Product("SuperAGI", "apps"),
    "devika": Product("Devika", "apps"),
    "metagpt": Product("MetaGPT", "apps"),
    "agentscope": Product("AgentScope", "apps"),
    "xagent": Product("XAgent", "apps"),
    "crewai": Product("CrewAI", "apps"),
    "letta": Product("Letta", "apps"),
    "praison": Product("PraisonAI", "apps"),
    "pydantic_ai": Product("Pydantic AI", "apps"),
    "composio": Product("Composio", "apps"),
    "griptape": Product("Griptape", "apps"),
    "pipecat": Product("Pipecat", "apps"),
    "spring_ai": Product("Spring AI", "apps"),
    "ash_ai": Product("Ash AI", "apps"),
    "astron": Product("Astron Agent", "apps"),
    "agent_zero": Product("Agent Zero", "apps"),
    "agent_s": Product("Agent-S", "apps"),
    "suna": Product("Suna", "apps"),
    "gpt_researcher": Product("GPT Researcher", "apps"),
    "local_deep_research": Product("Local Deep Research", "apps"),
    "hermes": Product("Hermes Agent and Hermes WebUI", "apps"),
    "cowagent": Product("chatgpt-on-wechat / CowAgent", "apps"),
    "mercury_agent": Product("Mercury Agent", "apps"),
    "network_ai": Product("Network-AI", "apps"),
    "omnigent": Product("Omnigent", "apps"),
    "deepchat": Product("DeepChat", "apps"),
    "rvc": Product("RVC voice conversion and GPT-SoVITS", "apps"),
    "ruoyi_ai": Product("ruoyi-ai", "apps"),
    "freegpt": Product("freegpt-webui", "apps"),
    "hexstrike": Product("HexStrike AI", "apps"),
    "claude_code": Product("Claude Code", "apps"),
    "cursor": Product("Cursor", "apps"),
    "openai_codex": Product("OpenAI Codex CLI and Desktop", "apps"),
    "gemini_cli": Product("Gemini CLI", "apps"),
    "mistral_vibe": Product("Mistral Vibe", "apps"),
    "aider": Product("Aider", "apps"),
    "kiro": Product("Kiro IDE", "apps"),
    "ms_copilot": Product("Microsoft Copilot and AI apps", "apps"),
    "salesforce_ai": Product("Salesforce Agentforce", "apps"),
    "deepseek": Product("DeepSeek tools", "apps"),
    "joyland": Product("Joyland.ai", "apps"),
    "vercel_ai": Product("Vercel AI SDK", "apps"),
    "jina_reader": Product("Jina Reader", "apps"),
    "deepwiki": Product("DeepWiki-Open", "apps"),
    "pptagent": Product("PPTAgent", "apps"),
    "drawio_ai": Product("next-ai-draw-io", "apps"),
    "notegen": Product("NoteGen", "apps"),
    "openclaude": Product("OpenClaude and Claude Code UI", "apps"),
    "atomic_agents": Product("Atomic Agents stack", "apps"),
    "boxlite": Product("BoxLite", "apps"),
    "summarize": Product("summarize (steipete)", "apps"),
    "sb_chatgpt": Product("springboot-openai-chatgpt", "apps"),
    "ai_video": Product("ai-fusion-video", "apps"),
    "deepfacelab": Product("DeepFaceLab", "apps"),
    "deloitte_ai": Product("Deloitte AI Assist for Customer", "apps"),
    "mcp_sdk": Product("Model Context Protocol SDKs and tools", "apps"),
    "mcp_servers": Product("Named MCP servers", "apps"),
}

# Normalised vendor -> ((product key, keywords), ...), tried in order. An
# empty keyword tuple takes every product of the vendor ("wholesale": the
# vendor's whole CVE footprint is that AI product). Keywords are
# whole-word phrases in the normalised product string.
RULES: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    # ---- frameworks -------------------------------------------------
    # The TensorFlow org also ships Keras (one certcc record files Keras
    # under vendor "tensorflow"), so Keras is tried first.
    "tensorflow": (("keras", ("keras",)), ("tensorflow", ())),
    "keras team": (("keras", ()),),
    "keras": (("keras", ()),),
    # Google: TensorFlow and Keras only — not Chrome/Android/Cloud; Gemini
    # CLI and the MCP Toolbox are named below.
    "google": (("keras", ("keras",)), ("tensorflow", ("tensorflow",)),
               ("gemini_cli", ("gemini cli",)),
               ("mcp_servers", ("mcp toolbox",))),
    "google llc": (("tensorflow", ("tensorflow",)),),
    "google cloud": (("mcp_servers", ("mcp toolbox", "cloud run mcp")),),
    "pytorch": (("torchserve", ("serve",)), ("pytorch", ())),
    "meta platforms inc": (("pytorch", ("executorch", "pytorch")),),
    "meta": (("pytorch", ("executorch", "pytorch")),),
    "lightning ai": (("pytorch", ()),),
    "pytorchlightning": (("pytorch", ()),),
    "onnx": (("onnx", ()),),
    "paddlepaddle": (("paddle", ()),),
    "baidu": (("paddle", ("paddle",)),),
    "huawei": (("mindspore", ("mindspore",)),),
    "mindspore": (("mindspore", ()),),
    "apache software foundation": (("mxnet", ("mxnet",)),
                                   ("opennlp", ("opennlp",))),
    "apache": (("mxnet", ("mxnet",)), ("opennlp", ("opennlp",))),
    "huggingface": (("tgi", ("text generation inference",
                             "text embeddings inference")),
                    ("hf_libs", ())),
    "hugging face": (("tgi", ("text generation inference",
                              "text embeddings inference")),
                     ("hf_libs", ())),
    "scikit learn": (("ml_libs", ()),),
    "lightgbm org": (("ml_libs", ()),),
    # NLTK ships pickled models and a data downloader; its CVEs are in
    # that machinery, so it counts as an NLP/ML library
    "nltk": (("nltk", ()),),
    "haotian liu": (("llava", ()),),
    "hiyouga": (("llama_factory", ()),),
    # NVIDIA: the ML software only — not GPU drivers, CUDA, DGX/Jetson
    # firmware or the Container Toolkit (general GPU compute).
    "nvidia": (("triton", ("triton",)),
               ("tensorrt", ("tensorrt",)),
               ("claw_family", ("nemoclaw",)),
               ("nvidia_nemo", ("nemo", "megatron", "merlin", "bionemo",
                                "isaac lab", "apex")),
               ("chatrtx", ("chatrtx",)),
               # NVIDIA's own copy of the Caffe framework
               ("nvidia_nemo", ("caffe",))),
    "nvidia corporation": (("triton", ("triton",)),
                           ("tensorrt", ("tensorrt",)),
                           ("nvidia_nemo", ("nemo", "megatron", "merlin"))),
    # Microsoft: the AI products the CNA lists as their own product —
    # not Windows/Edge/Office/VS Code. "copilot" is safe here only
    # because it is scoped to Microsoft (AWS Copilot CLI is not AI).
    "microsoft": (("onnxruntime", ("onnx runtime", "onnxruntime")),
                  ("deepspeed", ("deepspeed",)),
                  ("ml_libs", ("lightgbm",)),
                  ("azure_ml", ("azure machine learning", "azure ai foundry",
                                "azure ai studio")),
                  ("ms_copilot", ("copilot", "azure ai bot service",
                                  "semantic kernel", "autogen",
                                  "simplechat")),
                  ("pytorch", ("torchgeo",))),
    "microsoft corporation": (("onnxruntime", ("onnx runtime",
                                               "onnxruntime")),
                              ("ms_copilot", ("copilot",))),
    "amd": (("amd_ryzen_ai", ("ryzen ai software",)),),
    "intel": (("intel_ai", ("openvino", "neural compressor",
                            "extension for pytorch",
                            "extension for tensorflow",
                            "extension for transformers",
                            "llm library for pytorch")),),
    "intel corporation": (("intel_ai", ("openvino", "neural compressor")),),
    # ---- serving ----------------------------------------------------
    "vllm project": (("vllm", ()),),
    "ollama": (("ollama", ()),),
    "ggml org": (("llamacpp", ()),),
    "ggerganov": (("llamacpp", ()),),
    "llama cpp": (("llamacpp", ()),),
    "leejet": (("sd_webui", ("stable diffusion cpp",)),),
    "sgl project": (("sglang", ()),),
    "sglang": (("sglang", ()),),
    "internlm": (("lmdeploy", ("lmdeploy",)),),
    "modeltc": (("lightllm", ()),),
    "kvcache ai": (("mooncake", ()),),
    "mudler": (("localai", ()),),
    "go skynet": (("localai", ()),),
    "bentoml": (("bentoml", ()),),
    "ray project": (("ray", ()),),
    "anyscale": (("ray", ()),),
    "xorbitsai": (("xinference", ()),),
    "lm sys": (("fastchat", ()),),
    "berriai": (("litellm", ()),),
    "mlc ai": (("xgrammar", ()),),
    "chroma": (("vector_db", ()),),
    "chroma core": (("vector_db", ()),),
    "milvus io": (("vector_db", ()),),
    "qdrant": (("vector_db", ()),),
    "portkey ai": (("ai_gateway", ()),),
    "gitlab": (("ai_gateway", ("ai gateway",)),),
    # Red Hat: its AI products — OpenShift AI, RHEL AI, AI Inference
    # Server. Not RHEL, OpenShift Container Platform or Ansible, even
    # when a record lists an AI product further down (first-entry rule).
    "red hat": (("rh_inference", ("ai inference server",)),
                ("openshift_ai", ("openshift ai", "enterprise linux ai",
                                  "rhel ai", "rhoai"))),
    # IBM: Langflow (IBM became its CNA after acquiring DataStax), the
    # Watson speech and Maximo AI services, the MCP gateway — not
    # watsonx.data (a lakehouse), OpenPages "with Watson", AIX or RPA.
    "ibm": (("langflow", ("langflow",)),
            ("watson_speech", ("watson speech",)),
            ("ibm_ai", ("maximo ai service", "engineering ai hub")),
            ("mcp_sdk", ("contextforge", "context forge"))),
    "nvidia ai": (("nvidia_nemo", ()),),
    # ---- platforms --------------------------------------------------
    "mlflow": (("mlflow", ()),),
    "databricks": (("mlflow", ("mlflow",)),),
    "kubeflow": (("kubeflow", ()),),
    "allegroai": (("clearml", ()),),
    "allegro ai": (("clearml", ()),),
    "zenml io": (("zenml", ()),),
    "aimhubio": (("aim", ()),),
    "geyang": (("aim", ("ml logger",)),),
    # H2O.ai only: vendor "h2o" (GitHub_M) is the h2o HTTP server and
    # its quicly/picotls libraries, and "Kazuho Oku / H2O" is the same
    # server — neither is AI.
    "h2oai": (("h2o3", ()),),
    "humansignal": (("labelstudio", ()),),
    "heartexlabs": (("labelstudio", ()),),
    "cvat ai": (("cvat", ()),),
    "opencv": (("cvat", ("cvat",)),),
    "feast dev": (("feast", ()),),
    "polyaxon": (("polyaxon", ()),),
    "vertaai": (("modeldb", ()),),
    "lunary ai": (("lunary", ()),),
    "langfuse": (("langfuse", ()),),
    "uptrain ai": (("uptrain", ()),),
    "giskard ai": (("uptrain", ()),),
    "aws": (("sagemaker", ("sagemaker",)), ("kiro", ("kiro",)),
            ("mcp_servers", ("mcp",))),
    "amazon": (("sagemaker", ("sagemaker",)), ("mcp_servers", ("mcp",))),
    "splunk": (("splunk_ai", ("ai toolkit", "machine learning toolkit")),
               ("mcp_servers", ("mcp server",))),
    "lablup": (("backendai", ()),),
    "fedml ai": (("fedml", ()),),
    # ---- apps -------------------------------------------------------
    "openclaw": (("openclaw", ()),),
    "sipeed": (("claw_family", ("picoclaw",)),),
    "nextlevelbuilder": (("claw_family", ("goclaw",)),),
    "nanocoai": (("claw_family", ()),),
    "zevorn": (("claw_family", ("rt claw",)),),
    "dragonmonk111": (("claw_family", ("junoclaw",)),),
    "mf yang": (("claw_family", ("openclaw cn",)),),
    "mosaxiv": (("claw_family", ("clawlet",)),),
    "poco ai": (("claw_family", ("poco claw",)),),
    "8421bit": (("claw_family", ("miniclaw",)),),
    "langchain ai": (("langchain", ()),),
    "langchain": (("langchain", ()),),
    "run llama": (("llamaindex", ()),),
    "llamaindex": (("llamaindex", ()),),
    "langflow ai": (("langflow", ()),),
    "logspace ai": (("langflow", ()),),
    "langflow": (("langflow", ()),),
    "flowiseai": (("flowise", ()),),
    "flowise": (("flowise", ()),),
    "langgenius": (("dify", ()),),
    "open webui": (("open_webui", ()),),
    "gradio app": (("gradio", ()),),
    "gradio": (("gradio", ()),),
    "comfyanonymous": (("comfyui", ()),),
    "comfy org": (("comfyui", ()),),
    "automatic1111": (("sd_webui", ()),),
    "invoke ai": (("sd_webui", ()),),
    "oobabooga": (("tg_webui", ()),),
    "mintplex labs": (("anythingllm", ()),),
    "danny avila": (("librechat", ()),),
    "parisneo": (("lollms", ()),),
    "lobehub": (("lobechat", ()),),
    "chatgptnextweb": (("nextchat", ()),),
    "gaizhenbiao": (("chuanhu", ()),),
    "binary husky": (("gpt_academic", ()),),
    "gpt academic": (("gpt_academic", ()),),
    # FastGPT only — labring's laf and sealos are cloud platforms
    "labring": (("fastgpt", ("fastgpt",)),),
    "infiniflow": (("ragflow", ()),),
    "hkuds": (("lightrag", ()),),
    "eosphoros ai": (("dbgpt", ()),),
    "netease youdao": (("qanything", ()),),
    "chatchat space": (("chatchat", ()),),
    "stangirard": (("quivr", ()),),
    "quivrhq": (("quivr", ()),),
    "imartinez": (("privategpt", ()),),
    "zylon ai": (("privategpt", ()),),
    "promtengineer": (("privategpt", ()),),
    "danswer ai": (("danswer", ()),),
    "onyx dot app": (("danswer", ()),),
    "khoj ai": (("khoj", ()),),
    "vanna ai": (("vanna", ()),),
    "sinaptik ai": (("pandasai", ()),),
    "arc53": (("docsgpt", ()),),
    "sciphi ai": (("r2r", ()),),
    "pipeshub ai": (("pipeshub", ()),),
    "significant gravitas": (("autogpt", ()),),
    "transformeroptimus": (("superagi", ()),),
    "stitionai": (("devika", ()),),
    "foundationagents": (("metagpt", ()),),
    "foundation agents": (("metagpt", ()),),
    "geekan": (("metagpt", ()),),
    "modelscope": (("agentscope", ("agentscope",)),),
    "openbmb": (("xagent", ("xagent",)),),
    "crewai": (("crewai", ()),),
    "crewaiinc": (("crewai", ()),),
    "letta ai": (("letta", ()),),
    # PraisonAI only — the same author's WordPress plugin is not AI
    "mervinpraison": (("praison", ("praisonai", "praisonaiagents",
                                   "praisonai platform")),),
    "pydantic": (("pydantic_ai", ("pydantic ai",)),),
    "composiohq": (("composio", ()),),
    "griptape ai": (("griptape", ()),),
    "pipecat ai": (("pipecat", ()),),
    # Spring AI only — not Spring Framework/Boot/Security
    "spring": (("spring_ai", ("spring ai",)),),
    "vmware": (("spring_ai", ("spring ai",)),),
    "ash project": (("ash_ai", ("ash ai",)),),
    "iflytek": (("astron", ("astron agent",)),),
    "agent0ai": (("agent_zero", ()),),
    "simular ai": (("agent_s", ()),),
    "kortix ai": (("suna", ()),),
    "assafelovic": (("gpt_researcher", ()),),
    "learningcircuit": (("local_deep_research", ()),),
    "nousresearch": (("hermes", ()),),
    "nesquena": (("hermes", ("hermes",)),),
    "zhayujie": (("cowagent", ()),),
    "cosmicstack labs": (("mercury_agent", ()),),
    "jovancoding": (("network_ai", ()),),
    "omnigent ai": (("omnigent", ()),),
    "thinkinaixyz": (("deepchat", ()),),
    "rvc project": (("rvc", ()),),
    "rvc boss": (("rvc", ()),),
    "ageerle": (("ruoyi_ai", ()),),
    "ramon victor": (("freegpt", ()),),
    "0x4m4": (("hexstrike", ()),),
    "anthropics": (("claude_code", ("claude code",)),
                   ("mcp_sdk", ())),
    "anthropic": (("claude_code", ("claude code",)),),
    "cursor": (("cursor", ()),),
    "getcursor": (("cursor", ()),),
    "anysphere": (("cursor", ()),),
    "openai": (("openai_codex", ("codex",)),),
    "google gemini": (("gemini_cli", ()),),
    "mistralai": (("mistral_vibe", ("vibe",)),),
    "aider ai": (("aider", ()),),
    "salesforce": (("salesforce_ai", ("agentforce",)),),
    "deepseek ai": (("deepseek", ()),),
    "joyland": (("joyland", ()),),
    "vercel": (("vercel_ai", ("ai",)),),
    "jina ai": (("jina_reader", ("reader",)),),
    "asyncfuncai": (("deepwiki", ()),),
    "icip cas": (("pptagent", ("pptagent",)),),
    "dayuanjiang": (("drawio_ai", ("next ai draw io",)),),
    "codexu": (("notegen", ("notegen",)),),
    "gitlawb": (("openclaude", ()),),
    "siteboon": (("openclaude", ("claudecodeui",)),),
    "dep0we": (("atomic_agents", ()),),
    "boxlite ai": (("boxlite", ()),),
    "steipete": (("summarize", ("summarize",)),),
    "274056675": (("sb_chatgpt", ("chatgpt",)),),
    "stonewuu": (("ai_video", ("ai fusion video",)),),
    "deloitte": (("deloitte_ai", ("ai assist",)),),
    "modelcontextprotocol": (("mcp_sdk", ()),),
    "jlowin": (("mcp_sdk", ("fastmcp",)),),
    "prefecthq": (("mcp_sdk", ("fastmcp",)),),
    "agentfront": (("mcp_sdk", ()),),
    # third-party MCP servers with at least three records at review
    "sooperset": (("mcp_servers", ("mcp atlassian",)),),
    "czlonkowski": (("mcp_servers", ("n8n mcp",)),),
    "samanhappy": (("mcp_servers", ("mcphub",)),),
    "ondata": (("mcp_servers", ("mcp",)),),
    "flux159": (("mcp_servers", ("mcp",)),),
    "wonderwhy er": (("mcp_servers", ("desktopcommandermcp",)),),
    "doobidoo": (("mcp_servers", ("mcp",)),),
    "ihor sokoliuk": (("mcp_servers", ("mcp",)),),
    "ahujasid": (("mcp_servers", ("mcp",)),),
    "dbt labs": (("mcp_servers", ("dbt mcp",)),),
    "pipeboard co": (("mcp_servers", ("mcp",)),),
    "zcaceres": (("mcp_servers", ("mcp",)),),
    "noctedefensor": (("mcp_servers", ("ludusmcp",)),),
    "mastergo design": (("mcp_servers", ("mcp",)),),
    "zereight": (("mcp_servers", ("mcp",)),),
    "sonirico": (("mcp_servers", ("mcp",)),),
}

# Distinctive product names for entries no vendor rule covers. Under a
# placeholder vendor (VulDB files "n/a" / "PyTorch"; Intel files "n/a" /
# "Intel(R) Neural Compressor software") the name may appear anywhere in
# the product string as a whole-word phrase; under any other vendor the
# product string must BE the name ("Ollama AI" / "Ollama", "vLLM" /
# "vLLM"), so a third-party "nuxt-ollama" or "sherpa-onnx" is not filed
# under the upstream project. Only names that are not also the name of
# some other software: never "ray", "triton", "aim", "h2o", "agent",
# "copilot" or "mistral" (OpenStack Mistral is a workflow service).
BARE_NAMES: tuple[tuple[str, str], ...] = (
    # Intel files its framework extensions under vendor "n/a"; their
    # names contain "PyTorch"/"TensorFlow", so they are tried first.
    ("extension for pytorch", "intel_ai"),
    ("llm library for pytorch", "intel_ai"),
    ("oneccl bindings for pytorch", "intel_ai"),
    ("extension for tensorflow", "intel_ai"),
    ("optimization for tensorflow", "intel_ai"),
    ("extension for transformers", "intel_ai"),
    ("tensorflow", "tensorflow"),
    ("pytorch", "pytorch"),
    ("mindspore", "mindspore"),
    ("paddlepaddle", "paddle"),
    ("onnx", "onnx"),
    ("openvino", "intel_ai"),
    ("neural compressor", "intel_ai"),
    ("comfyui", "comfyui"),
    ("ollama", "ollama"),
    ("vllm", "vllm"),
    ("mlflow", "mlflow"),
    ("langflow", "langflow"),
    ("openclaw", "openclaw"),
    ("deeppavlov", "ml_libs"),
    ("deepfacelab", "deepfacelab"),
)



def _has(text: str, phrase: str) -> bool:
    return f" {phrase} " in f" {text} "


def classify(vendor: object, product: object) -> str | None:
    """Product key for one affected entry, or None when it is not an AI
    product (or not one the table names)."""
    v, p = normalize(vendor), normalize(product)
    for key, keywords in RULES.get(v, ()):
        if not keywords or any(_has(p, kw) for kw in keywords):
            return key
    placeholder = v in _PLACEHOLDERS
    for phrase, key in BARE_NAMES:
        if p == phrase or (placeholder and _has(p, phrase)):
            return key
    return None


def first_entry(record: dict) -> tuple[str, str] | None:
    """(vendor, product) of the first affected entry in the CNA container
    with a non-placeholder vendor or product — the entry the classifier
    reads. None when the CNA named no product at all."""
    cna = (record.get("containers") or {}).get("cna") or {}
    affected = cna.get("affected")
    if not isinstance(affected, list):
        return None
    for entry in affected:
        if not isinstance(entry, dict):
            continue
        vendor, product = entry.get("vendor"), entry.get("product")
        vendor = vendor if isinstance(vendor, str) else ""
        product = product if isinstance(product, str) else ""
        if normalize(vendor) not in _PLACEHOLDERS or \
                normalize(product) not in _PLACEHOLDERS:
            return vendor, product
    return None


def classify_record(record: dict) -> tuple[str | None, bool]:
    """(product key or None, named) for one cvelistV5 record. ``named`` is
    False when the CNA container names no usable vendor or product, so
    the record could not have been classified either way."""
    entry = first_entry(record)
    if entry is None:
        return None, False
    return classify(*entry), True


def category_of(key: str) -> str:
    return PRODUCTS[key].category


def rule_count() -> int:
    """Vendor rules plus bare names — emitted beside CLASSIFIER_VERSION."""
    return sum(len(r) for r in RULES.values()) + len(BARE_NAMES)
