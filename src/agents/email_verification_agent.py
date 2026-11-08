"""
Email Verification Agent
========================
A hybrid phishing-detection pipeline combining:
  FAISS vector similarity  (35%)
  RegEx symbolic analysis  (30%)
  DNS validation           (20%)
  LLaMA 3.3-70B via Groq  (15%)

Usage from main.py
------------------
    from email_verification_agent import initialize, email_verification_agent

    initialize(
        groq_api_key   = "gsk_...",
        vdb_index_path = "path/to/email_vdb.index",
        train_texts    = "path/to/train_email_texts.npy",
        train_labels   = "path/to/train_email_labels.npy",
    )

    report = email_verification_agent(email_text, verbose=True)
    print(report["risk_verdict"], report["risk_score"])
"""

# ── Standard library ───────────────────────────────────────────────────────────
import os
import re
import json
import time
import urllib.parse
from email import message_from_string
from itertools import product

# ── Third-party ────────────────────────────────────────────────────────────────
import faiss
import numpy as np
import dns.resolver
import tldextract
from groq import Groq
from sentence_transformers import SentenceTransformer

# ── Shared memory module ────────────────────────────────────────────────────────
import sys as _sys, os as _os
_sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
try:
    from agent_memory import get_memory as _get_memory
    _MEMORY_AVAILABLE = True
except ImportError:
    _MEMORY_AVAILABLE = False
from textblob import TextBlob

# sklearn is only needed for batch_evaluate / evaluate_ood helpers
try:
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score, f1_score,
        confusion_matrix,
    )
    import pandas as pd
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


# ══════════════════════════════════════════════════════════════════════════════
# 1.  CONFIGURATION  (override via initialize() kwargs)
# ══════════════════════════════════════════════════════════════════════════════

LLM_MODEL               = "llama-3.3-70b-versatile"
EMBEDDING_MODEL         = "all-MiniLM-L6-v2"
MAX_TOKENS              = 1200
TEMPERATURE             = 0.1

FAISS_SIMILARITY_THRESHOLD = 0.75
HIGH_RISK_SCORE            = 0.70
MEDIUM_RISK_SCORE          = 0.45

CALL_DELAY    = 2.0
BATCH_PAUSE   = 15.0
TOKEN_BUDGET  = 5500

# ── Module-level singletons (populated by initialize()) ───────────────────────
_groq_client      = None
_embedder         = None
_faiss_index      = None
_vector_db_texts  = []
_vector_db_labels = []
_call_counter     = 0
_total_tokens     = 0


def initialize(
    groq_api_key: str,
    vdb_index_path: str,
    train_texts_path: str,
    train_labels_path: str,
    embedding_model: str = EMBEDDING_MODEL,
):
    """
    Load all heavy resources once.  Call this before using any other function.

    Parameters
    ----------
    groq_api_key        : Groq API key (string).
    vdb_index_path      : Path to the FAISS .index file.
    train_texts_path    : Path to train_email_texts.npy
    train_labels_path   : Path to train_email_labels.npy
    embedding_model     : Sentence-transformer model name (default: all-MiniLM-L6-v2).
    """
    global _groq_client, _embedder, _faiss_index
    global _vector_db_texts, _vector_db_labels

    # Groq client
    os.environ["GROQ_API_KEY"] = groq_api_key
    _groq_client = Groq(api_key=groq_api_key)

    # FAISS index
    print("🔄 Loading FAISS index...")
    _faiss_index = faiss.read_index(vdb_index_path)
    print(f"  ✅ FAISS index | Vectors: {_faiss_index.ntotal} | Dim: {_faiss_index.d}")

    # Datasets
    train_texts  = np.load(train_texts_path,  allow_pickle=True)
    train_labels = np.load(train_labels_path, allow_pickle=True)
    _vector_db_texts  = list(train_texts)
    _vector_db_labels = list(train_labels)
    print(f"  ✅ Training set loaded: {len(_vector_db_texts):,} emails")

    # Sentence embedder
    print("🔄 Loading sentence transformer...")
    _embedder = SentenceTransformer(embedding_model)
    print(f"  ✅ Embedder ready: {embedding_model}")

    # Build typosquat index
    print("🔨 Building typosquat index...")
    _build_typosquat_index()
    print(f"  ✅ {len(set(BRAND_LIST))} brands → {len(TYPOSQUAT_SET):,} variants")


# ══════════════════════════════════════════════════════════════════════════════
# 2.  TYPOSQUAT / BRAND SPOOFING
# ══════════════════════════════════════════════════════════════════════════════

HOMOGLYPH_MAP = {
    "o" : ["0"],
    "l" : ["1", "i"],
    "i" : ["1", "l"],
    "e" : ["3"],
    "a" : ["4", "@"],
    "s" : ["5"],
    "g" : ["9"],
    "rn": ["m"],
}

COMMON_SUFFIXES = [
    "-secure", "-login", "-verify", "-support", "-online",
    "-account", "-update", "-service", "-help", "-alert",
]

BRAND_LIST = [
    # Tech / Software / Productivity
    "google", "microsoft", "apple", "adobe", "oracle", "salesforce",
    "zoom", "slack", "dropbox", "docusign", "intuit", "quickbooks",
    "github", "atlassian", "notion", "figma", "canva", "trello",
    "asana", "monday", "hubspot", "zendesk", "freshdesk", "intercom",
    "twilio", "sendgrid", "mailchimp", "wordpress", "wix", "squarespace",
    # Email
    "gmail", "yahoo", "outlook", "hotmail", "icloud", "protonmail",
    "zoho", "fastmail", "aol",
    # Banking / Finance
    "paypal", "chase", "wellsfargo", "bankofamerica", "citibank",
    "barclays", "hsbc", "lloyds", "natwest", "santander",
    "capitalone", "americanexpress", "amex", "mastercard", "visa",
    "stripe", "square", "zelle", "venmo", "cashapp", "wise", "revolut",
    "ally", "schwab", "fidelity", "vanguard", "etrade",
    "usbank", "pnc", "regions", "truist",
    "geico", "progressive", "statefarm", "allstate",
    "aetna", "cigna", "humana",
    "westpac", "anz", "nab", "icici", "hdfc", "sbi",
    # E-Commerce
    "amazon", "ebay", "walmart", "target", "etsy", "shopify",
    "aliexpress", "wish", "bestbuy", "costco", "ikea",
    "flipkart", "myntra", "nykaa", "lazada", "shopee", "rakuten",
    "asos", "nike", "adidas", "macys", "nordstrom", "newegg", "wayfair",
    # Social
    "facebook", "instagram", "twitter", "linkedin", "tiktok",
    "snapchat", "pinterest", "reddit", "discord", "whatsapp", "telegram",
    "tumblr", "threads",
    # Streaming / Gaming
    "netflix", "spotify", "hulu", "disneyplus", "youtube",
    "twitch", "primevideo", "hbomax", "peacock", "paramount",
    "steam", "epicgames", "roblox", "playstation", "xbox", "nintendo",
    "ea", "ubisoft", "blizzard", "activision",
    # Travel
    "airbnb", "booking", "expedia", "tripadvisor",
    "kayak", "skyscanner", "makemytrip",
    "delta", "united", "southwest", "jetblue", "ryanair", "emirates",
    "marriott", "hilton", "hyatt",
    "uber", "lyft", "ola", "grab",
    "ticketmaster", "eventbrite",
    # Food
    "doordash", "ubereats", "grubhub", "instacart",
    "swiggy", "zomato",
    "dominos", "pizzahut", "mcdonalds", "starbucks",
    # Cloud / Hosting
    "amazonaws", "azure", "googlecloud", "cloudflare", "godaddy",
    "namecheap", "bluehost", "digitalocean", "heroku",
    "netlify", "vercel", "fastly", "akamai",
    # Crypto
    "coinbase", "binance", "kraken", "gemini", "metamask",
    "ledger", "trezor", "opensea", "robinhood",
    "kucoin", "bybit", "okx", "bitfinex",
    "phantom", "trustwallet", "exodus",
    # Delivery
    "fedex", "ups", "dhl", "usps", "royalmail", "auspost",
    "canadapost", "dpd", "aramex", "delhivery",
    # Telecom
    "att", "verizon", "tmobile", "comcast", "xfinity",
    "spectrum", "bt", "vodafone", "orange", "airtel", "jio",
    "telstra", "optus", "rogers", "bell", "telus",
    # Govt / Tax
    "irs", "hmrc", "gov", "medicare", "socialsecurity", "nhs",
    "uidai", "epfo", "incometax",
    # Education
    "coursera", "udemy", "edx", "duolingo", "byju", "chegg",
    # HR / Jobs
    "indeed", "glassdoor", "naukri", "linkedin", "upwork", "fiverr",
    "workday", "bamboohr", "adp",
    # Real Estate
    "zillow", "redfin", "realtor", "trulia",
    # Automotive
    "tesla", "carvana", "carmax", "autotrader",
]

TYPOSQUAT_SET: set  = set()
BRAND_MAP: dict     = {}


def _homoglyph_variants(brand: str) -> set:
    segments = []
    i = 0
    while i < len(brand):
        matched = False
        for orig in sorted(HOMOGLYPH_MAP.keys(), key=len, reverse=True):
            if brand[i: i + len(orig)] == orig:
                segments.append([orig] + HOMOGLYPH_MAP[orig])
                i += len(orig)
                matched = True
                break
        if not matched:
            ch = brand[i]
            segments.append([ch] + HOMOGLYPH_MAP.get(ch, []))
            i += 1
    results = {"".join(combo) for combo in product(*segments)}
    results.discard(brand)
    return results


def _generate_variants(brand: str) -> set:
    variants = set()
    variants.update(_homoglyph_variants(brand))
    for i, ch in enumerate(brand):
        variants.add(brand[:i] + ch + brand[i:])
    for i in range(len(brand)):
        v = brand[:i] + brand[i + 1:]
        if len(v) >= 3:
            variants.add(v)
    for i in range(len(brand) - 1):
        s = list(brand)
        s[i], s[i + 1] = s[i + 1], s[i]
        variants.add("".join(s))
    for i in range(2, len(brand) - 1):
        variants.add(brand[:i] + "-" + brand[i:])
    for suffix in COMMON_SUFFIXES:
        variants.add(brand + suffix)
    variants.discard(brand)
    variants.discard("")
    return variants


def _build_index(brands: list) -> tuple:
    ts, bm = set(), {}
    for brand in set(brands):
        if len(brand) >= 3:
            for v in _generate_variants(brand):
                ts.add(v)
                bm[v] = brand
    return ts, bm


def _build_typosquat_index():
    global TYPOSQUAT_SET, BRAND_MAP
    TYPOSQUAT_SET, BRAND_MAP = _build_index(BRAND_LIST)


def update_brand_list(new_brands: list):
    """Add new brands to the typosquat index and rebuild instantly."""
    global BRAND_LIST, TYPOSQUAT_SET, BRAND_MAP
    added = [b.lower().strip() for b in new_brands
             if b.lower().strip() not in BRAND_LIST]
    if not added:
        print("ℹ️  All brands already in list — no update needed.")
        return
    BRAND_LIST.extend(added)
    TYPOSQUAT_SET, BRAND_MAP = _build_index(BRAND_LIST)
    print(f"✅ Added {len(added)} brand(s): {added}")
    print(f"   Total brands: {len(set(BRAND_LIST))} → {len(TYPOSQUAT_SET):,} variants")


# ══════════════════════════════════════════════════════════════════════════════
# 3.  REGEX / SYMBOLIC TOOLS
# ══════════════════════════════════════════════════════════════════════════════

SUSPICIOUS_KEYWORDS = [
    r"\b(urgent|immediately|verify|confirm|suspended|limited|restricted|unusual.activity)\b",
    r"\b(click.here|act.now|expires?|deadline|hours?|24h|48h)\b",
    r"\b(password|credentials|login|account|bank|credit.card|social.security|ssn)\b",
    r"\b(prize|winner|congratulations|lottery|claim|reward|gift|free)\b",
    r"\b(update.your|verify.your|confirm.your|validate.your)\b",
]

URL_PATTERN   = re.compile(
    r"http[s]?://(?:[a-zA-Z]|[0-9]|[$\-_@.&+!*(),]|(?:%[0-9a-fA-F]{2}))+",
    re.IGNORECASE,
)
PHONE_PATTERN = re.compile(
    r"(\+?1?[\s.\-]?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4})"
)


def extract_metadata(email_text: str) -> dict:
    meta = {"sender_domain": None, "reply_to": None, "subject": None,
            "urls": [], "has_html": False}
    try:
        msg = message_from_string(email_text)
        from_field = msg.get("From", "")
        m = re.search(r"@([\w.\-]+)", from_field)
        if m:
            meta["sender_domain"] = m.group(1).lower()
        meta["reply_to"] = msg.get("Reply-To", "")
        meta["subject"]  = msg.get("Subject", "")
        body = str(msg.get_payload() or email_text)
        meta["urls"]     = URL_PATTERN.findall(body)
        meta["has_html"] = bool(re.search(r"<html|<body|<a href", body, re.IGNORECASE))
    except Exception:
        meta["urls"] = URL_PATTERN.findall(email_text)
    return meta


def extract_domain_info(url: str) -> dict:
    try:
        ext = tldextract.extract(url)
        return {
            "subdomain": ext.subdomain,
            "domain": ext.domain,
            "suffix": ext.suffix,
            "full_domain": ext.top_domain_under_public_suffix,
        }
    except Exception as e:
        return {"error": str(e), "full_domain": ""}


def _check_brand_spoofing(domain: str) -> tuple:
    if not domain:
        return False, None
    base = domain.split(".")[0].lower()
    if base in TYPOSQUAT_SET:
        return True, BRAND_MAP.get(base)
    if domain.lower() in TYPOSQUAT_SET:
        return True, BRAND_MAP.get(domain.lower())
    return False, None


def regex_symbolic_analysis(email_text: str) -> dict:
    """
    Return keyword hits, brand-spoofing hits, suspicious URLs,
    and phone numbers found in the email.
    """
    text_lower = email_text.lower()
    results = {
        "suspicious_keyword_hits": [],
        "brand_spoofing_hits":     [],
        "suspicious_urls":         [],
        "phone_numbers":           [],
    }

    for p in SUSPICIOUS_KEYWORDS:
        results["suspicious_keyword_hits"].extend(
            re.findall(p, text_lower, re.IGNORECASE)
        )

    domains_to_check = set()
    metadata = extract_metadata(email_text)
    if metadata.get("sender_domain"):
        domains_to_check.add(metadata["sender_domain"])
    for url in URL_PATTERN.findall(email_text):
        d = extract_domain_info(url).get("full_domain", "")
        if d:
            domains_to_check.add(d)

    for domain in domains_to_check:
        is_spoof, brand = _check_brand_spoofing(domain)
        if is_spoof:
            results["brand_spoofing_hits"].append(
                {"domain": domain, "impersonates": brand}
            )

    for url in URL_PATTERN.findall(email_text):
        parsed = urllib.parse.urlparse(url)
        d = parsed.netloc.lower()
        if any([
            bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", d)),
            len(d) > 50,
            d.count("-") > 3,
            d.count(".") > 5,
            bool(re.search(r"(login|secure|verify|update|confirm)", d)),
        ]):
            results["suspicious_urls"].append(url)

    results["phone_numbers"] = PHONE_PATTERN.findall(email_text)
    return results


def dns_validate_domain(domain: str, timeout: float = 2.0) -> dict:
    result = {"valid": False, "has_mx": False, "has_spf": False,
              "resolves": False, "suspicious": False, "reason": ""}
    if not domain or len(domain) < 4:
        result["reason"] = "Invalid domain"
        return result
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout  = timeout
        resolver.lifetime = timeout
        try:
            resolver.resolve(domain, "A")
            result["resolves"] = result["valid"] = True
        except Exception:
            result["suspicious"] = True
            result["reason"]     = "Domain does not resolve"
            return result
        try:
            resolver.resolve(domain, "MX")
            result["has_mx"] = True
        except Exception:
            pass
        try:
            for r in resolver.resolve(domain, "TXT"):
                if "v=spf1" in str(r):
                    result["has_spf"] = True
                    break
        except Exception:
            pass
        if result["resolves"] and not result["has_mx"] and not result["has_spf"]:
            result["suspicious"] = True
            result["reason"]     = "No MX/SPF — possible spoofed sender"
    except Exception as e:
        result["reason"] = str(e)[:80]
    return result


def sentiment_analysis(email_text: str) -> dict:
    try:
        clean = re.sub(r"<[^>]+>", " ", email_text)
        clean = re.sub(r"http\S+", " ", clean).strip()[:2000]
        blob  = TextBlob(clean)
        pol, sub = blob.sentiment.polarity, blob.sentiment.subjectivity
        return {
            "polarity":     round(pol, 3),
            "subjectivity": round(sub, 3),
            "tone": ("negative" if pol < -0.2 else "positive" if pol > 0.2 else "neutral"),
        }
    except Exception as e:
        return {"error": str(e), "polarity": 0, "subjectivity": 0, "tone": "neutral"}


# ══════════════════════════════════════════════════════════════════════════════
# 4.  FAISS / EMBEDDING
# ══════════════════════════════════════════════════════════════════════════════

def encode_email(email_text: str) -> np.ndarray:
    if _embedder is None:
        raise RuntimeError("Call initialize() before using encode_email().")
    clean = re.sub(r"<[^>]+>", " ", str(email_text))
    clean = re.sub(r"\s+", " ", clean).strip()[:512]
    return _embedder.encode([clean], normalize_embeddings=True).astype("float32")


def faiss_similarity_search(email_text: str, top_k: int = 5) -> dict:
    if _faiss_index is None:
        raise RuntimeError("Call initialize() before using faiss_similarity_search().")
    embedding = encode_email(email_text)
    distances, indices = _faiss_index.search(embedding, top_k)

    results, phish_count, total_valid = [], 0, 0
    _phish_labels = {"1", "spam", "phishing", "fraud", "1.0"}

    for dist, idx in zip(distances[0], indices[0]):
        if idx < 0 or idx >= len(_vector_db_texts):
            continue
        label   = str(_vector_db_labels[idx])
        snippet = str(_vector_db_texts[idx])[:200]
        results.append({
            "index":      int(idx),
            "similarity": round(float(dist), 4),
            "label":      label,
            "snippet":    snippet,
        })
        total_valid += 1
        if label in _phish_labels:
            phish_count += 1

    phishing_ratio = phish_count / total_valid if total_valid > 0 else 0.5
    total_sim = sum(r["similarity"] for r in results)
    weighted_phish = (
        sum(
            r["similarity"] * (1 if r["label"] in _phish_labels else 0)
            for r in results
        ) / total_sim
        if total_sim > 0
        else 0.5
    )

    return {
        "top_k_results":          results,
        "phishing_ratio":         round(phishing_ratio, 3),
        "weighted_phishing_score": round(weighted_phish, 3),
        "avg_similarity":         round(float(np.mean([r["similarity"] for r in results])) if results else 0, 4),
        "is_likely_phishing":     weighted_phish > FAISS_SIMILARITY_THRESHOLD,
    }


def get_rag_context(email_text: str, top_k: int = 3) -> str:
    res   = faiss_similarity_search(email_text, top_k=top_k)
    parts = []
    _phish_labels = {"1", "spam", "phishing", "1.0"}
    for i, r in enumerate(res["top_k_results"][:3], 1):
        label_str = "PHISHING/SPAM" if r["label"] in _phish_labels else "LEGITIMATE"
        parts.append(
            f'[Similar Email {i} — {label_str} | Similarity: {r["similarity"]:.3f}]\n{r["snippet"]}...'
        )
    return "\n\n".join(parts)


# ══════════════════════════════════════════════════════════════════════════════
# 5.  LLM (GROQ)
# ══════════════════════════════════════════════════════════════════════════════

def build_rag_prompt(
    email_text, metadata, regex_results, faiss_results, sentiment, dns_results, rag_context
) -> str:
    dns_summary = ""
    for d in dns_results[:3]:
        dns_summary += (
            f"  - {d.get('domain','?')} | Resolves: {d.get('resolves','?')} "
            f"| MX: {d.get('has_mx','?')} | SPF: {d.get('has_spf','?')} "
            f"| Suspicious: {d.get('suspicious','?')}\n"
        )

    return f"""You are an expert cybersecurity analyst specializing in email phishing detection.

=== RETRIEVED CONTEXT (Similar Emails from Vector DB) ===
{rag_context if rag_context else 'No similar emails found.'}

=== EMAIL UNDER ANALYSIS ===
{email_text[:1500]}

=== PRE-PROCESSED SIGNALS ===

METADATA:
  Sender Domain : {metadata.get('sender_domain', 'Unknown')}
  Reply-To      : {metadata.get('reply_to', 'None')}
  Subject       : {metadata.get('subject', 'None')}
  HTML Content  : {metadata.get('has_html', False)}
  Embedded URLs : {len(metadata.get('urls', []))}

REGEX SYMBOLIC ANALYSIS:
  Suspicious Keywords : {regex_results.get('suspicious_keyword_hits', [])[:8]}
  Brand Spoofing      : {regex_results.get('brand_spoofing_hits', [])}
  Suspicious URLs     : {regex_results.get('suspicious_urls', [])[:3]}
  Phone Numbers       : {regex_results.get('phone_numbers', [])[:3]}

FAISS VECTOR SEARCH:
  Weighted Phishing Score  : {faiss_results.get('weighted_phishing_score', 0):.3f}
  Phishing Neighbor Ratio  : {faiss_results.get('phishing_ratio', 0):.2f}
  Similar to Known Phishing: {faiss_results.get('is_likely_phishing', False)}

SENTIMENT ANALYSIS (TextBlob):
  Polarity      : {sentiment.get('polarity', 0)}  (-1.0 very negative → +1.0 very positive)
  Subjectivity  : {sentiment.get('subjectivity', 0)}  (0.0 objective → 1.0 subjective)
  Tone          : {sentiment.get('tone', 'neutral')}

DNS VALIDATION:
{dns_summary if dns_summary else '  No domains validated.'}

=== CHAIN-OF-THOUGHT INSTRUCTIONS ===
STEP 1 - STRUCTURAL ANALYSIS: Analyze sender domain, reply-to mismatch, HTML usage.
STEP 2 - CONTENT ANALYSIS: Evaluate keywords, brand impersonation, phone numbers, language urgency.
STEP 3 - TECHNICAL INDICATORS: Assess URL patterns, DNS validity, domain anomalies.
STEP 4 - SIMILARITY ASSESSMENT: Compare with retrieved similar emails from the vector DB.
STEP 5 - SENTIMENT ASSESSMENT: Interpret polarity/subjectivity — manipulative framing is a phishing indicator.
STEP 6 - FINAL SYNTHESIS: Combine all signals into a final risk verdict.

=== OUTPUT FORMAT (JSON ONLY — no text outside the JSON) ===
{{
  "step1_structural"  : "<structural analysis>",
  "step2_content"     : "<content analysis>",
  "step3_technical"   : "<technical analysis>",
  "step4_similarity"  : "<similarity assessment>",
  "step5_sentiment"   : "<sentiment interpretation>",
  "step6_synthesis"   : "<final reasoning>",
  "risk_verdict"      : "<SAFE | SUSPICIOUS | PHISHING>",
  "confidence_score"  : <0.0-1.0>,
  "risk_score"        : <0.0-1.0>,
  "key_indicators"    : ["<indicator1>", "<indicator2>", "<indicator3>"],
  "justification"     : "<2-3 sentence analyst summary>",
  "recommended_action": "<ALLOW | QUARANTINE | BLOCK>"
}}"""


def call_llm(prompt: str) -> dict:
    global _call_counter, _total_tokens
    if _groq_client is None:
        raise RuntimeError("Call initialize() before using call_llm().")

    _call_counter += 1
    _total_tokens += len(prompt) // 4 + MAX_TOKENS

    if _call_counter % 10 == 0:
        print(f"  ⏳ [{_call_counter} calls | ~{_total_tokens} tokens] — pausing {BATCH_PAUSE}s...")
        time.sleep(BATCH_PAUSE)
    else:
        time.sleep(CALL_DELAY)

    def _make_call():
        return _groq_client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {
                    "role":    "system",
                    "content": (
                        "You are a cybersecurity expert. "
                        "Respond ONLY with a valid JSON object. No markdown, no preamble."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens  = MAX_TOKENS,
            temperature = TEMPERATURE,
        )

    for attempt in range(3):
        try:
            response = _make_call()
            raw = response.choices[0].message.content.strip()
            raw = re.sub(r"^```(?:json)?\n?", "", raw)
            raw = re.sub(r"\n?```$",          "", raw)
            return {"success": True, "result": json.loads(raw), "raw": raw}
        except Exception as e:
            err = str(e)
            if "429" in err or "rate_limit" in err.lower():
                wait = 60 * (attempt + 1)
                print(f"  🚫 Rate limit (attempt {attempt+1}/3) — sleeping {wait}s...")
                time.sleep(wait)
            elif "JSONDecodeError" in type(e).__name__ or "json" in err.lower():
                return {"success": False, "error": f"JSON parse: {e}", "raw": locals().get("raw", "")}
            else:
                return {"success": False, "error": err, "raw": ""}

    return {"success": False, "error": "Rate limit — all 3 retries exhausted", "raw": ""}


# ══════════════════════════════════════════════════════════════════════════════
# 6.  HYBRID RISK SCORE
# ══════════════════════════════════════════════════════════════════════════════

def compute_hybrid_risk_score(regex_results, faiss_results, dns_results, llm_result) -> dict:
    """
    Weights (sum = 1.0):
      FAISS  35%  — vector similarity to known phishing/legitimate
      RegEx  30%  — symbolic signals: keywords, brand spoofing, URLs
      DNS    20%  — domain validity, MX/SPF checks
      LLM    15%  — semantic synthesis (includes sentiment interpretation)
    """
    faiss_score = faiss_results.get("weighted_phishing_score", 0.5)

    kw  = len(regex_results.get("suspicious_keyword_hits", []))
    br  = len(regex_results.get("brand_spoofing_hits", []))
    url = len(regex_results.get("suspicious_urls", []))
    regex_score = min(kw * 0.06 + br * 0.25 + url * 0.15, 1.0)

    dns_suspicious = sum(1 for d in dns_results if d.get("suspicious", False))
    dns_score      = min(dns_suspicious * 0.33, 1.0)

    if llm_result.get("success") and "result" in llm_result:
        llm_score = float(llm_result["result"].get("risk_score", 0.5))
    else:
        llm_score = (faiss_score + regex_score) / 2.0

    final_score = (
        0.35 * faiss_score +
        0.30 * regex_score +
        0.20 * dns_score   +
        0.15 * llm_score
    )

    if final_score >= HIGH_RISK_SCORE:
        risk_label, action = "PHISHING",   "BLOCK"
    elif final_score >= MEDIUM_RISK_SCORE:
        risk_label, action = "SUSPICIOUS", "QUARANTINE"
    else:
        risk_label, action = "SAFE",       "ALLOW"

    # High-confidence LLM override
    if llm_result.get("success") and "result" in llm_result:
        llm_verdict    = llm_result["result"].get("risk_verdict", "").upper()
        llm_confidence = float(llm_result["result"].get("confidence_score", 0))
        if llm_confidence >= 0.85 and llm_verdict in ("SAFE", "SUSPICIOUS", "PHISHING"):
            risk_label = llm_verdict
            action     = {"SAFE": "ALLOW", "SUSPICIOUS": "QUARANTINE", "PHISHING": "BLOCK"}[llm_verdict]

    return {
        "final_risk_score":   round(final_score, 4),
        "risk_label":         risk_label,
        "recommended_action": action,
        "component_scores": {
            "faiss": round(faiss_score, 4),
            "regex": round(regex_score, 4),
            "dns":   round(dns_score,   4),
            "llm":   round(llm_score,   4),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# 7.  MAIN AGENT
# ══════════════════════════════════════════════════════════════════════════════

def email_verification_agent(email_text: str, verbose: bool = True) -> dict:
    """
    Full pipeline:
      Pre-processing → FAISS → Symbolic Analysis → RAG+LLM → Risk Report

    Returns a dict with keys:
      risk_verdict, risk_score, recommended_action, component_scores,
      metadata, regex_analysis, faiss_analysis, sentiment_analysis,
      dns_validation, llm_analysis, llm_success, processing_time_sec
    """
    start = time.time()

    if verbose:
        print("\n" + "=" * 60)
        print("🔍 EMAIL VERIFICATION AGENT")
        print("=" * 60)

    # 1 — Metadata
    if verbose: print("\n[1/5] 📋 Extracting metadata...")
    metadata = extract_metadata(email_text)

    # 2 — FAISS + RAG
    if verbose: print("[2/5] 🔍 FAISS vector search + RAG context...")
    faiss_results = faiss_similarity_search(email_text, top_k=5)
    rag_context   = get_rag_context(email_text, top_k=3)

    # 3 — Symbolic analysis
    if verbose: print("[3/5] 🔧 Symbolic analysis (RegEx + tldextract + DNS + TextBlob)...")
    regex_results = regex_symbolic_analysis(email_text)
    sentiment     = sentiment_analysis(email_text)

    dns_results = []
    for url in metadata.get("urls", [])[:5]:
        domain_info = extract_domain_info(url)
        full_domain = domain_info.get("full_domain", "")
        if full_domain:
            dns_info = dns_validate_domain(full_domain)
            dns_info.update(domain_info)
            dns_results.append(dns_info)
    if metadata.get("sender_domain"):
        d = dns_validate_domain(metadata["sender_domain"])
        d["domain"] = metadata["sender_domain"]
        d["type"]   = "sender"
        dns_results.append(d)

    # 4 — LLM
    if verbose: print(f"[4/5] 🤖 {LLM_MODEL} (Groq) + RAG + Chain-of-Thought...")
    prompt     = build_rag_prompt(email_text, metadata, regex_results,
                                  faiss_results, sentiment, dns_results, rag_context)
    llm_result = call_llm(prompt)

    # 5 — Risk scoring
    if verbose: print("[5/5] 📊 Computing hybrid risk score...")
    risk = compute_hybrid_risk_score(regex_results, faiss_results, dns_results, llm_result)

    elapsed = time.time() - start

    report = {
        "risk_verdict":        risk["risk_label"],
        "risk_score":          risk["final_risk_score"],
        "recommended_action":  risk["recommended_action"],
        "component_scores":    risk["component_scores"],
        "metadata":            metadata,
        "regex_analysis":      regex_results,
        "faiss_analysis":      faiss_results,
        "sentiment_analysis":  sentiment,
        "dns_validation":      dns_results,
        "llm_analysis":        llm_result.get("result", {}),
        "llm_success":         llm_result.get("success", False),
        "processing_time_sec": round(elapsed, 2),
    }

    if verbose:
        emoji = {"SAFE": "✅", "SUSPICIOUS": "⚠️", "PHISHING": "🚨"}.get(report["risk_verdict"], "❓")
        print("\n" + "=" * 60)
        print(f"  {emoji}  VERDICT: {report['risk_verdict']}")
        print(f"  📊 Risk Score      : {report['risk_score']:.4f}")
        print(f"  🎯 Action          : {report['recommended_action']}")
        print(f"  ⏱️  Processing Time : {elapsed:.2f}s")
        print(f"  🤖 LLM Success     : {report['llm_success']}")
        if report["llm_success"] and report["llm_analysis"]:
            llm = report["llm_analysis"]
            print(f"\n  💬 Justification:\n     {llm.get('justification', 'N/A')}")
            print("\n  🔑 Key Indicators:")
            for ind in llm.get("key_indicators", [])[:3]:
                print(f"     • {ind}")
        print("\n  Component Scores:")
        for k, v in report["component_scores"].items():
            bar = "█" * int(v * 20) + "░" * (20 - int(v * 20))
            print(f"     {k:10s} [{bar}] {v:.3f}")
        print("=" * 60)

    # ── Save to shared memory module (memory/email/) ──────────────────────────
    if _MEMORY_AVAILABLE:
        try:
            saved_path = _get_memory().save_email_report(report)
            print(f"  [MEMORY] Email report saved -> {saved_path}")
        except Exception as _mem_err:
            print(f"  [MEMORY] Email save failed: {_mem_err}")
    else:
        print("  [MEMORY] Skipped — agent_memory module not found")

    return report

