# -*- coding: utf-8 -*-
# Flask API (T1-only + optional T2):
# - URL/domain scoring (offline lexical rules, UGC platform handling, optional brand binding)
# - Email (HTML) scoring: sender + content + URL blend
# - Optional T2 URL model auto-load (url_model.joblib) for lexical ML
#
# No external WHOIS/DNS/cert lookups are performed in this file.

from flask import Flask, request, jsonify
from urllib.parse import urlparse
from email.utils import parseaddr
from bs4 import BeautifulSoup
import re, math, idna, tldextract
import os

app = Flask(__name__)

# ---------------- First-party official domains (eTLD+1) ----------------
# Any subdomain of a whitelisted eTLD+1 is considered official.
OFFICIAL_DOMAINS = {
    # AU Federal & national services
    "australia.gov.au","my.gov.au","mygovid.gov.au","servicesaustralia.gov.au",
    "ato.gov.au","business.gov.au","accc.gov.au","scamwatch.gov.au",
    "moneysmart.gov.au","asic.gov.au","abs.gov.au","afp.gov.au","humanservices.gov.au",
    # AU states/territories
    "vic.gov.au","nsw.gov.au","qld.gov.au","wa.gov.au","sa.gov.au","tas.gov.au","act.gov.au","nt.gov.au",
    # VIC universities
    "monash.edu","unimelb.edu.au","rmit.edu.au","deakin.edu.au","swinburne.edu.au","latrobe.edu.au",
    # Big tech / identity
    "apple.com","icloud.com","google.com","google.com.au","youtube.com",
    "microsoft.com","office.com","live.com","outlook.com",
    "facebook.com","instagram.com","whatsapp.com","twitter.com","x.com","tiktok.com","linkedin.com",
    # Payments / e-commerce
    "paypal.com","stripe.com","squareup.com","afterpay.com","zip.co","amazon.com","amazon.com.au","ebay.com.au",
    # AU banks
    "commbank.com.au","nab.com.au","anz.com","westpac.com.au","stgeorge.com.au","bankofmelbourne.com.au",
    "banksa.com.au","bendigobank.com.au","bankwest.com.au","ing.com.au","macquarie.com","suncorp.com.au",
    "mebank.com.au","boq.com.au","ubank.com.au","amp.com.au",
    # Telcos / ISPs
    "telstra.com","optus.com.au","vodafone.com.au","tpg.com.au","iinet.net.au","aussiebroadband.com.au","amaysim.com.au",
    # Postal / delivery
    "auspost.com.au","startrack.com.au","dhl.com","fedex.com","ups.com","tollgroup.com","aramex.com","couriersplease.com.au",
    # Utilities / energy
    "agl.com.au","originenergy.com.au","energyaustralia.com.au","powershop.com.au",
    "ausnetservices.com.au","citipower.com.au","unitedenergy.com.au",
    # Airlines
    "qantas.com","virginaustralia.com","jetstar.com","airnewzealand.com",
}

# ---------------- UGC platforms (do NOT auto-trust as official) ----------------
# These are legitimate platforms where users can host arbitrary content.
PLATFORM_UGC_ETLD1 = {
    "google.com",   # docs/sites/drive.*
    "forms.gle",
    "dropbox.com",
    "notion.site","notion.so",
    "wixsite.com",
    "github.io",
    "medium.com","substack.com",
}

# URL path patterns that commonly indicate hosted forms/pages collecting data
UGC_PATH_PATTERNS = [
    re.compile(r"^/spreadsheets?/"),
    re.compile(r"^/spreadsheet/"),
    re.compile(r"^/forms?/"),
    re.compile(r"/viewform\b"),
    re.compile(r"^/file/d/"),
]

# ---------------- Lexical risk signals ----------------
RISK_WORDS = {
    "login","verify","update","secure","account","password","reset",
    "pay","refund","gift","free","suspend","unlock","confirm","bank","wallet"
}
SUSPICIOUS_TLDS = {"zip","top","xyz","gq","click","work","loan","cam","mom","bar","country"}

# ---------------- Brand tokens & mapping ----------------
_tldx = tldextract.TLDExtract(suffix_list_urls=None)  # no PSL network fetch

def tokens_from_officials(domains: set[str]) -> set[str]:
    toks = set()
    for d in domains:
        ext = _tldx(d)
        if ext.domain:
            toks.add(ext.domain.lower())
    return toks

BRAND_TOKENS = tokens_from_officials(OFFICIAL_DOMAINS) | {
    # common aliases (not necessarily registrable domains)
    "mygov","mygovid","centrelink","medicare",
    "commbank","westpac","stgeorge","bankofmelbourne","banksa","bendigobank",
    "bankwest","suncorp","macquarie","ubank","boq","amp",
    "telstra","optus","vodafone","tpg","iinet","aussiebroadband","amaysim",
    "auspost","startrack",
    "energyaustralia","origin","agl",
    "qantas","virgin","jetstar",
    "google","youtube","gmail",
    "microsoft","outlook","office","live",
    "apple","icloud","itunes",
    "facebook","instagram","whatsapp","meta",
    "twitter","x","tiktok","linkedin",
    "amazon","ebay","paypal","stripe","square","afterpay","zip",
}
BRAND_TOKENS = {re.sub(r"[^a-z0-9]", "", t) for t in BRAND_TOKENS if t}

BRAND_TO_DOMAINS = {
    "ato":{"ato.gov.au"},
    "mygov":{"my.gov.au","mygovid.gov.au","servicesaustralia.gov.au"},
    "servicesaustralia":{"servicesaustralia.gov.au"},
    "monash":{"monash.edu"},
    "unimelb":{"unimelb.edu.au"},
    "rmit":{"rmit.edu.au"},
    "deakin":{"deakin.edu.au"},
    "swinburne":{"swinburne.edu.au"},
    "latrobe":{"latrobe.edu.au"},
    "commbank":{"commbank.com.au"},
    "nab":{"nab.com.au"},
    "anz":{"anz.com"},
    "westpac":{"westpac.com.au"},
    "stgeorge":{"stgeorge.com.au"},
    "bankofmelbourne":{"bankofmelbourne.com.au"},
    "banksa":{"banksa.com.au"},
    "bendigobank":{"bendigobank.com.au"},
    "bankwest":{"bankwest.com.au"},
    "ing":{"ing.com.au"},
    "macquarie":{"macquarie.com"},
    "suncorp":{"suncorp.com.au"},
    "mebank":{"mebank.com.au"},
    "boq":{"boq.com.au"},
    "ubank":{"ubank.com.au"},
    "amp":{"amp.com.au"},
    "auspost":{"auspost.com.au"},
    "telstra":{"telstra.com"},
    "optus":{"optus.com.au"},
    "vodafone":{"vodafone.com.au"},
    "tpg":{"tpg.com.au"},
    "iinet":{"iinet.net.au"},
    "aussiebroadband":{"aussiebroadband.com.au"},
    "amaysim":{"amaysim.com.au"},
    "energyaustralia":{"energyaustralia.com.au"},
    "origin":{"originenergy.com.au"},
    "agl":{"agl.com.au"},
    "qantas":{"qantas.com"},
    "virgin":{"virginaustralia.com"},
    "jetstar":{"jetstar.com"},
    "airnewzealand":{"airnewzealand.com"},
    "google":{"google.com","google.com.au"},
    "microsoft":{"microsoft.com","office.com","live.com","outlook.com"},
    "apple":{"apple.com","icloud.com"},
    "paypal":{"paypal.com"},
    "stripe":{"stripe.com"},
    "amazon":{"amazon.com","amazon.com.au"},
    "ebay":{"ebay.com.au"},
}

# ---------------- Utils ----------------
def etld1(host: str) -> str:
    ext = _tldx(host or "")
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else (ext.domain or "")

def is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", host or ""))

def levenshtein(a: str, b: str) -> int:
    if a == b: return 0
    if not a:  return len(b)
    if not b:  return len(a)
    prev = list(range(len(b)+1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j]+1, cur[j-1]+1, prev[j-1] + (ca != cb)))
        prev = cur
    return prev[-1]

def min_brand_similarity(hostname_core: str) -> float:
    # return similarity in [0,1]; higher means more similar to some brand token
    if not BRAND_TOKENS or not hostname_core:
        return 0.0
    dmin = min(levenshtein(hostname_core, b) for b in BRAND_TOKENS)
    return 1.0 - (dmin / max(len(hostname_core), 1))

def is_platform_ugc(host: str, e1: str, path: str) -> bool:
    # mark as UGC when eTLD+1 is a known platform or *.google.com with forms/docs paths
    if e1 in PLATFORM_UGC_ETLD1:
        return True
    if host.endswith(".google.com"):
        for pat in UGC_PATH_PATTERNS:
            if pat.search(path or ""):
                return True
    return False

def normalize_token(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())

# ---------------- Optional T2 model ----------------
URL_MODEL = None
try:
    from joblib import load as joblib_load
    URL_MODEL = joblib_load("url_model.joblib")
except Exception:
    URL_MODEL = None

def t2_score_url(url: str):
    """Return T2 probability in [0,1] if model is available, else None."""
    if URL_MODEL is None:
        return None
    try:
        proba = URL_MODEL.predict_proba([url])[0][1]
        return float(proba)
    except Exception:
        return None

# ---------------- T1 URL scoring ----------------
def score_url_t1(url: str, brand: str | None = None) -> dict:
    try:
        p = urlparse(url)
        host = (p.hostname or "").lower()
        e1 = etld1(host)
        pathq = (p.path or "") + "?" + (p.query or "")
        pathq_l = pathq.lower()

        reasons = []
        signals = {}

        # UGC detection and first-party official determination
        ugc = is_platform_ugc(host, e1, p.path or "")
        official = (e1 in OFFICIAL_DOMAINS) and (not ugc)
        if official:
            return {"url": url, "official": True, "etld1": e1, "risk": 0.0,
                    "reasons": ["Matched official whitelist"]}

        # UGC baseline signal
        if ugc:
            signals["ugc_platform"] = 0.35
            reasons.append("Hosted on UGC platform (owner unverified) – avoid submitting sensitive info")
        else:
            signals["ugc_platform"] = 0.0

        # Brand similarity
        host_core = re.sub(r"[\W_]", "", host or "")
        sim = min_brand_similarity(host_core)
        signals["brand_similarity"] = sim
        if sim >= 0.6:
            reasons.append("Highly similar to known brand keywords")

        # Punycode / homograph
        puny = False
        try:
            host_idn = idna.encode(host).decode()
            puny = "xn--" in host_idn
        except Exception:
            pass
        signals["punycode"] = 1.0 if puny else 0.0
        if puny:
            reasons.append("Domain contains Punycode (possible homograph)")

        # Risky keywords in path/query
        kw_hits = [w for w in RISK_WORDS if w in pathq_l]
        signals["risky_keywords"] = min(1.0, 0.2 * len(kw_hits)) if kw_hits else 0.0
        if kw_hits:
            reasons.append(f"High-risk keywords in path: {', '.join(sorted(kw_hits))}")

        # Suspicious TLD
        tld = e1.split(".")[-1] if e1 else ""
        signals["suspicious_tld"] = 1.0 if tld in SUSPICIOUS_TLDS else 0.0
        if signals["suspicious_tld"] > 0:
            reasons.append(f"Suspicious TLD: .{tld}")

        # Deep subdomain
        sub_count = host.count(".") - 1 if host else 0
        signals["deep_subdomain"] = 0.6 if sub_count >= 2 else 0.0
        if sub_count >= 2:
            reasons.append(f"Deep subdomain ({sub_count+1} levels)")

        # IP host / '@' / long URL / many hyphens
        signals["ip_host"] = 0.7 if is_ip(host) else 0.0
        if signals["ip_host"] > 0:
            reasons.append("Using IP as hostname")

        at_cnt = url.count("@")
        signals["has_at"] = 0.6 if at_cnt > 0 else 0.0
        if at_cnt > 0:
            reasons.append("URL contains '@'")

        signals["long_url"] = 0.3 if len(url) > 90 else 0.0
        if signals["long_url"] > 0:
            reasons.append("URL is very long")

        hyphens = (host or "").count("-")
        signals["many_hyphens"] = 0.3 if hyphens >= 3 else 0.0
        if hyphens >= 3:
            reasons.append("Too many hyphens in domain")

        # Optional brand binding
        if brand:
            brand_norm = normalize_token(brand)
            brand_domains = BRAND_TO_DOMAINS.get(brand_norm, set())
            if brand_domains and (e1 not in brand_domains):
                signals["brand_mismatch"] = 0.35
                reasons.append(f"Brand mismatch (brand: {brand_norm}, domain: {e1})")
            else:
                signals["brand_mismatch"] = 0.0
        else:
            signals["brand_mismatch"] = 0.0

        # Weighted aggregation + sigmoid normalization to [0,1]
        weight = {
            "ugc_platform": 0.30,
            "brand_similarity": 0.35,
            "punycode": 0.15,
            "risky_keywords": 0.20,
            "suspicious_tld": 0.10,
            "deep_subdomain": 0.10,
            "ip_host": 0.25,
            "has_at": 0.10,
            "long_url": 0.05,
            "many_hyphens": 0.05,
            "brand_mismatch": 0.30,
        }
        score_lin = sum(weight[k] * signals.get(k, 0.0) for k in weight)
        risk = 1 / (1 + math.exp(-3.0 * (score_lin - 0.5)))

        # Reason ordering: brand/UGC first, then punycode, then others
        reasons = list(dict.fromkeys(reasons))
        reasons_sorted = sorted(
            reasons,
            key=lambda s: 0 if ("brand" in s.lower() or "ugc" in s.lower()) else (1 if "punycode" in s.lower() else 2)
        )

        return {
            "url": url,
            "official": False,
            "etld1": e1,
            "risk": round(float(risk), 2),
            "reasons": reasons_sorted
        }

    except Exception as e:
        return {
            "url": url,
            "official": False,
            "etld1": "",
            "risk": 0.0,
            "reasons": [f"Parse error: {type(e).__name__}: {e}"]
        }

# ---------------- Content & sender scoring (for HTML emails) ----------------
ZW_CHARS = "[\u200b\u200c\u200d\u2060]"  # zero-width chars
DOMAIN_RE = re.compile(r"\b([a-z0-9][a-z0-9\-\.]+\.[a-z]{2,})\b", re.I)

def extract_links_and_forms(html: str):
    """Parse HTML and return links (href,text), forms (action,has_password), and visible text."""
    soup = BeautifulSoup(html or "", "lxml")
    links = [{"href": a.get("href"), "text": a.get_text(strip=True)} for a in soup.find_all("a", href=True)]
    forms = []
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        has_pwd = any(i.get("type","").lower() == "password" for i in f.find_all("input"))
        forms.append({"action": action, "has_password": has_pwd})
    text = soup.get_text(separator=" ", strip=True)
    return links, forms, text

def content_score(html: str, brand: str | None, url_items: list[dict]) -> dict:
    """Heuristics over email HTML body (no network)."""
    links, forms, text = extract_links_and_forms(html)
    text_l = (text or "").lower()

    reasons = []
    score = 0.0

    # Risky words in visible text
    risky_words = [w for w in RISK_WORDS if w in text_l]
    if risky_words:
        score += min(0.25, 0.05 * len(risky_words))
        reasons.append(f"Body contains high-risk words: {', '.join(sorted(risky_words))}")

    # Inline forms
    if forms:
        score += 0.2
        reasons.append("Email contains an HTML form")
        if any(f["has_password"] for f in forms):
            score += 0.2
            reasons.append("Form contains a password input field")

    # Zero-width characters (obfuscation)
    if re.search(ZW_CHARS, html or ""):
        score += 0.1
        reasons.append("Body contains zero-width characters (possible obfuscation)")

    # Link text domain vs destination domain mismatch
    for a in links:
        href = a.get("href") or ""
        text_dom = None
        m = DOMAIN_RE.search(a.get("text") or "")
        if m:
            text_dom = etld1(urlparse(m.group(1)).hostname or m.group(1))
        dest_host = (urlparse(href).hostname or "").lower()
        dest_e1 = etld1(dest_host)
        if text_dom and dest_e1 and (text_dom != dest_e1):
            score += 0.15
            reasons.append(f"Link text domain ({text_dom}) differs from destination domain ({dest_e1})")

    # Count suspicious URL items (non-official and risky)
    suspicious_links = sum(1 for it in url_items if (not it.get("official")) and it.get("risk", 0) >= 0.5)
    if suspicious_links >= 1:
        score += min(0.3, 0.15 * suspicious_links)
        reasons.append(f"Contains suspicious links: {suspicious_links}")

    # Brand mention vs destination mismatch (best-effort)
    if brand:
        brand_norm = normalize_token(brand)
        brand_domains = BRAND_TO_DOMAINS.get(brand_norm, set())
        if brand_domains:
            any_brand_link = any(etld1(urlparse(it["url"]).hostname or "") in brand_domains for it in url_items)
            if not any_brand_link and len(url_items) >= 1:
                score += 0.15
                reasons.append(f"Mentions brand ({brand_norm}) but links do not target its official domains")

    score = max(0.0, min(1.0, score))
    reasons = list(dict.fromkeys(reasons))
    return {"score": round(float(score), 2), "reasons": reasons, "links": links, "forms": forms}

def sender_score(headers: dict, brand: str | None) -> dict:
    """Score sender using common headers. If headers are absent, return neutral."""
    reasons = []
    score = 0.0
    from_h = headers.get("From") or headers.get("from") or ""
    reply_to = headers.get("Reply-To") or headers.get("reply-to") or ""
    return_path = headers.get("Return-Path") or headers.get("return-path") or ""
    authres = headers.get("Authentication-Results") or headers.get("authentication-results") or ""

    name, email_addr = parseaddr(from_h)
    email_addr = (email_addr or "").lower()
    from_dom = email_addr.split("@")[-1] if "@" in email_addr else ""
    from_e1 = etld1(from_dom)

    # Display name spoof (brand-looking name but non-matching domain)
    name_norm = normalize_token(name)
    if name_norm in BRAND_TO_DOMAINS and from_e1 not in BRAND_TO_DOMAINS[name_norm]:
        score += 0.25
        reasons.append(f"Display name suggests brand ({name_norm}) but From domain does not match ({from_e1})")

    # Reply-To mismatch
    if reply_to:
        _, rt_addr = parseaddr(reply_to)
        rt_dom = (rt_addr or "").split("@")[-1].lower() if "@" in (rt_addr or "") else ""
        rt_e1 = etld1(rt_dom)
        if from_e1 and rt_e1 and (rt_e1 != from_e1):
            score += 0.2
            reasons.append(f"Reply-To domain differs from From domain ({from_e1} → {rt_e1})")

    # Return-Path mismatch
    if return_path:
        _, rp_addr = parseaddr(return_path)
        rp_dom = (rp_addr or "").split("@")[-1].lower() if "@" in (rp_addr or "") else ""
        rp_e1 = etld1(rp_dom)
        if from_e1 and rp_e1 and (rp_e1 != from_e1):
            score += 0.15
            reasons.append(f"Return-Path domain differs from From domain ({from_e1} → {rp_e1})")

    # Authentication results (DMARC/SPF/DKIM)
    if authres:
        al = authres.lower()
        if "dmarc=fail" in al or "spf=fail" in al or "dkim=fail" in al:
            score += 0.3
            reasons.append("Authentication failed (DMARC/SPF/DKIM)")
        elif ("dmarc=pass" in al) or ("spf=pass" in al) or ("dkim=pass" in al):
            score -= 0.1  # small relief only
            reasons.append("Authentication pass signal (DMARC/SPF/DKIM)")

    # Optional brand binding
    if brand:
        bn = normalize_token(brand)
        bdoms = BRAND_TO_DOMAINS.get(bn, set())
        if bdoms and from_e1 and (from_e1 not in bdoms):
            score += 0.25
            reasons.append(f"Brand mismatch (brand: {bn}, From domain: {from_e1})")

    score = max(0.0, min(1.0, score))
    reasons = list(dict.fromkeys(reasons))
    return {"score": round(float(score), 2),
            "from": {"name": name, "email": email_addr, "etld1": from_e1},
            "reasons": reasons}

# ---------------- API: health ----------------
@app.get("/health")
def health():
    return "ok", 200

# ---------------- API: email check ----------------
@app.post("/email/check")
def email_check():
    """
    Request JSON:
    {
      "html": "<html>...</html>",          // required
      "headers": {"From":"...", ...},      // optional but recommended
      "brand": "ato",                      // optional brand hint
      "extract_urls_from_html_only": true  // reserved flag, not used here
    }
    """
    data = request.get_json(silent=True) or {}
    html = data.get("html", "")
    headers = data.get("headers") or {}
    brand = data.get("brand")

    if not html:
        return jsonify(error="missing 'html' field"), 400

    # Extract links from HTML
    links, forms, _ = extract_links_and_forms(html)
    url_candidates = []
    for a in links:
        href = a.get("href") or ""
        if href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
            continue
        if href.startswith("http://") or href.startswith("https://"):
            url_candidates.append(href)

    # T1 (+ optional T2) for each URL
    url_items = []
    for u in url_candidates:
        item = score_url_t1(u, brand=brand)
        proba_t2 = t2_score_url(u)
        if proba_t2 is not None:
            blended = 0.6 * item["risk"] + 0.4 * proba_t2
            item["risk_t2"] = round(float(proba_t2), 2)
            item["risk_blended"] = round(float(blended), 2)
        url_items.append(item)

    # Content & sender scoring
    content = content_score(html, brand=brand, url_items=url_items)
    sender = sender_score(headers if isinstance(headers, dict) else {}, brand=brand)

    # Aggregate overall risk (weights are tunable)
    url_max = max([it.get("risk_blended", it["risk"]) for it in url_items], default=0.0)
    overall = 0.35 * sender["score"] + 0.30 * content["score"] + 0.35 * url_max
    overall = round(float(max(0.0, min(1.0, overall))), 2)

    return jsonify({
        "overall_risk": overall,
        "sender": sender,
        "content": content,
        "urls": url_items
    })

# ---------------- API: single URL check ----------------
@app.get("/check")
def check_url_get():
    # GET /check?url=...&brand=...
    url = (request.args.get("url") or "").strip()
    brand = (request.args.get("brand") or "").strip() or None
    if not url:
        return jsonify(error="missing 'url' query param"), 400
    item = score_url_t1(url, brand=brand)
    proba_t2 = t2_score_url(url)
    if proba_t2 is not None:
        item["risk_t2"] = round(float(proba_t2), 2)
        item["risk_blended"] = round(float(0.6 * item["risk"] + 0.4 * proba_t2), 2)
    return jsonify(item)

if __name__ == "__main__":
    # Dev run: python app.py
    app.run(host="0.0.0.0", port=8080, debug=True)
