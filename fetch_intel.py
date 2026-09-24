#!/usr/bin/env python3
"""
Beast Intel — free, automatic OSINT sweep.

What this does, in plain terms:
  1. Reads the list of names/brands to watch from config.json.
  2. Checks three sources that are free because they're public services,
     not because of a "free tier" that can run out or get shut off:
       - Google News RSS
       - Bing News RSS
       - Hacker News (Algolia search API)
  3. Reads each headline/post and guesses which category it belongs to
     (threats, PII leaks, impersonation, defamation, financial/legal)
     and how serious it looks, using plain keyword rules.
  4. Remembers what it's already seen (seen.json) so it never reports
     the same story twice.
  5. Writes the results into live_findings.json AND directly into a
     ready-to-open dashboard file (dashboard.html), so opening that
     file always shows the latest sweep.

Run it by hand:   python3 fetch_intel.py
Run it forever for free: see the GitHub Actions workflow in this folder.
"""

import json
import re
import time
import urllib.request
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

EASTERN = ZoneInfo("America/New_York")

ROOT = Path(__file__).parent
CONFIG_PATH = ROOT / "config.json"
SEEN_PATH = ROOT / "seen.json"
FINDINGS_PATH = ROOT / "live_findings.json"
DASHBOARD_TEMPLATE = ROOT / "dashboard_template.html"
DASHBOARD_OUT = ROOT / "dashboard.html"

USER_AGENT = "Mozilla/5.0 (compatible; BeastIntel/1.0; +internal security monitoring)"

# ---------------------------------------------------------------------------
# 1. Categorization rules — plain keyword matching. Cheap, fast, no AI
#    needed, and easy for a human to read and adjust.
# ---------------------------------------------------------------------------
CATEGORY_RULES = [
    ("Threats & Security Risks", ["threat", "kill", "attack", "shooting", "bomb", "stalk", "home address", "residence", "in danger", "assault", "workplace violence"]),
    ("Exposures & PII Leaks", ["leak", "breach", "password", "ssn", "social security", "doxx", "personal data", "hacked", "database exposed"]),
    ("Impersonation & Brand Abuse", ["fake", "impersonat", "clone", "phishing", "scam account", "lookalike", "counterfeit"]),
    ("Operational & Financial Intel", [
        "lawsuit", "sec filing", "court", "class action", "subpoena", "investigation", "financial",
        "disgruntled", "walkout", "strike", "harassment", "unsafe", "osha", "injury", "fired",
        "whistleblower", "workplace", "production site", "set", "employee", "labor", "union"
    ]),
    ("Negativity & Defamation", ["scam", "fraud", "boycott", "expose", "exposed", "controversy", "allegations", "backlash", "cancel"]),
]
DEFAULT_CATEGORY = "Negativity & Defamation"

SEVERITY_RULES = [
    ("Critical", ["home address", "kill", "bomb", "attack", "in danger", "ssn", "social security", "assault", "workplace violence"]),
    ("High", ["lawsuit", "class action", "leak", "breach", "hacked", "scam", "fraud", "harassment", "unsafe", "osha", "whistleblower", "injury"]),
    ("Medium", ["fake", "impersonat", "boycott", "controversy", "backlash", "disgruntled", "walkout", "strike", "fired"]),
]
DEFAULT_SEVERITY = "Low"

SEVERITY_RISK = {"Critical": 92, "High": 74, "Medium": 52, "Low": 28}

SOURCE_RELIABILITY = {"Google News": 5, "Bing News": 5, "Hacker News": 3}


def classify(text):
    text_l = text.lower()
    category = DEFAULT_CATEGORY
    for cat, keywords in CATEGORY_RULES:
        if any(k in text_l for k in keywords):
            category = cat
            break
    severity = DEFAULT_SEVERITY
    for sev, keywords in SEVERITY_RULES:
        if any(k in text_l for k in keywords):
            severity = sev
            break
    return category, severity


def load_config():
    if not CONFIG_PATH.exists():
        raise SystemExit(f"Missing {CONFIG_PATH}. Copy config.example.json to config.json and edit it first.")
    return json.loads(CONFIG_PATH.read_text())


def load_seen():
    if SEEN_PATH.exists():
        return set(json.loads(SEEN_PATH.read_text()))
    return set()


def save_seen(seen):
    # Cap so this file never grows forever.
    SEEN_PATH.write_text(json.dumps(sorted(seen)[-5000:]))


def http_get(url, timeout=15):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


# ---------------------------------------------------------------------------
# 2. Source fetchers. Each returns a list of dicts: title, snippet, url, source, source_type, published
# ---------------------------------------------------------------------------
def fetch_google_news(query, limit=10):
    url = "https://news.google.com/rss/search?" + urllib.parse.urlencode({
        "q": query, "hl": "en-US", "gl": "US", "ceid": "US:en"
    })
    try:
        raw = http_get(url)
        root = ET.fromstring(raw)
        items = []
        for item in root.findall("./channel/item")[:limit]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()
            desc = (item.findtext("description") or "").strip()
            desc = re.sub("<[^>]+>", "", desc)
            source_el = item.find("source")
            src_name = source_el.text if source_el is not None else "Google News"
            items.append({
                "title": title, "snippet": desc[:280], "url": link,
                "source": src_name, "source_type": "Google News", "published": pub
            })
        return items
    except Exception as e:
        print(f"  [warn] Google News fetch failed for '{query}': {e}")
        return []


def fetch_bing_news(query, limit=10):
    url = "https://www.bing.com/news/search?" + urllib.parse.urlencode({"q": query, "format": "rss"})
    try:
        raw = http_get(url)
        root = ET.fromstring(raw)
        items = []
        for item in root.findall("./channel/item")[:limit]:
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()
            pub = (item.findtext("pubDate") or "").strip()
            desc = (item.findtext("description") or "").strip()
            desc = re.sub("<[^>]+>", "", desc)
            items.append({
                "title": title, "snippet": desc[:280], "url": link,
                "source": "Bing News", "source_type": "Bing News", "published": pub
            })
        return items
    except Exception as e:
        print(f"  [warn] Bing News fetch failed for '{query}': {e}")
        return []


def fetch_hackernews(query, limit=10):
    url = "https://hn.algolia.com/api/v1/search?" + urllib.parse.urlencode({"query": query, "hitsPerPage": limit})
    try:
        raw = http_get(url)
        data = json.loads(raw)
        items = []
        for hit in data.get("hits", []):
            title = hit.get("title") or hit.get("story_title") or "(untitled Hacker News item)"
            link = hit.get("url") or f"https://news.ycombinator.com/item?id={hit.get('objectID')}"
            snippet = (hit.get("comment_text") or "")[:280]
            items.append({
                "title": title, "snippet": snippet, "url": link,
                "source": "Hacker News", "source_type": "Hacker News",
                "published": hit.get("created_at", "")
            })
        return items
    except Exception as e:
        print(f"  [warn] Hacker News fetch failed for '{query}': {e}")
        return []


SOURCES = [fetch_google_news, fetch_bing_news, fetch_hackernews]


def parse_published(published):
    """Best-effort parse of a source's date string into a datetime. Returns None if unparseable."""
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%a, %d %b %Y %H:%M:%S %z"):
        try:
            dt = datetime.strptime(published, fmt)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue
    if published and "T" in str(published):  # ISO format from Algolia
        try:
            return datetime.fromisoformat(published.replace("Z", "+00:00"))
        except Exception:
            pass
    return None


def relative_time(dt):
    if dt is None:
        return "Recently"
    hours = int((datetime.now(timezone.utc) - dt).total_seconds() // 3600)
    if hours < 1:
        return "Just now"
    if hours < 24:
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    return f"{hours // 24} day{'s' if hours // 24 != 1 else ''} ago"


def run_sweep():
    config = load_config()
    watch_terms = config["watch_terms"]
    risk_modifiers = config.get("risk_modifiers", [])
    seen = load_seen()
    results = []
    result_id = int(time.time())

    for term in watch_terms:
        queries = [term]
        if risk_modifiers:
            mod_query = f'"{term}" (' + " OR ".join(risk_modifiers) + ")"
            queries.append(mod_query)

        for query in queries:
            for fetcher in SOURCES:
                print(f"Checking {fetcher.__name__} for: {query}")
                for hit in fetcher(query, limit=config.get("results_per_query", 8)):
                    if not hit["url"] or hit["url"] in seen:
                        continue
                    seen.add(hit["url"])
                    combined_text = f"{hit['title']} {hit['snippet']}"
                    category, severity = classify(combined_text)
                    result_id += 1
                    published_dt = parse_published(hit["published"])
                    epoch_ms = int((published_dt or datetime.now(timezone.utc)).timestamp() * 1000)
                    results.append({
                        "id": f"RES-LIVE-{result_id}",
                        "keywordMatched": term,
                        "category": category,
                        "severity": severity,
                        "riskScore": SEVERITY_RISK[severity],
                        "confidence": 70,
                        "source": hit["source"],
                        "sourceType": hit["source_type"],
                        "title": hit["title"][:180],
                        "snippet": hit["snippet"] or "(no preview text available — open the link to see the full content)",
                        "detectedAt": relative_time(published_dt),
                        "detectedAtEpoch": epoch_ms,
                        "url": hit["url"],
                        "status": "New",
                        "assignee": "Unassigned",
                        "tags": ["auto-scan"],
                        "notes": [],
                        "isDemo": False
                    })

    save_seen(seen)
    results.sort(key=lambda r: r["riskScore"], reverse=True)
    return results, watch_terms


def write_findings(results):
    FINDINGS_PATH.write_text(json.dumps(results, indent=2))
    print(f"\nWrote {len(results)} new findings to {FINDINGS_PATH}")


def write_dashboard(results, watch_terms):
    if not DASHBOARD_TEMPLATE.exists():
        print(f"  [warn] No {DASHBOARD_TEMPLATE.name} found — skipping dashboard update. Findings are still in {FINDINGS_PATH.name}.")
        return
    html = DASHBOARD_TEMPLATE.read_text()
    results_js = json.dumps(results, indent=2)
    tags_js = json.dumps(watch_terms)
    # Eastern time, 12-hour clock. Shows EST in winter and EDT in summer automatically.
    now_et = datetime.now(EASTERN)
    stamp = now_et.strftime("%b %d, %Y ") + now_et.strftime("%I:%M %p").lstrip("0") + now_et.strftime(" %Z")

    source_names = ", ".join(sorted({s.__name__.replace("fetch_", "").replace("_", " ").title() for s in SOURCES}))
    html = html.replace(
        "SOURCES_CHECKED_PLACEHOLDER",
        f"Sources checked this sweep: {source_names} · {len(results)} results found · last swept {stamp}"
    )

    html = html.replace(
        "const INITIAL_SEARCH_RESULTS = [];",
        f"const INITIAL_SEARCH_RESULTS = {results_js};"
    )
    html = html.replace(
        "const [activeKeywordTags, setActiveKeywordTags] = useState([]);",
        f"const [activeKeywordTags, setActiveKeywordTags] = useState({tags_js});"
    )
    html = html.replace(
        "<title>Beast OSINT Test — Online Monitoring</title>",
        f"<title>Beast OSINT Live — updated {stamp}</title>"
    )
    html = html.replace(
        '<span className="px-2 py-0.5 text-[10px] font-medium bg-slate-700 text-slate-400 border border-slate-600 rounded-full">No setup needed</span>',
        f'<span className="px-2 py-0.5 text-[10px] font-medium bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 rounded-full">Live — updated {stamp}</span>'
    )
    DASHBOARD_OUT.write_text(html)
    print(f"Updated {DASHBOARD_OUT} — open this file to see the results.")


if __name__ == "__main__":
    print("=== Beast Intel sweep starting ===")
    results, watch_terms = run_sweep()
    write_findings(results)
    write_dashboard(results, watch_terms)
    print("=== Done ===")
