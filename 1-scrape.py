"""
1_scrape.py
===========
Stage 1 of the phishing-detection data pipeline (Chapter 3 methodology).
Output: one JSON file per sample, one row per sample in a manifest CSV,
Usage: 
py 1-scrape.py [--target-per-class NUM] [--phishing-sources SPECIFIC SOURCE] 
               [--skip-legit] [--phishstats-key API_KEY]
"""

# LIBRARY IMPORTS
import argparse
import concurrent.futures as futures
import csv
import hashlib
import json
import logging
import os
import io
import socket
import ssl
import whois
import sys
from datetime import datetime, timezone
from urllib.parse import urlparse
from tranco import Tranco

import requests
from bs4 import BeautifulSoup

#  universal retry handling
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# DIRECTORIES
RAW_DIR = "data/raw"
MANIFEST_PATH = os.path.join(RAW_DIR, "manifest.csv")
MALFORMED_LOG_PATH = os.path.join(RAW_DIR, "malformed_urls.csv") # new tracker
LOG_PATH = "logs/scrape.log"

# DATA SOURCES
# Phishing.Database: raw active phishing links feed
# maintained on GitHub by Mitchell Krogza etc.
PHISHING_DATABASE_ACTIVE_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE/phishing-links-ACTIVE1.txt"

# OpenPhish community feed: refreshed every ~12h
# capped around a ~300 URL per refresh
OPENPHISH_FEED_URL = "https://openphish.com/feed.txt"

# PhishTank: bulk csv dump of currently-valid phishing URLs
PHISHTANK_CSV_URL = "http://data.phishtank.com/data/online-valid.csv"

# PhishStats: JSON API of scored phishing APIs, requires an API key
# sent via the X-API-Key header. Refreshes every ~90 minutes.
PHISHSTATS_FEED_URL = "https://api.phishstats.info/api/phishing?_size=100"
PHISHSTATS_API_KEY = os.environ.get("PHISHSTATS_API_KEY") # set API key via environment variable

# requests initialisation and time out configs
session = requests.Session()
retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
session.mount("https://", HTTPAdapter(max_retries=retries))
session.mount("http://", HTTPAdapter(max_retries=retries))
REQUEST_TIMEOUT = (3.0, 8.0)
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
# rate-limiting
MIN_DELAY_BETWEEN_REQUESTS = 0.5

os.makedirs(RAW_DIR, exist_ok=True)
os.makedirs("logs", exist_ok=True)

# logging configuration and initialisation
stream_handler = logging.StreamHandler(sys.stdout)
stream_handler.flush = sys.stdout.flush
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler(LOG_PATH), stream_handler],
    force=True,
)
log = logging.getLogger(__name__)


# URL COLLECTION
def get_phishing_db_urls(limit=None):
    """
    Fetch the active URLs from the Phishing.Database repository.
    Reading line-by-line from the plain text raw file.
    """
    log.info("Fetching active phishing URLs from Phishing.Database repository")
    try:
        resp = requests.get(PHISHING_DATABASE_ACTIVE_URL, headers=HEADERS,
                            timeout=REQUEST_TIMEOUT, stream=True)
        resp.raise_for_status()
    except Exception as e:
        log.error(f"Failed to fetch Phishing.Databse active list ({e}).")
        return []

    out = []
    now_iso = datetime.now(timezone.utc).isoformat()

    for line in resp.iter_lines(decode_unicode=True):
        if not line:
            continue
        url = line.strip()

        # skip comment lines if present in text feed
        if url.startswith('#'):
            continue

        # ensure minial valid scheme
        if not url.startswith(("https://", "http://")):
            url = f"http://{url}"

        out.append({
            "url": url,
            "source": "phishing_db",
            "listed_at": now_iso,
            })

        if limit and len(out) >= limit:
            break

    log.info(f"Phishing.Database feed returned {len(out)} active seed URLs.")
    return out

def get_openphish_urls(limit=None):
    """
    Fetch OpenPhish community feed.
    The free feed refreshes every ~12 hours and caps around ~300 URLs per refresh
    """
    log.info("Fetching active phishing URLs from the OpenPhish community feed")
    try:
        resp = requests.get(OPENPHISH_FEED_URL, headers=HEADERS,
                            timeout=REQUEST_TIMEOUT, stream=True)
        resp.raise_for_status()
    except Exception as e:
        log.info(f"Failed to fetch from OpenPhish ({e})")
        return []

    now_iso = datetime.now(timezone.utc).isoformat()
    out = []

    for line in resp.text.splitlines():
        url = line.strip()
        if not url or url.startswith("#"):
            continue
        if not url.startswith(("https://", "http://")):
            url = f"http://{url}"
        out.append({"url": url, "source": "openphish", "listed_at": now_iso})
        if limit and len(out) >= limit:
            break
    log.info(f"OpenPhish feed returned {len(out)} seed URLs")
    return out

def get_phishtank_urls(limit=None):
    """
    Fetch PhishTank's online bulk csv dump"""
    log.info("Fetching active phishing urls from PhishTank")
    try:
        resp = requests.get(PHISHTANK_CSV_URL, headers=HEADERS,
                            timeout=REQUEST_TIMEOUT, stream=True)
        resp.raise_for_status()
    except Exception as e:
        log.info(f"Failed to fetch from PhishTank feed ({e})")
        return []

    now_iso = datetime.now(timezone.utc).isoformat()
    out = []

    try:
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            url = (row.get("url") or "").strip()
            if not url:
                continue
            out.append({
                "url": url,
                "source": "phishtank",
                "listed_at": now_iso,
            })
            if limit and len(out) >= limit:
                break
    except Exception as e:
        log.info(f"Failed to parse PhishTank CSV ({e})")
        return []

    log.info(f"PhishTank feed returned {len(out)} seed URLs")
    return out

def get_phishstats_urls(api_key,limit=None):
    """
    Fetch PhishStats feed: JSON format.
    Requires API. Returns empty list on failure.
    Feed is updated every ~90 minutes
    """
    if not api_key:
        log.error("No PhishStats API key provided: "
                  "Set PHISHSTATS_API_KEY environment variable "
                  "or pass --phishstats-key via CLI.")

    request_headers = {**HEADERS, "X-API-Key": api_key}
    try:
        resp = requests.get(PHISHSTATS_FEED_URL, headers=request_headers,
                            timeout=REQUEST_TIMEOUT, stream=True)
        if resp.status_code in (401, 403):
            log.error(
                f"PhishStats rejected the provided API key (HTTP {resp.status_code})"
                f"Check that API key is set corretly. Continuing without this source..."
            )
            return []
        resp.raise_for_status()
        entries = resp.json()
    except Exception as e:
        log.error(f"PhishStats fetch failed ({e})")
        return []

    out = []
    for entry in entries:
        url = entry.get("url")
        if not url:
            continue
        out.append({
            "url": url,
            "source": "phishstats",
            "listed_at": entry.get("timestamp") or entry.get("date"),
        })
    log.info(f"PhishStats feed returned {len(out)} seed URLs")
    if limit:
        out = out[:limit]
    return out

# registry of every phishing seed source, keyed by name.
PHISHING_SEED_FETCHERS = {
    "phishing_database": get_phishing_db_urls,
    "openphish": get_openphish_urls,
    "phishtank": get_phishtank_urls,
    "phishstats": get_phishstats_urls,
}

def get_tranco_legit_urls(count):
    """
    Fetch the Tranco top-sites. 
    Using the official 'tranco' PyPI library
    """
    log.info("Fetching Tranco top-sites list...")
    t = Tranco(cache=True, cache_dir="data/.tranco_cache")
    tranco_list = t.list()
    domains = tranco_list.top(count * 4)
    urls = [{"url": f"https://{d}", "source": "tranco", "listed_at": None} for d in domains]
    log.info(f"Tranco candidate URLs: {len(urls)} (target {count}).")
    return urls

# per-sample static extraction (URL fetch + HTML + script text only)
def get_ssl_info(hostname, port=443):
    """
    SSL certificate check. 
    Returns dict or None on failure.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return {
                    "has_valid_cert": True,
                    "issuer": dict(x[0] for x in cert.get("issuer", [])),
                    "not_after": cert.get("notAfter"),
                }
    except Exception:
        return {"has_valid_cert": False, "issuer": None, "not_after": None}

def get_whois_info(domain):
    """
    WHOIS lookup. 
    Returns dict or None on failure.
    """
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        return {"creation_date": str(creation) if creation else None, "registrar": w.registrar}
    except Exception:
        return {"creation_date": None, "registrar": None}

def extract_scripts(soup):
    """
    Pull inline, internal and external references without executing.
    """
    inline, external_srcs = [], []
    for tag in soup.find_all("script"):
        if tag.get("src"):
            external_srcs.append(tag["src"])
        elif tag.string:
            inline.append(tag.string)
    return inline, external_srcs

def normalise(url):
    """
    Normalise URL for cross-source deduplication.
    The same phishing site reported by two different feeds
    hashing to the same sample_id instead of being scraped twice.
    Query strings left untouched.
    """
    parsed = urlparse(url if "://" in url else f"http://{url}")
    protocol = "https" if parsed.scheme == "https" else "http"
    hostname = (parsed.hostname or "").lower()
    try:
        # accessing .port raised ValueError if not a valid integer
        if parsed.port and parsed.port not in (80, 443):
            hostname = f"{hostname}:{parsed.port}"
    except ValueError:
        # malformed URL (invalid port string)
        return None
        
    path = parsed.path.rstrip("/")
    return f"{protocol}://{hostname}{path}"

def sample_id_for(url):
    return hashlib.sha1(url.encode("utf-8")).hexdigest()[:16]

def dedupe_seeds(seeds):
    """
    Drop duplicate seeds after merging multiple phishing sources
    keeping only the first occurance and its source label
    """
    seen = set()
    malformed_records = []
    out = []
    for seed in seeds:
        key = normalise(seed['url'])
        if not key:
            malformed_records.append({
                "source": seed.get("source", "unknown"),
                "url": seed.get("url"),
                "timestamp": datetime.now(timezone.utc).isoformat()
            })
            # when normalise returns None 
            # due to ValueError exception handling
            continue
        if key in seen:
            continue
        seen.add(key)
        out.append(seed)

    # track malformed URLs
    if malformed_records:
        write_header = not os.path.exists(MALFORMED_LOG_PATH)
        with open(MALFORMED_LOG_PATH, 'a', newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["source", "url", "timestamp"])
            if write_header:
                writer.writeheader()
            writer.writerows(malformed_records)
        log.info(f"Discarder {len(malformed_records)} malformed URLs. Logged to {MALFORMED_LOG_PATH}")
    return out

def fetch_url_with_fallback(url, session):
    """
    Attempt to fetch URL using HTTPS
    Fall back to HTTP if SSL/connection fails
    """
    try:
        return session.get(url, headers=HEADERS, 
                           timeout=REQUEST_TIMEOUT, 
                           allow_redirects=True)
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError):
        if url.startswith("https://"):
            fallback_url = url.replace("https://", "http://", 1)
            return session.get(fallback_url, headers=HEADERS, 
                               timeout=REQUEST_TIMEOUT, 
                               allow_redirects=True)

def scrape_one(seed, label):
    """
    Attempt to fetch seed URL and write static metadata, raw HTML, and scripts to disk
    """
    url = seed["url"]
    sid = sample_id_for(url)
    out_path = os.path.join(RAW_DIR, f"{sid}.json")

    if os.path.exists(out_path):
        log.info(f"[skip] already scraped: {url}")
        return None

    try:
        # use helper function with fallback
        resp = fetch_url_with_fallback(url, session)
    except requests.exceptions.RequestException as e:
        log.info(f"[discard] {label} {url} - > connection error {e}")
        return None
    
    if resp.status_code != 200:
        log.info(f"[discard] {label} {url} -> HTTP {resp.status_code}")
        return None

    final_url = resp.url
    hostname = urlparse(final_url).hostname or urlparse(url).hostname

    try:
        soup = BeautifulSoup(resp.text, "html.parser")
    except Exception as e:
        log.info(f"[discard] {label} {url} -> HTML parse error: {e}")
        return None

    inline_scripts, external_script_srcs = extract_scripts(soup)
    ssl_info = get_ssl_info(hostname) if hostname else {"has_valid_cert": False}
    whois_info = get_whois_info(hostname) if hostname else {}

    record = {
        "sample_id": sid,
        "label": label, 
        "source": seed["source"],
        "listed_at": seed.get("listed_at"),
        "seed_url": url,
        "final_url": final_url,
        "hostname": hostname,
        "http_status": resp.status_code,
        "scraped_at": datetime.now(timezone.utc).isoformat(),
        "raw_html": resp.text,
        "inline_scripts": inline_scripts,
        "external_script_srcs": external_script_srcs,
        "ssl_info": ssl_info,
        "whois_info": whois_info,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(record, f)

    log.info(f"[ok] {label} {url} -> saved {sid}.json "
              f"({len(inline_scripts)} inline scripts, "
              f"{len(external_script_srcs)} external)")

    # lighweight row for manifest
    return {
        "sample_id": sid,
        "label": label,
        "source": seed["source"],
        "seed_url": url,
        "final_url": final_url,
        "hostname": hostname,
        "http_status": resp.status_code,
        "scraped_at": record["scraped_at"],
        "n_inline_scripts": len(inline_scripts),
        "n_external_scripts": len(external_script_srcs),
    }


# HELPER FUNCTIONS
MANIFEST_FIELDS = [
    "sample_id", "label", "source", "seed_url", "final_url", "hostname",
    "http_status", "scraped_at", "n_inline_scripts", "n_external_scripts",
]

def append_to_manifest(rows):
    write_header = not os.path.exists(MANIFEST_PATH)
    with open(MANIFEST_PATH, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=MANIFEST_FIELDS)
        if write_header:
            writer.writeheader()
        for row in rows:
            if row:
                writer.writerow(row)

# main collection function
def collect_class(seeds, label, target_count):
    """
    Scrape seeds for one class until target_count successful samples
    are collected or the seed list is exhausted. Returns count collected.
    """
    import random

    # shuffle seeds before crawling to introduce some variation
    log.info("****** Seed shuffling start ******")
    random.seed(42)     # for reproducibility
    shuffled_seeds = list(seeds)
    random.shuffle(shuffled_seeds)
    log.info("****** Seed shuffling done ******")

    collected = 0
    discarded = 0
    rows = []

    with futures.ThreadPoolExecutor(max_workers=32) as executor:
        future_to_seed = {executor.submit(scrape_one, seed, label): seed for seed in seeds}
        try:
            for future in futures.as_completed(future_to_seed):
                seed = future_to_seed[future]
                try:
                    row = future.result()
                except Exception as e:
                    log.warning(f"[Discard] {label} {seed['url']} worker error -> {e}")
                    row = None
                if row:
                    collected += 1
                    rows.append(row)
                else:
                    discarded += 1
                if collected >= target_count:
                    break
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    append_to_manifest(rows)
    total_attempted = collected + discarded
    discard_rate = (discarded / total_attempted * 100) if total_attempted else 0
    log.info(
        f"****** {label} collection complete: {collected}/{target_count} target "
        f"({discarded} discarded, {discard_rate:.2f}% discard rate) ******"
    )
    return collected


def main():
    parser = argparse.ArgumentParser(description="Stage 1: scrape phishing + legitimate samples.")
    parser.add_argument("--target-per-class", type=int, default=100,
                         help="Number of samples to collect per class for THIS run")
    parser.add_argument(
        "--phishing-sources",
        nargs="+",
        choices=list(PHISHING_SEED_FETCHERS.keys()) + ["all"],
        default=["all"],
        help="Which phishing feed(s) to pull from this run. Pass a single "
             "source (e.g. --phishing-sources openphish) to poll it on its own."
             "Default 'all' pulls every registered source.",
        )
    parser.add_argument("--skip-legit", action="store_true",
                         help="Skip the Tranco legitimate pull -- useful when a run is only "
                              "polling a single phishing feed.")
    parser.add_argument("--phishstats-key", default=None,
                         help="API key for PhishStats, overriding the PHISHSTATS_API_KEY env variable.")
    args = parser.parse_args()

    log.info(f"************ Starting scrape run: target {args.target_per_class} per class ************")

    source_names = list(PHISHING_SEED_FETCHERS.keys()) if "all" in args.phishing_sources else args.phishing_sources
    log.info(f"Phishing sources for this run: {source_names}")

    # per-source extra kwargs beyond the shared "limit="
    # currently PhishStats needs one (its API key)
    source_extra_kwargs = {
        "phishstats": {"api_key": args.phishstats_key or PHISHSTATS_API_KEY},
        }

    # pull seeds from every requested phishing source and merge them
    phishing_seeds = []
    for name in source_names:
        fetcher = PHISHING_SEED_FETCHERS[name]
        extra = source_extra_kwargs.get(name, {})
        try:
            seeds = fetcher(limit=args.target_per_class * 5, **extra)
        except Exception as e:
            log.error(f"[{name}] seed fetch failed, skipping this source for this run: {e}")
            seeds = []
        phishing_seeds.extend(seeds)

    before_dedup = len(phishing_seeds)
    phishing_seeds = dedupe_seeds(phishing_seeds)
    log.info(f"Merged {before_dedup} phishing seed URLs from {source_names} "
             f"-> {len(phishing_seeds)} after cross-source dedup.")

    n_phish = collect_class(phishing_seeds, "phishing", args.target_per_class)
    n_legit = 0
    if args.skip_legit:
        log.info("--skip-legit set: not pulling Tranco legitimate seeds in this run.")
    else:
        legit_seeds = get_tranco_legit_urls(args.target_per_class)
        n_legit = collect_class(legit_seeds, "legitimate", args.target_per_class)

    log.info(f"****** Scrape run complete: {n_phish} phishing, {n_legit} legitimate ******")
    log.info(f"Manifest written to {MANIFEST_PATH}")

if __name__ == "__main__":
    try:
        log.info("********** SCRIPT EXECUTION STARTED **********")
        main()
    except Exception as e:
        log.exception(f"Fatal error during script execution: {e}")