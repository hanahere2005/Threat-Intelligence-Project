

import os
import requests
import json
import time

OTX_API_KEY = os.getenv("OTX_API_KEY", "")
BASE = "https://otx.alienvault.com/api/v1"
OUTPUT_FILE = "otx.jsonl"
REQUEST_TIMEOUT = 30
PAGE_SIZE = 50
SLEEP_BETWEEN = 1


def get_headers():
    headers = {"Accept": "application/json"}
    if OTX_API_KEY:
        headers["X-OTX-API-KEY"] = OTX_API_KEY
    return headers


def fetch_subscribed_pulses(max_pages: int = 5) -> list:
    """Fetch pulses you are subscribed to (requires API key)."""
    page = 1
    all_pulses = []
    while page <= max_pages:
        url = f"{BASE}/pulses/subscribed?page={page}&limit={PAGE_SIZE}"
        print(f"[INFO] GET {url}")
        resp = requests.get(url, headers=get_headers(), timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            print(f"[WARN] {resp.status_code}: {resp.text}")
            break
        data = resp.json()
        results = data.get("results", [])
        if not results:
            break
        all_pulses.extend(results)
        print(f"[INFO] Got {len(results)} pulses from page {page}")
        page += 1
        time.sleep(SLEEP_BETWEEN)
    return all_pulses


def fetch_search_pulses(query: str, max_pages: int = 2) -> list:
    
    page = 1
    all_pulses = []
    while page <= max_pages:
        url = f"{BASE}/search/pulses?q={query}&page={page}&limit={PAGE_SIZE}"
        print(f"[INFO] GET {url}")
        resp = requests.get(url, headers=get_headers(), timeout=REQUEST_TIMEOUT)
        if resp.status_code != 200:
            print(f"[WARN] {resp.status_code}: {resp.text}")
            break
        data = resp.json()
        results = data.get("results", [])
        if not results:
            break
        all_pulses.extend(results)
        print(f"[INFO] Got {len(results)} pulses from page {page}")
        page += 1
        time.sleep(SLEEP_BETWEEN)
    return all_pulses


def write_pulses(pulses: list):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for p in pulses:
            rec = {
                "source": "alienvault_otx",
                "source_id": p.get("id"),
                "name": p.get("name"),
                "author": p.get("author_name"),
                "description": p.get("description"),
                "tags": p.get("tags"),
                "indicators": p.get("indicators"),
                "raw": p,
            }
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    print(f"[INFO] Written {len(pulses)} pulses to {OUTPUT_FILE}")


def main():
    
    pulses = fetch_subscribed_pulses(max_pages=3)


    print(f"[INFO] Total pulses fetched: {len(pulses)}")
    write_pulses(pulses)


if __name__ == "__main__":
    main()
