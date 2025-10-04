import requests, json, os, datetime

OUT_DIR = "../ingest_results"
CIRCL_URL = "https://cve.circl.lu/api/last"

def fetch_circl():
    os.makedirs(OUT_DIR, exist_ok=True)
    resp = requests.get(CIRCL_URL)
    data = resp.json()
    results = []
    for item in data:
        doc = {
            "title": item.get("id", ""),
            "description": item.get("summary", ""),
            "category": "vulnerability",
            "tags": ["CIRCL", "CVE"],
            "metadata": {
                "Published": item.get("Published", ""),
                "Modified": item.get("Modified", "")
            },
            "original_source_url": CIRCL_URL,
            "actual_url": CIRCL_URL,
            "ingested_at": datetime.datetime.utcnow().isoformat(),
            "raw_data": item
        }
        results.append(doc)
    out_path = os.path.join(OUT_DIR, "circl_cve_data.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"Saved {len(results)} items to {out_path}")

if __name__ == "__main__":
    fetch_circl()