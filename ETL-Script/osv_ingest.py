import requests
import json
from datetime import datetime

# List of popular packages and versions to query
packages_to_check = [
    {"name": "requests", "version": "2.25.0"},
    {"name": "flask", "version": "2.0.0"},
    {"name": "django", "version": "3.2.0"},
    {"name": "numpy", "version": "1.21.0"},
    {"name": "pillow", "version": "8.2.0"},
    {"name": "pyyaml", "version": "5.4.1"},
    {"name": "cryptography", "version": "3.4.7"},
    {"name": "urllib3", "version": "1.26.4"},
    {"name": "jinja2", "version": "2.11.3"},
    {"name": "sqlalchemy", "version": "1.3.23"},
    {"name": "paramiko", "version": "2.7.2"},
    {"name": "lxml", "version": "4.6.3"},
    {"name": "pyjwt", "version": "2.1.0"},
    {"name": "werkzeug", "version": "2.0.0"},
    {"name": "setuptools", "version": "56.0.0"},
    {"name": "scikit-learn", "version": "0.24.2"},
    {"name": "matplotlib", "version": "3.4.2"},
    {"name": "pandas", "version": "1.2.4"},
    {"name": "markupsafe", "version": "1.1.1"},
    {"name": "pycryptodome", "version": "3.10.1"},
    {"name": "fastapi", "version": "0.65.1"},
    {"name": "aiohttp", "version": "3.7.4"},
    {"name": "tqdm", "version": "4.61.0"},
    {"name": "pytest", "version": "6.2.4"},
    {"name": "sentry-sdk", "version": "1.1.0"}
]

def query_osv_bulk(package_list, ecosystem="PyPI"):
    url = "https://api.osv.dev/v1/querybatch"
    payload = {
        "queries": [
            {
                "package": {"name": pkg["name"], "ecosystem": ecosystem},
                "version": pkg["version"]
            }
            for pkg in package_list
        ]
    }

    response = requests.post(url, json=payload)
    if response.status_code != 200:
        print(f"Error querying OSV API: {response.status_code} - {response.text}")
        return []

    data = response.json()
    results = []

    for query_result in data.get("results", []):
        for vuln in query_result.get("vulns", []):
            source_id = vuln.get("id")
            entity_type = "Vulnerability"
            title = vuln.get("summary", f"Vulnerability {source_id}")
            description = vuln.get("details", "")
            cve_ids = vuln.get("aliases", [])
            indicators = []
            created = vuln.get("published", "")
            modified = vuln.get("modified", "")
            node = vuln  # raw data

            record = {
                "source": "opencti",
                "source_id": source_id,
                "record_type": entity_type.lower(),
                "title": title,
                "short_description": description[:512] if description else "",
                "full_description": description,
                "cve_ids": cve_ids,
                "affected_products": [],
                "cvss": None,
                "epss_score": None,
                "exploit_available": None,
                "indicators": indicators,
                "references": [],
                "tags": [],
                "published_date": created,
                "modified_date": modified,
                "observed_at": None,
                "telemetry_metadata": None,
                "raw": node,
                "ingested_at": datetime.utcnow().isoformat() + "Z",
                "ingested_by": "opencti_extract.py"
            }

            results.append(record)

    return results

def save_to_json(data, filename="osv_opencti_bulk.json"):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"Saved {len(data)} records to {filename}")

# Run the bulk extraction
if __name__ == "__main__":
    records = query_osv_bulk(packages_to_check)
    if records:
        save_to_json(records)