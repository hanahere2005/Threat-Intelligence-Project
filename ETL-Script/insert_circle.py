import os
import glob
import json
import datetime
import psycopg2
from psycopg2.extras import Json

# PostgreSQL configuration
DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "Threat-Intelligence-Database-Schema",  # Your DB name
    "user": "postgres",               # Your DB user
    "password": "root@123"
}

# Directory where CIRCL JSON files are stored
CIRCLE_JSON_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../ingest_results"))

def find_latest_circl_json():
    """Find the latest circl_cve_data*.json file"""
    print(f"🔍 Looking for CIRCL JSON files in: {CIRCLE_JSON_DIR}")
    files = glob.glob(os.path.join(CIRCLE_JSON_DIR, "circl_cve_data*.json"))
    print(f"📝 Files found: {files}")
    if not files:
        return None
    latest_file = max(files, key=os.path.getctime)
    print(f"✅ Latest CIRCL JSON: {latest_file}")
    return latest_file

def parse_timestamp(ts_str):
    """Convert string to timestamp, fallback to None"""
    if not ts_str:
        return None
    try:
        return datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
    except:
        return None

def insert_circl_json_to_postgres(json_file_path: str):
    if not os.path.exists(json_file_path):
        print(f"❌ File not found: {json_file_path}")
        return

    with open(json_file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not data:
        print("❌ No CIRCL items found in JSON.")
        return

    print(f"🔄 Loaded {len(data)} CIRCL items from JSON.")

    # Connect to PostgreSQL
    try:
        conn = psycopg2.connect(**DB_CONFIG)
        conn.autocommit = True
        cursor = conn.cursor()
        print("✅ Connected to PostgreSQL.")
    except Exception as e:
        print(f"❌ Database connection failed: {e}")
        return

    insert_query = """
    INSERT INTO "Storing-Threat-Data".cves (
        external_id, source, title, description, category,
        severity, cvss_score, cvss_vector,
        cwe_list, cwe_ids,
        vendors, products, affected_products_count,
        references_count, "references", tags,
        original_source_url, actual_url, source_name,
        published_date, last_updated_from_source,
        ingested_at, data_version, metadata
    )
    VALUES (
        %(external_id)s, %(source)s, %(title)s, %(description)s, %(category)s,
        %(severity)s, %(cvss_score)s, %(cvss_vector)s,
        %(cwe_list)s, %(cwe_ids)s,
        %(vendors)s, %(products)s, %(affected_products_count)s,
        %(references_count)s, %(references)s::jsonb, %(tags)s,
        %(original_source_url)s, %(actual_url)s, %(source_name)s,
        %(published_date)s, %(last_updated_from_source)s,
        %(ingested_at)s, %(data_version)s, %(metadata)s::jsonb
    )
    ON CONFLICT (external_id) DO UPDATE
    SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        category = EXCLUDED.category,
        severity = EXCLUDED.severity,
        cvss_score = EXCLUDED.cvss_score,
        cvss_vector = EXCLUDED.cvss_vector,
        cwe_list = EXCLUDED.cwe_list,
        cwe_ids = EXCLUDED.cwe_ids,
        vendors = EXCLUDED.vendors,
        products = EXCLUDED.products,
        affected_products_count = EXCLUDED.affected_products_count,
        references_count = EXCLUDED.references_count,
        "references" = EXCLUDED."references",
        tags = EXCLUDED.tags,
        last_updated_from_source = EXCLUDED.last_updated_from_source,
        ingested_at = EXCLUDED.ingested_at,
        metadata = EXCLUDED.metadata;
    """

    for item in data:
        # Use title or fallback to raw_data.document.tracking.id
        external_id = item.get("title") or \
                      item.get("raw_data", {}).get("document", {}).get("tracking", {}).get("id")

        if not external_id:
            print("❌ Skipping item with no ID")
            continue

        # Extract references
        references = item.get("raw_data", {}).get("document", {}).get("references", [])

        # Extract vendors/products if available
        vendors = []
        products = []
        product_tree = item.get("raw_data", {}).get("product_tree", {}).get("branches", [])
        def extract_products(branches):
            for branch in branches:
                if branch.get("category") == "vendor":
                    vendors.append(branch.get("name"))
                if branch.get("category") == "product_name":
                    products.append(branch.get("name"))
                if "branches" in branch:
                    extract_products(branch["branches"])
        extract_products(product_tree)

        try:
            cursor.execute(insert_query, {
                "external_id": external_id,
                "source": "CIRCL",
                "title": item.get("title") or external_id,
                "description": item.get("description"),
                "category": item.get("category", "vulnerability"),
                "severity": None,
                "cvss_score": None,
                "cvss_vector": None,
                "cwe_list": [],
                "cwe_ids": [],
                "vendors": vendors,
                "products": products,
                "affected_products_count": len(products),
                "references_count": len(references),
                "references": Json(references),
                "tags": item.get("tags", ["CIRCL"]),
                "original_source_url": item.get("original_source_url"),
                "actual_url": item.get("actual_url"),
                "source_name": "CIRCL",
                "published_date": parse_timestamp(item.get("metadata", {}).get("Published")),
                "last_updated_from_source": parse_timestamp(item.get("metadata", {}).get("Modified")),
                "ingested_at": parse_timestamp(item.get("ingested_at")),
                "data_version": "1.0",
                "metadata": Json(item)
            })
        except Exception as e:
            print(f"❌ Failed to insert {external_id}: {e}")

    cursor.close()
    conn.close()
    print("✅ All CIRCL items inserted successfully.")

if __name__ == "__main__":
    latest_file = find_latest_circl_json()
    if latest_file:
        insert_circl_json_to_postgres(latest_file)
