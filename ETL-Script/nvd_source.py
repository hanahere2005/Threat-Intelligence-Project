import requests
import json
import datetime
import time
import os
from typing import Dict, List, Optional

def fetch_nvd_enhanced(days_back: int = 7, max_results: int = 30):
    """
    Enhanced NVD fetcher with all necessary fields for database storage
    """
    NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    end_date = datetime.datetime.now(datetime.timezone.utc)
    start_date = end_date - datetime.timedelta(days=days_back)
    
    start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    end_date_str = end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
    
    HEADERS = {
        "User-Agent": "ThreatIntelBot/1.0",
        "Accept": "application/json"
    }
    
    results = []
    start_index = 0
    
    print("🔍 ENHANCED NVD THREAT INTELLIGENCE FETCHER")
    print("=" * 70)
    print(f"📅 Date Range: {start_date_str} to {end_date_str}")
    print(f"🎯 Target: {max_results} CVEs")
    print("=" * 70)
    
    while len(results) < max_results:
        params = {
            "pubStartDate": start_date_str,
            "pubEndDate": end_date_str,
            "startIndex": start_index,
            "resultsPerPage": min(50, max_results - len(results))
        }
        
        print(f"\n📡 Fetching batch {start_index//50 + 1}...")
        
        try:
            resp = requests.get(NVD_URL, params=params, headers=HEADERS, timeout=30)
            
            if resp.status_code != 200:
                print(f"❌ HTTP Error {resp.status_code}")
                break
                
            data = resp.json()
            vulnerabilities = data.get("vulnerabilities", [])
            
            if not vulnerabilities:
                print("✅ No more CVEs found.")
                break
            
            for vuln in vulnerabilities:
                cve_data = vuln["cve"]
                cve_info = extract_cve_details_enhanced(cve_data)
                results.append(cve_info)
                
                # Display in terminal
                display_cve_enhanced(cve_info)
            
            start_index += len(vulnerabilities)
            
            # Rate limiting
            time.sleep(1)
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            break
        except json.JSONDecodeError as e:
            print(f"❌ JSON parsing error: {e}")
            break
        except Exception as e:
            print(f"❌ Unexpected error: {e}")
            break
    
    # Show summary
    show_enhanced_summary(results)
    
    # Save to JSON file
    save_enhanced_data(results)
    
    return results

def extract_cve_details_enhanced(cve_data: Dict) -> Dict:
    """Extract ALL necessary CVE details for database storage"""
    cve_id = cve_data.get("id", "Unknown")
    
    # Get description
    descriptions = cve_data.get("descriptions", [])
    description = next((desc["value"] for desc in descriptions if desc["lang"] == "en"), "No description")
    
    # Extract metrics with FULL details
    metrics = cve_data.get("metrics", {})
    severity = "Unknown"
    cvss_score = None  # Use None instead of "N/A" for database
    cvss_vector = None
    cvss_details = {}

    # Check all CVSS versions for the most complete data
    for cvss_version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        if cvss_version in metrics and metrics[cvss_version]:
            cvss_metric = metrics[cvss_version][0]
            cvss_data = cvss_metric.get("cvssData", {})
            severity = cvss_metric.get("baseSeverity", "Unknown")
            cvss_score = cvss_data.get("baseScore")
            cvss_vector = cvss_data.get("vectorString")
            cvss_details = {
                "attackVector": cvss_data.get("attackVector"),
                "attackComplexity": cvss_data.get("attackComplexity"),
                "privilegesRequired": cvss_data.get("privilegesRequired"),
                "userInteraction": cvss_data.get("userInteraction"),
                "scope": cvss_data.get("scope"),
                "confidentialityImpact": cvss_data.get("confidentialityImpact"),
                "integrityImpact": cvss_data.get("integrityImpact"),
                "availabilityImpact": cvss_data.get("availabilityImpact"),
                "version": cvss_version.replace("cvssMetricV", "CVSS "),
                "exploitabilityScore": cvss_metric.get("exploitabilityScore"),
                "impactScore": cvss_metric.get("impactScore")
            }
            break
    
    # Extract CWE information
    weaknesses = cve_data.get("weaknesses", [])
    cwe_list = []
    cwe_ids = []
    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            if desc["lang"] == "en":
                cwe_list.append(desc["value"])
                # Extract CWE ID from description if possible
                if "CWE-" in desc["value"]:
                    cwe_ids.append(desc["value"].split("CWE-")[1].split(" ")[0])
    
    # Extract AFFECTED PRODUCTS (CPE data) - CRITICAL for automotive context
    configurations = cve_data.get("configurations", [])
    affected_products = []
    vendors = set()
    products = set()
    
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                if cpe_match.get("vulnerable", False):
                    cpe_uri = cpe_match.get("cpe23Uri", "")
                    cpe_parts = cpe_uri.split(":")
                    if len(cpe_parts) > 4:
                        vendor = cpe_parts[3]
                        product = cpe_parts[4]
                        vendors.add(vendor)
                        products.add(product)
                        
                        affected_products.append({
                            "vendor": vendor,
                            "product": product,
                            "cpe23Uri": cpe_uri,
                            "versionEndExcluding": cpe_match.get("versionEndExcluding"),
                            "versionEndIncluding": cpe_match.get("versionEndIncluding"),
                            "versionStartExcluding": cpe_match.get("versionStartExcluding"),
                            "versionStartIncluding": cpe_match.get("versionStartIncluding"),
                            "vulnerable": cpe_match.get("vulnerable", True)
                        })
    
    # Extract REFERENCES
    references = cve_data.get("references", [])
    ref_urls = []
    for ref in references:
        ref_data = {
            "url": ref.get("url", ""),
            "source": ref.get("source", ""),
            "tags": ref.get("tags", [])
        }
        ref_urls.append(ref_data)
    
    # Build PROPER TAGS for searching/filtering
    tags = ["CVE", "vulnerability", f"severity:{severity.lower()}"]
    
    # Add CWE tags
    if cwe_list:
        tags.extend([f"cwe:{cwe}" for cwe in cwe_list[:2]])
    if cwe_ids:
        tags.extend([f"cwe_id:{cwe_id}" for cwe_id in cwe_ids[:3]])
    
    # Add vendor and product tags
    tags.extend([f"vendor:{vendor}" for vendor in list(vendors)[:3]])
    tags.extend([f"product:{product}" for product in list(products)[:3]])
    
    # Add additional tags based on CVSS metrics
    if cvss_details.get("attackVector"):
        tags.append(f"attack_vector:{cvss_details['attackVector'].lower()}")
    if cvss_details.get("privilegesRequired"):
        tags.append(f"privileges:{cvss_details['privilegesRequired'].lower()}")
    
    # Remove duplicates and ensure tags are clean
    tags = list(set([tag.lower().replace(" ", "_") for tag in tags]))
    
    # Get timestamps
    published_date = cve_data.get("published", "")
    last_modified = cve_data.get("lastModified", "")
    
    # FINAL STRUCTURE with ALL necessary fields for database
    return {
        # === CORE IDENTIFICATION ===
        "external_id": cve_id,
        "title": cve_id,
        "description": description,
        
        # === CATEGORIZATION ===
        "category": "vulnerability",
        "severity": severity,
        "cvss_score": cvss_score,
        
        # === RICH METADATA (stores everything else) ===
        "metadata": {
            # Basic CVE info
            "published_date": published_date,
            "last_modified_date": last_modified,
            "vuln_status": cve_data.get("vulnStatus", ""),
            "source_identifier": cve_data.get("sourceIdentifier", ""),
            
            # CVSS details
            "cvss_vector": cvss_vector,
            "cvss_details": cvss_details,
            
            # Weakness information
            "cwe_list": cwe_list,
            "cwe_ids": cwe_ids,
            
            # Affected products
            "affected_products_count": len(affected_products),
            "affected_products_sample": affected_products[:5],  # First 5 products
            "vendors": list(vendors)[:10],  # Top 10 vendors
            "products": list(products)[:10],  # Top 10 products
            
            # References
            "references_count": len(ref_urls),
            "references_sample": ref_urls[:10],  # First 10 references
            
            # Source analysis info
            "metrics_available": list(metrics.keys()),
            
            # Raw data preservation (optional - for debugging)
            "raw_configurations_count": len(configurations),
            "raw_weaknesses_count": len(weaknesses)
        },
        
        # === SEARCHABLE TAGS ===
        "tags": tags,
        
        # === SOURCE TRACKING (CRITICAL for database) ===
        "original_source_url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        "actual_url": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "source_name": "NVD API",
        
        # === TIMESTAMPS ===
        "published_date": published_date,
        "last_updated_from_source": last_modified,
        
        # === PROCESSING INFO ===
        "ingested_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "data_version": "1.0"
    }

def display_cve_enhanced(cve_info: Dict):
    """Enhanced terminal display showing all critical fields"""
    severity_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠", 
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "Unknown": "⚪"
    }
    
    icon = severity_icons.get(cve_info["severity"], "⚪")
    
    print(f"\n{icon} {cve_info['external_id']}")
    print(f"   📊 Severity: {cve_info['severity']} | CVSS: {cve_info['cvss_score'] or 'N/A'}")
    print(f"   📅 Published: {cve_info['published_date'][:10]}")
    print(f"   🏷️  Status: {cve_info['metadata']['vuln_status']}")
    print(f"   📝 Desc: {cve_info['description'][:100]}...")
    
    # Show affected vendors/products
    vendors = cve_info['metadata'].get('vendors', [])[:3]
    if vendors:
        print(f"   🏭 Vendors: {', '.join(vendors)}")
    
    # Show CWEs
    if cve_info['metadata']['cwe_list']:
        print(f"   🐛 CWE: {', '.join(cve_info['metadata']['cwe_list'][:2])}")
    
    # Show key tags
    key_tags = [tag for tag in cve_info['tags'] if any(x in tag for x in ['vendor:', 'product:', 'cwe:'])][:4]
    if key_tags:
        print(f"   🏷️  Tags: {', '.join(key_tags)}")
    
    # Show affected products count
    affected_count = cve_info['metadata'].get('affected_products_count', 0)
    print(f"   📦 Affected Products: {affected_count}")
    
    print("   " + "─" * 50)

def show_enhanced_summary(results: List[Dict]):
    """Enhanced summary with more detailed analytics"""
    print("\n" + "=" * 70)
    print("📊 ENHANCED FETCH SUMMARY")
    print("=" * 70)
    
    # Severity breakdown
    severity_count = {}
    for cve in results:
        sev = cve["severity"]
        severity_count[sev] = severity_count.get(sev, 0) + 1
    
    print("\n🔴 SEVERITY DISTRIBUTION:")
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "Unknown"]:
        count = severity_count.get(severity, 0)
        if count > 0:
            icon = {
                "CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", 
                "LOW": "🟢", "Unknown": "⚪"
            }.get(severity, "⚪")
            print(f"   {icon} {severity}: {count} CVEs")
    
    # CVSS scoring stats
    scored_cves = [cve for cve in results if cve["cvss_score"] is not None]
    high_critical = [cve for cve in results if cve["severity"] in ["HIGH", "CRITICAL"]]
    
    print(f"\n📈 SCORING STATS:")
    print(f"   ✅ CVEs with CVSS scores: {len(scored_cves)}/{len(results)}")
    print(f"   🚨 High/Critical CVEs: {len(high_critical)}")
    
    # Vendor statistics
    all_vendors = []
    all_products = []
    for cve in results:
        all_vendors.extend(cve['metadata'].get('vendors', []))
        all_products.extend(cve['metadata'].get('products', []))
    
    from collections import Counter
    vendor_counts = Counter(all_vendors)
    product_counts = Counter(all_products)
    
    print(f"\n🏭 TOP VENDORS:")
    for vendor, count in vendor_counts.most_common(5):
        print(f"   • {vendor}: {count} CVEs")
    
    print(f"\n📦 TOP PRODUCTS:")
    for product, count in product_counts.most_common(5):
        print(f"   • {product}: {count} CVEs")
    
    print(f"\n📦 TOTAL FETCHED: {len(results)} CVEs")

def save_enhanced_data(results: List[Dict]):
    """Save enhanced data to JSON file with proper structure"""
    if not results:
        print("❌ No data to save")
        return
        
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = f"nvd_enhanced_data_{timestamp}.json"
    
    # Create enhanced output structure
    output_data = {
        "metadata": {
            "fetch_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "source": "NVD API v2.0",
            "total_cves": len(results),
            "date_range": {
                "days_back": 7,
                "start_date": (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=7)).isoformat(),
                "end_date": datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
        },
        "cves": results
    }
    
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2, ensure_ascii=False)
    
    # Also save a simplified version for quick analysis
    simple_filename = f"nvd_simple_export_{timestamp}.json"
    simple_data = []
    for cve in results:
        simple_data.append({
            "external_id": cve["external_id"],
            "severity": cve["severity"],
            "cvss_score": cve["cvss_score"],
            "published_date": cve["published_date"],
            "vendors": cve["metadata"].get("vendors", [])[:3],
            "products": cve["metadata"].get("products", [])[:3],
            "description": cve["description"][:200]
        })
    
    with open(simple_filename, "w", encoding="utf-8") as f:
        json.dump(simple_data, f, indent=2, ensure_ascii=False)
    
    file_path = os.path.abspath(filename)
    simple_path = os.path.abspath(simple_filename)
    
    print(f"\n💾 ENHANCED DATA SAVED:")
    print(f"   📁 Full data: {filename}")
    print(f"   📁 Simple export: {simple_filename}")
    print(f"   📍 Full path: {file_path}")

def quick_test():
    """Quick test to verify API is working"""
    print("🚀 QUICK API TEST")
    print("=" * 40)
    
    try:
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=2"
        response = requests.get(url, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            total = data.get('totalResults', 0)
            print(f"✅ API is working! Total CVEs available: {total}")
            
            # Show 2 sample CVEs with basic info
            for vuln in data.get('vulnerabilities', [])[:2]:
                cve_id = vuln['cve'].get('id', 'Unknown')
                print(f"   Sample: {cve_id}")
                
        else:
            print(f"❌ API returned status: {response.status_code}")
            
    except Exception as e:
        print(f"❌ API test failed: {e}")

if __name__ == "__main__":
    # Run quick test first
    quick_test()
    
    print("\n" + "=" * 70)
    
    # Run main enhanced fetcher
    fetch_nvd_enhanced(days_back=3, max_results=20)