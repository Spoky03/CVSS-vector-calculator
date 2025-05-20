import requests
import pandas as pd
import time

API_KEY = "" 
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_data(start_index=0, results_per_page=2000, max_pages=1):
    """
    Pobiera dane z API NVD CVE entries.
    """
    all_cves = []

    for page in range(max_pages):
        params = {
            "startIndex": start_index + page * results_per_page,
            "resultsPerPage": results_per_page,
            "cvssV4Metrics": "true",  
            "pubStartDate": "2024-01-01T00:00:00.000Z",
            "pubEndDate": "2025-01-01T00:00:00.000Z",
        }

        headers = {"apiKey": API_KEY} if API_KEY else {}

        print(f"[INFO] Fetching page {page + 1}...")
        response = requests.get(BASE_URL)

        if response.status_code != 200:
            print(f"[ERROR] Status {response.status_code}: {response.text}")
            break

        data = response.json()
        cves = data.get("vulnerabilities", [])
        all_cves.extend(cves)

        time.sleep(1.5)  # throttling

    return all_cves


def process_cves_to_dataframe(cves_raw):
    """
    DataFrame zawierający przetworzone dane CVE
    """
    processed = []

    for item in cves_raw:
        cve = item.get("cve", {})
        id = cve.get("id")
        description = cve.get("descriptions", [{}])[0].get("value", "")
        metrics = cve.get("metrics", {})
        cvss_v2 = metrics.get("cvssMetricV2", [{}])[0] if "cvssMetricV2" in metrics else {}

        processed.append({
            "cve_id": id,
            "description": description,
            "cvss_v2_base_score": cvss_v2.get("cvssData", {}).get("baseScore"),
            "cvss_v2_vector": cvss_v2.get("cvssData", {}).get("vectorString"),
            "exploitability_score": cvss_v2.get("exploitabilityScore"),
            "impact_score": cvss_v2.get("impactScore"),
        })

    df = pd.DataFrame(processed)
    return df


if __name__ == "__main__":
    raw_cves = fetch_nvd_data(max_pages=1) 
    df_cves = process_cves_to_dataframe(raw_cves)

    print(df_cves.head())
    df_cves.to_csv("nvd_cvss4_data.csv", index=False)
    print("[INFO] Dane zapisane do pliku 'nvd_cvss4_data.csv'")
