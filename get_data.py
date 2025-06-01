import requests
import pandas as pd
import time

API_KEY = "" 
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_nvd_data(start_index=1, results_per_page=2000, max_pages=1):
    all_cves = []
    for page in range(max_pages):
        params = {
            "startIndex": start_index + page * results_per_page,
            "resultsPerPage": results_per_page,
            "pubStartDate": "2024-08-04T00:00:00.000",
            "pubEndDate": "2024-10-22T00:00:00.000",
        }
        headers = {"apiKey": API_KEY} if API_KEY else {}

        print(f"[INFO] Fetching page {page + 1}...")
        response = requests.get(BASE_URL, headers=headers, params=params)
        if response.status_code != 200:
            print(f"[ERROR] Status {response.status_code}: {response.text}")
            break

        data = response.json()
        cves = data.get("vulnerabilities", [])
        all_cves.extend(cves)

        # throttle requests to avoid hitting the API rate limit
        time.sleep(3)
    return all_cves


def process_cves_to_dataframe(cves_raw):
    """
    DataFrame containing processed CVE data with CVSSv4 metrics
    """
    processed = []

    for item in cves_raw:
        cve = item.get("cve", {})
        id = cve.get("id")
        description = cve.get("descriptions", [{}])[0].get("value", "")
        metrics = cve.get("metrics", {})
        cvss_v4 = metrics.get("cvssMetricV40", [{}])[0] if "cvssMetricV40" in metrics else None

        # Skip items without CVSSv4 data
        if not cvss_v4:
            continue

        processed.append({
            "cve_id": id,
            "description": description,
            "baseScore": cvss_v4.get("cvssData", {}).get("baseScore"),
            "baseSeverity": cvss_v4.get("cvssData", {}).get("baseSeverity"),
            "vectorString": cvss_v4.get("cvssData", {}).get("vectorString"),
            "attackVector": cvss_v4.get("cvssData", {}).get("attackVector"),
            "attackComplexity": cvss_v4.get("cvssData", {}).get("attackComplexity"),
            "attackRequirements": cvss_v4.get("cvssData", {}).get("attackRequirements"),
            "privilegesRequired": cvss_v4.get("cvssData", {}).get("privilegesRequired"),
            "userInteraction": cvss_v4.get("cvssData", {}).get("userInteraction"),
            "vulnConfidentialityImpact": cvss_v4.get("cvssData", {}).get("vulnConfidentialityImpact"),
            "vulnIntegrityImpact": cvss_v4.get("cvssData", {}).get("vulnIntegrityImpact"),
            "vulnAvailabilityImpact": cvss_v4.get("cvssData", {}).get("vulnAvailabilityImpact"),
            "subConfidentialityImpact": cvss_v4.get("cvssData", {}).get("subConfidentialityImpact"),
            "subIntegrityImpact": cvss_v4.get("cvssData", {}).get("subIntegrityImpact"),
            "subAvailabilityImpact": cvss_v4.get("cvssData", {}).get("subAvailabilityImpact"),
            "exploitMaturity": cvss_v4.get("cvssData", {}).get("exploitMaturity"),
            "confidentialityRequirement": cvss_v4.get("cvssData", {}).get("confidentialityRequirement"),
            "integrityRequirement": cvss_v4.get("cvssData", {}).get("integrityRequirement"),
            "availabilityRequirement": cvss_v4.get("cvssData", {}).get("availabilityRequirement"),
            "modifiedAttackVector": cvss_v4.get("cvssData", {}).get("modifiedAttackVector"),
            "modifiedAttackComplexity": cvss_v4.get("cvssData", {}).get("modifiedAttackComplexity"),
            "modifiedAttackRequirements": cvss_v4.get("cvssData", {}).get("modifiedAttackRequirements"),
            "modifiedPrivilegesRequired": cvss_v4.get("cvssData", {}).get("modifiedPrivilegesRequired"),
            "modifiedUserInteraction": cvss_v4.get("cvssData", {}).get("modifiedUserInteraction"),
            "modifiedVulnConfidentialityImpact": cvss_v4.get("cvssData", {}).get("modifiedVulnConfidentialityImpact"),
            "modifiedVulnIntegrityImpact": cvss_v4.get("cvssData", {}).get("modifiedVulnIntegrityImpact"),
            "modifiedVulnAvailabilityImpact": cvss_v4.get("cvssData", {}).get("modifiedVulnAvailabilityImpact"),
            "modifiedSubConfidentialityImpact": cvss_v4.get("cvssData", {}).get("modifiedSubConfidentialityImpact"),
            "modifiedSubIntegrityImpact": cvss_v4.get("cvssData", {}).get("modifiedSubIntegrityImpact"),
            "modifiedSubAvailabilityImpact": cvss_v4.get("cvssData", {}).get("modifiedSubAvailabilityImpact"),
            "Safety": cvss_v4.get("cvssData", {}).get("Safety"),
            "Automatable": cvss_v4.get("cvssData", {}).get("Automatable"),
            "Recovery": cvss_v4.get("cvssData", {}).get("Recovery"),
            "valueDensity": cvss_v4.get("cvssData", {}).get("valueDensity"),
            "vulnerabilityResponseEffort": cvss_v4.get("cvssData", {}).get("vulnerabilityResponseEffort"),
            "providerUrgency": cvss_v4.get("cvssData", {}).get("providerUrgency"),
        })

    df = pd.DataFrame(processed)
    return df

if __name__ == "__main__":
    raw_cves = fetch_nvd_data(max_pages=5) 
    df_cves = process_cves_to_dataframe(raw_cves)

    print(df_cves.head())
    df_cves.to_csv("nvd_cvss4_data.csv", index=False)
    print("[INFO] Dane zapisane do pliku 'nvd_cvss4_data.csv'")
