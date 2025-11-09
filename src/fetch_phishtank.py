import requests
import pandas as pd
import random
import os

# Ensure directories exist
os.makedirs("data/raw", exist_ok=True)

def fetch_phishtank(limit=10000):
    print("📥 Fetching phishing URLs from PhishTank...")
    url = "https://data.phishtank.com/data/online-valid.json"
    response = requests.get(url)
    data = response.json()

    phishing_urls = []
    for entry in data[:limit]:
        phishing_urls.append(entry["url"])

    print(f"✅ Fetched {len(phishing_urls)} phishing URLs.")
    return phishing_urls

def fetch_legitimate(limit=10000):
    print("🌐 Fetching legitimate URLs from Tranco (top websites)...")
    response = requests.get("https://tranco-list.eu/top-1m.csv.zip")
    open("tranco.csv.zip", "wb").write(response.content)

    df = pd.read_csv("tranco.csv.zip", compression="zip", header=None, names=["rank", "domain"])
    legit_urls = ["https://" + d for d in df["domain"].head(limit)]
    print(f"✅ Collected {len(legit_urls)} legitimate URLs.")
    return legit_urls

def create_dataset():
    phishing = fetch_phishtank(limit=8000)
    legitimate = fetch_legitimate(limit=8000)

    df_phish = pd.DataFrame({"url": phishing, "label": "phishing"})
    df_legit = pd.DataFrame({"url": legitimate, "label": "benign"})

    df = pd.concat([df_phish, df_legit]).sample(frac=1).reset_index(drop=True)
    df.to_csv("data/raw/phishtank_dataset.csv", index=False)
    print("💾 Saved dataset to data/raw/phishtank_dataset.csv")

if __name__ == "__main__":
    create_dataset()
