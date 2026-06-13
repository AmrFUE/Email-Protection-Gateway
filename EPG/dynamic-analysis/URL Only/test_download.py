import pandas as pd
import requests
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor

download_extensions = [
    ".exe",".zip",".rar",".7z",".msi",".apk",
    ".pdf",".doc",".docx",".xls",".xlsx",
    ".ppt",".pptx",".js",".scr"
]

def file_download_detected(url):

    print("Checking:", url)

    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.text, "html.parser")

        for tag in soup.find_all("a", href=True):
            link = tag["href"].lower()

            for ext in download_extensions:
                if ext in link:
                    print("DONE:", url, "→ download detected")
                    return 1

        print("DONE:", url, "→ no download")
        return 0

    except Exception as e:
        print("ERROR:", url)
        return 0


# قراءة الداتاسيت
df = pd.read_csv("urls.csv")

urls = df["url"].tolist()

# تشغيل parallel
with ThreadPoolExecutor(max_workers=10) as executor:
    results = list(executor.map(file_download_detected, urls))

df["file_download_detected"] = results

df.to_csv("dataset_with_feature.csv", index=False)

print("\nAll URLs processed ✔")