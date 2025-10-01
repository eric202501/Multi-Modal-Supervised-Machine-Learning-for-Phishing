from tqdm import tqdm
import requests
from bs4 import BeautifulSoup
import pandas as pd
import re
import math
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

def calculate_entropy(text):
    if not text:
        return 0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum([p * math.log(p, 2) for p in prob if p > 0])

def safe_anchor(js_code):
    anchors = re.findall(r'<a\b[^>]*>', js_code, re.IGNORECASE)
    total = len(anchors)
    unsafe = 0

    for tag in anchors:
        tag_lower = tag.lower()
        if 'target="_blank"' in tag_lower and 'rel="noopener' not in tag_lower and 'rel="noreferrer' not in tag_lower:
            unsafe += 1

    if total == 0:
        return 0.0

    percent = unsafe / total * 100

    return percent

def extract_all_js_features(js_code):
    features = {
    
        "eval_count": len(re.findall(r'\beval\s*\(', js_code)),
        "function_count": len(re.findall(r'\bfunction\b', js_code)),
        "document_write": len(re.findall(r'document\.write\s*\(', js_code)),
        "setTimeout": len(re.findall(r'setTimeout\s*\(', js_code)),
        "length": len(js_code),
        "entropy": calculate_entropy(js_code),
        "iframe_count": len(re.findall(r'iframe', js_code, re.IGNORECASE)),
        "window_location": len(re.findall(r'window\.location', js_code, re.IGNORECASE)),
        "createElement_count": len(re.findall(r'createElement\s*\(', js_code)),
        "appendChild_count": len(re.findall(r'appendChild\s*\(', js_code)),
        "dispatchEvent_count": len(re.findall(r'dispatchEvent\s*\(', js_code)),
        "onmouseover_count": len(re.findall(r'onmouseover', js_code)),
        "fromCharCode_count": len(re.findall(r'fromCharCode\s*\(', js_code)),
        "charCodeAt_count": len(re.findall(r'charCodeAt\s*\(', js_code)),
        "escape_count": len(re.findall(r'escape\s*\(', js_code)),
        "unescape_count": len(re.findall(r'unescape\s*\(', js_code)),
        "digit_count": len(re.findall(r'\d', js_code)),
        "hex_count": len(re.findall(r'0x[0-9a-fA-F]+', js_code)),
        "backslash_count": js_code.count('\\'),
        "pipe_count": js_code.count('|'),
        "percent_count": js_code.count('%'),
        "curly_brace_count": js_code.count('{') + js_code.count('}'),
        "space_count": js_code.count(' '),

        "parseInt_count": len(re.findall(r'\bparseInt\s*\(', js_code)),
        "classid_count": len(re.findall(r'classid', js_code, re.IGNORECASE)),
        "ActiveXObject_count": len(re.findall(r'ActiveXObject\s*\(', js_code)),
        "concat_count": len(re.findall(r'\.concat\s*\(', js_code)),
        "indexOf_count": len(re.findall(r'\.indexOf\s*\(', js_code)),
        "substring_count": len(re.findall(r'\.substring\s*\(', js_code)),
        "replace_count": len(re.findall(r'\.replace\s*\(', js_code)),
        "addEventListener_count": len(re.findall(r'\.addEventListener\s*\(', js_code)),
        "attachEvent_count": len(re.findall(r'\.attachEvent\s*\(', js_code)),
        "getElementById_count": len(re.findall(r'getElementById\s*\(', js_code)),
        "search_count": len(re.findall(r'\.search\s*\(', js_code)),
        "split_count": len(re.findall(r'\.split\s*\(', js_code)),
        "onerror_count": len(re.findall(r'onerror', js_code, re.IGNORECASE)),
        "onload_count": len(re.findall(r'onload', js_code, re.IGNORECASE)),
        "onbeforeunload_count": len(re.findall(r'onbeforeunload', js_code, re.IGNORECASE)),
        "setAttribute_count": len(re.findall(r'\.setAttribute\s*\(', js_code)),
        "charAt_count": len(re.findall(r'\.charAt\s*\(', js_code)),
        "consoleLog_count": len(re.findall(r'console\.log\s*\(', js_code)),
        "js_file_count": len(re.findall(r'\.js["\']', js_code)),
        "php_file_count": len(re.findall(r'\.php["\']', js_code)),
        "random_count": len(re.findall(r'Math\.random\s*\(', js_code)),
        "decode_count": len(re.findall(r'decode(?:URI|URIComponent)?\s*\(', js_code)),
        "toString_count": len(re.findall(r'\.toString\s*\(', js_code)),
        "encoded_char_count": len(re.findall(r'\\x[0-9a-fA-F]{2}', js_code)) +
                              len(re.findall(r'\\u[0-9a-fA-F]{4}', js_code)),
        "long_string_count": len([s for s in re.findall(r'["\']([^"\']{200,})["\']', js_code)]),
        "max_word_length": max([len(w) for w in re.findall(r'\w+', js_code)] + [0]),
        "min_word_length": min([len(w) for w in re.findall(r'\w+', js_code)] + [1000]),
        "entropy_longest_word": calculate_entropy(max(re.findall(r'\w+', js_code), key=len, default='')),
        "popup_window": 1 if "prompt(" in js_code.lower() else 0,
        "right_clic": 1 if re.search(r'event\.button\s*==\s*2', js_code) else 0
    }

    total_chars = len(js_code) if len(js_code) > 0 else 1
    features.update({
        "share_of_digits": features["digit_count"] / total_chars,
        "share_of_hex": features["hex_count"] / total_chars,
        "share_of_backslash": features["backslash_count"] / total_chars,
        "share_of_pipe": features["pipe_count"] / total_chars,
        "share_of_percent": features["percent_count"] / total_chars,
        "share_of_curly_braces": features["curly_brace_count"] / total_chars,
        "share_of_spaces": features["space_count"] / total_chars,
        "unsafe_anchor_percent": safe_anchor(js_code)
    })

    return features


def resolve_legal_url(domain):
    url_set = [f"https://{domain}", f"https://www.{domain}", f"http://{domain}", f"http://www.{domain}"]
    for url in url_set:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return url
        except:
            continue
    return None


def extract_js_from_url(url):
    scripts = []
    try:
        res = requests.get(url, timeout=8)
        soup = BeautifulSoup(res.text, "html.parser")
        for tag in soup.find_all("script"):
            if tag.get("src"):
                src_url = tag.get("src")
                if not src_url.startswith("http"):
                    src_url = urljoin(url, src_url)
                try:
                    js = requests.get(src_url, timeout=5).text
                    scripts.append(js)
                except:
                    pass
            elif tag.string:
                scripts.append(tag.string)
    except:
        pass
    return scripts



def process_url(input,resolve=False):
    if resolve:
        url = resolve_legal_url(input)
    else:
        url = input        
    if not url:
        return None
    tqdm.write(f"[抓取] {url}")
    js_list = extract_js_from_url(url)
    feature_list = [extract_all_js_features(js) for js in js_list if js]
    if feature_list:
        df_feat = pd.DataFrame(feature_list)
        summary = df_feat.max().to_dict()
        summary["url"] = url
        return summary
    return None

def process_csv_threaded(legal_csv,phish_csv,output_csv,max_worker=32):
    legal_df = pd.read_csv(legal_csv, header=None, names=["domain"])
    phish_df = pd.read_csv(phish_csv)
    phish_urls = phish_df["url"].dropna().unique()
    legal_domains = legal_df["domain"].dropna().unique()[:70001]
    legal_records = []
    phish_records = []

    print(f"開始處理釣魚網址，共 {len(phish_urls)} 筆")
    with ThreadPoolExecutor(max_workers=max_worker) as executor:
        futures = {executor.submit(process_url, url): url for url in phish_urls}
        for future in tqdm(as_completed(futures), total=len(futures), desc="釣魚網址進度"):
            result = future.result()
            if result:
                result["label"] = 1  # phish
                phish_records.append(result)
    print(f"✅ 釣魚網址完成，共 {len(phish_records)} 筆")

    print(f"開始處理合法網址，共 {len(legal_domains)} 筆")
    with ThreadPoolExecutor(max_workers=max_worker) as executor:
        futures = {executor.submit(process_url, domain, resolve=True): domain for domain in legal_domains}
        for future in tqdm(as_completed(futures), total=len(futures), desc="合法網址進度"):
            result = future.result()
            if result:
                result["label"] = 0  # legal
                legal_records.append(result)
    print(f"合法網址完成，共 {len(legal_records)} 筆")


    all_records = legal_records + phish_records
    pd.DataFrame(all_records).to_csv(output_csv, index=False)
    print(f"所有資料已寫入：{output_csv}（總共 {len(all_records)} 筆）")


if __name__ == "__main__":
    process_csv_threaded("tranco_KW2XW.csv", "verified_online.csv", "js_features.csv", max_worker=80)
