import os 
import re 
import pandas as pd 
from bs4 import BeautifulSoup

def extract_features_from_html(html):
    soup = BeautifulSoup(html, "html.parser")

    # 所有連結
    links = soup.find_all('a')
    hrefs = [link.get('href', '') for link in links]
    external_links = [h for h in hrefs if h.startswith('http')]
    https_links = [h for h in hrefs if h.startswith('https://')]

    # 所有 script
    scripts = soup.find_all('script', src=True)
    external_scripts = [s for s in scripts if not s['src'].startswith(('/', '.', '#'))]

    # 敏感關鍵字
    sensitive_keywords = re.compile(r"(bank|verify|account|secure|update|confirm)", re.I)
    has_sensitive_keywords = int(bool(soup.find_all(string=sensitive_keywords)))

    # 驚嘆號數量與全大寫單字
    text = soup.get_text(separator=' ', strip=True)
    num_exclamations = text.count('!')
    num_uppercase_words = sum(1 for word in text.split() if word.isupper() and len(word) > 1)

    # 平均連結長度
    link_lengths = [len(h) for h in hrefs if h]
    avg_link_length = sum(link_lengths) / len(link_lengths) if link_lengths else 0

    # 是否有密碼欄位
    has_password_field = int(bool(soup.find_all('input', {'type': 'password'})))

    # 外部 CSS 檔案數量
    css_links = [link for link in soup.find_all('link', rel='stylesheet') if link.get('href')]
    external_css = [c for c in css_links if c['href'].startswith('http')]

    # Inline styles
    num_inline_styles = len(soup.select('[style]'))

    features = {
        "num_links": len(links),
        "num_forms": len(soup.find_all('form')),
        "num_inputs": len(soup.find_all('input')),
        "num_scripts": len(soup.find_all('script')),
        "num_iframes": len(soup.find_all('iframe')),
        "has_login": int(bool(soup.find_all(string=re.compile('login', re.I)))),
        "num_meta": len(soup.find_all('meta')),
        "text_length": len(text),
        "has_password_field": has_password_field,
        "has_https_links": int(bool(https_links)),
        "external_script_ratio": len(external_scripts) / len(scripts) if scripts else 0,
        "external_links_ratio": len(external_links) / len(links) if links else 0,
        "has_sensitive_keywords": has_sensitive_keywords,
        "num_exclamations": num_exclamations,
        "num_uppercase_words": num_uppercase_words,
        "avg_link_length": avg_link_length,
        "num_divs": len(soup.find_all('div')),
        "num_images": len(soup.find_all('img')),
        "num_inline_styles": num_inline_styles,
        "num_css_files": len(css_links),
        "num_external_css": len(external_css)
    }

    return features

def load_data(phishing_dir, legit_dir): 
    data = [] 
    for directory, label in [(phishing_dir, 1), (legit_dir, 0)]: 
        for file in os.listdir(directory): 
            filepath = os.path.join(directory, file) 
            try: 
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f: html = f.read() features = extract_features_from_html(html) 
                features['label'] = label 
                data.append(features) 
            except Exception as e: 
                print(f"Error reading {filepath}: {e}") 
        return pd.DataFrame(data) # 替換成你實際的資料夾路徑 
    df = load_data('C:/Users/User/Downloads/training/Phish', 'C:/Users/User/Downloads/training/NotPhish') 
    df.to_csv('features.csv', index=False) 
    print("已儲存為 features.csv")