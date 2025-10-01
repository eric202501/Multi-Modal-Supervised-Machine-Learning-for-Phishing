import pandas as pd
import dns.resolver
import concurrent.futures
import time
import random
from tqdm import tqdm
import tldextract
import re
import whois
from datetime import datetime

# DNS Resolver 設定 (Cloudflare + Google DNS)
resolver = dns.resolver.Resolver()
resolver.nameservers = ['1.1.1.1', '8.8.8.8']
resolver.timeout = 2
resolver.lifetime = 4

# 可疑關鍵字
suspicious_keywords = ['login', 'secure', 'verify', 'update', 'account', 'bank', 'paypal']
seen_domains = set()

# 解析 domain
def extract_domain_from_url(url):
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"
    return domain

# 特徵提取函數
def extract_dns_features(url):
    domain = extract_domain_from_url(url)
    if domain in seen_domains:   
        return None
    seen_domains.add(domain)

    features = {
        'domain': domain,
        'domain_length': len(domain),
        'subdomain_count': domain.count('.') - 1,
        'has_suspicious_keywords': int(any(kw in domain.lower() for kw in suspicious_keywords)),
        'A_record_count': 0,
        'ttl_avg': 0,
        'has_multiple_A_records': 0,
        'CNAME_count': 0,
        'MX_count': 0,
        'NS_count': 0,
        'TXT_count': 0,
        'has_AAAA': 0,
        'symbol_ratio': 0,
        'whois_days_to_expire': -1,
        'whois_success':0,
        'label': 1  # 可用於未來標記是否為釣魚
    }

    # === 新增特徵 ===
    symbols = re.findall(r'[./\-_=+@:?&%]', domain)
    features['symbol_ratio'] = len(symbols) 

    for _ in range(5):  
        try:
            w = whois.whois(domain)
            expiration_date = w.expiration_date

            if isinstance(expiration_date, list):  # 多個時間取最近的
                expiration_date = min(expiration_date)

            if expiration_date:
                days_left = (expiration_date - pd.Timestamp.now()).days
                features['whois_days_to_expire'] = days_left
                features['whois_success'] = 1
            break
        except:
            time.sleep(0.5)
            continue

    # === A 記錄查詢 ===
    answers = None
    for try_domain in [domain, 'www.' + domain]:
        try:
            answers = resolver.resolve(try_domain, 'A')
            break
        except dns.resolver.NoAnswer:
            continue
        except Exception:
            continue

    if answers:
        ttl_values = []
        ip_list = []
        for r in answers.response.answer:
            for item in r.items:
                if hasattr(item, 'address'):
                    ip_list.append(item.address)
                if isinstance(r, dns.rrset.RRset):
                    ttl_values.append(r.ttl)

        features['A_record_count'] = len(ip_list)
        features['has_multiple_A_records'] = int(len(ip_list) > 1)
        if ttl_values:
            features['ttl_avg'] = sum(ttl_values) / len(ttl_values)
    else:
        return None

    # CNAME
    try:
        cname_answers = resolver.resolve(domain, 'CNAME')
        features['CNAME_count'] = len(cname_answers)
    except:
        pass

    # MX
    try:
        mx_answers = resolver.resolve(domain, 'MX')
        features['MX_count'] = len(mx_answers)
    except:
        pass

    # NS
    try:
        ns_answers = resolver.resolve(domain, 'NS')
        features['NS_count'] = len(ns_answers)
    except:
        pass

    # TXT
    try:
        txt_answers = resolver.resolve(domain, 'TXT')
        features['TXT_count'] = len(txt_answers)
    except:
        pass

    # AAAA (IPv6)
    try:
        aaaa_answers = resolver.resolve(domain, 'AAAA')
        features['has_AAAA'] = int(len(aaaa_answers) > 0)
    except:
        pass

    time.sleep(random.uniform(0.01, 0.05))
    return features


# === 主程式區 ===

# 載入資料 (釣魚網址)
df = pd.read_csv('C:/Users/User/Downloads/verified_online (1).csv', encoding='big5', encoding_errors='ignore')
urls = df.iloc[:, 1].tolist()[:20000]

# 多執行緒處理 + tqdm 進度條
results = []
with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    futures = {executor.submit(extract_dns_features, url): url for url in urls}
    
    for future in tqdm(concurrent.futures.as_completed(futures), total=len(futures)):
        try:
            result = future.result()
            if result is not None:
                results.append(result)
        except Exception as e:
            print(f"Error processing {futures[future]}: {e}")

# 輸出結果
result_df = pd.DataFrame(results)
result_df.to_csv('dns_features_phinsh1000.csv', index=False)

