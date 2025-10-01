import pandas as pd

def extract_features(input_csv: str, output_csv: str, features: list) -> None:
    """
    讀取 input_csv，僅保留 features 清單中指定的欄位，
    並將結果寫入 output_csv。
    """
    # 1. 讀取原始資料
    df = pd.read_csv(input_csv)
    
    # 2. 檢查缺少的欄位
    missing = [col for col in features if col not in df.columns]
    if missing:
        raise KeyError(f"找不到以下欄位，請確認資料集是否包含它們：{missing}")
    
    # 3. 只選取指定的特徵欄位
    selected_df = df[features]
    
    # 4. 輸出到新的 CSV 檔，並關閉索引
    selected_df.to_csv(output_csv, index=False, encoding='utf-8-sig')

if __name__ == "__main__":
    FEATURES = [
    "length_url",
    "length_hostname",
    "ip",
    "nb_dots",
    "nb_hyphens",
    "nb_at",
    "nb_qm",
    "nb_and",
    "nb_or",
    "nb_eq",
    "nb_underscore",
    "nb_tilde",
    "nb_percent",
    "nb_slash",
    "nb_star",
    "nb_colon",
    "nb_comma",
    "nb_semicolumn",
    "nb_dollar",
    "nb_space",
    "nb_www",
    "nb_com",
    "nb_dslash",
    "http_in_path",
    "https_token",
    "ratio_digits_url",
    "ratio_digits_host",
    "punycode",
    "port",
    "tld_in_path",
    "tld_in_subdomain",
    "abnormal_subdomain",
    "nb_subdomains",
    "prefix_suffix",
    "random_domain",
    "shortening_service",
    "path_extension",
    "nb_redirection",
    "nb_external_redirection",
    "length_words_raw",
    "char_repeat",
    "shortest_words_raw",
    "shortest_word_host",
    "shortest_word_path",
    "longest_words_raw",
    "longest_word_host",
    "longest_word_path",
    "avg_words_raw",
    "avg_word_host",
    "avg_word_path",
    "phish_hints",
    "domain_in_brand",
    "brand_in_subdomain",
    "brand_in_path",
    "suspecious_tld",
    "statistical_report",
    "web_traffic",
    "google_index",
    "page_rank"


    ]
    FEATURES.append("status")
    
    chose="url_external_features_only.csv"
    extract_features("dataset_phishing.csv", chose, FEATURES)
    print(f"已將指定特徵抽取到{chose}")
