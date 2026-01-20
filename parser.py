import os
import re
import gzip
import requests
from collections import Counter
from datetime import datetime
from bs4 import BeautifulSoup

def fetch_remote_log_filenames(base_url, token=None):
    headers = {"User-Agent": "Mozilla/5.0"}
    params = {"token": token} if token else {}

    resp = requests.get(base_url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    pre = soup.find("pre")
    if not pre:
        raise RuntimeError("No <pre> found")

    filenames = []
    for line in pre.text.splitlines():
        parts = line.split()
        if parts and parts[0].endswith((".log", ".gz")):
            filenames.append(parts[0])
    return filenames

def parse_nginx_timestamp(line):
    m = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]', line)
    if m:
        dt = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
        return dt.replace(tzinfo=None)
    m = re.search(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})', line)
    if m:
        return datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
    return None

def extract_status_code(line):
    """
    從 nginx access log line 提取 HTTP status code
    格式: ... "GET /path HTTP/1.1" 200 ...
    """
    m = re.search(r'" \d{3} ', line)
    if m:
        return m.group(0).strip().strip('"')
    # 或用更精確方法：
    parts = line.split('"')
    if len(parts) > 2:
        status_part = parts[2].strip().split()
        if status_part:
            return status_part[0]
    return None

def stream_and_filter_log(base_url, filename, token, start_dt, end_dt, out_fp, status_counter):
    import requests
    import gzip

    url = f"{base_url.rstrip('/')}/{filename}"

    with requests.get(url, stream=True, timeout=60) as resp:
        resp.raise_for_status()

        # gzip stream
        if filename.endswith(".gz"):
            f = gzip.open(resp.raw, mode="rt", encoding="utf-8", errors="replace")
        else:
            f = resp.iter_lines(decode_unicode=True)

        for line in f:
            if not line:
                continue

            ts = parse_nginx_timestamp(line)
            if not ts:
                continue

            if ts > end_dt:
                break
            if start_dt <= ts <= end_dt:
                if token and token not in line:
                    continue

                out_fp.write(line + "\n")
                code = extract_status_code(line)
                if code:
                    status_counter[code] += 1



def run_nginx_pipe_analysis(base_url, token, start_time_str, end_time_str, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    start_dt = datetime.strptime(start_time_str, "%Y/%m/%d %H:%M:%S")
    end_dt   = datetime.strptime(end_time_str, "%Y/%m/%d %H:%M:%S")

    filenames = fetch_remote_log_filenames(base_url, token)

    combined_path = os.path.join(output_dir, "combined.log")
    summary_path  = os.path.join(output_dir, "summary.log")

    status_counter = Counter()

    with open(combined_path, "w", encoding="utf-8") as out:
        for fname in filenames:
            stream_and_filter_log(base_url, fname, token, start_dt, end_dt, out, status_counter)

    # 寫 summary.log
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("HTTP Status Code Summary:\n")
        for code, count in sorted(status_counter.items()):
            f.write(f"{code}: {count}\n")

    return combined_path, summary_path

if __name__ == "__main__":
    combined, summary = run_nginx_pipe_analysis(
        base_url="http://your-nginx/logs/",
        token="YOUR_TOKEN",
        start_time_str="2026/01/20 14:15:00",
        end_time_str="2026/01/20 14:20:59",
        output_dir="./output"
    )

    print("Combined log written to:", combined)
    print("Summary log written to:", summary)