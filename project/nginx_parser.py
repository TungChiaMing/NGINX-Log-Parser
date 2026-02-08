import os
import re
import gzip
import shutil
import uuid
import requests
from collections import Counter
from datetime import datetime, timedelta
from bs4 import BeautifulSoup
import requests
import gzip

from io import BytesIO

from project import utils
from flask import Blueprint, flash, redirect, render_template, request, send_from_directory, session, url_for

log_parser_router = Blueprint("log_parser", __name__)

@log_parser_router.route("/", methods=["GET", "POST"])
@utils.login_required
def index():
    default_end = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    default_start = (datetime.now() - timedelta(hours=1)).strftime("%Y/%m/%d %H:%M:%S")

    form_data = {
        "base_url": "",
        "token": "",
        "start_time": default_start,
        "end_time": default_end
    }

    sessions = os.path.join(os.getcwd(), "sessions")


    if request.method == "POST":
        form_data.update({
            "base_url": request.form.get("base_url", ""),
            "token": request.form.get("token", ""),
            "start_time": request.form.get("start_time", default_start),
            "end_time": request.form.get("end_time", default_end),
        })

        session["last_form_data_log_parser"] = form_data

        session_id = str(uuid.uuid4())
        session_dir = os.path.join(sessions, session_id)
        os.makedirs(session_dir, exist_ok=True)

        try:
            results = []

            raw_base_urls = form_data["base_url"]

            base_urls = [
                u.strip()
                for u in raw_base_urls.split(",")
                if u.strip()
            ]

            for base_url in base_urls:
                url_id = base_url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_").replace("?", "_").replace("&", "_").replace("=", "_")

                url_dir = os.path.join(session_dir, url_id)
                os.makedirs(url_dir, exist_ok=True)

                combined_log, summary_log = run_nginx_log_analysis(
                    base_url=base_url,
                    token=form_data["token"],
                    start_time_str=form_data["start_time"],
                    end_time_str=form_data["end_time"],
                    output_dir=url_dir
                )

                results.append({
                    "base_url": base_url,
                    "combined_log": os.path.basename(combined_log),
                    "summary_log": os.path.basename(summary_log),
                    "combined_content": utils.read_text_file_safe(combined_log),
                    "summary_content": utils.read_text_file_safe(summary_log),
                    "url_id": url_id
                })

            
            return render_template(
                "log_parser_result.html",
                success=True,
                session_id=session_id,
                results=results,
                username=session.get("username")
            )

        except Exception as e:
            shutil.rmtree(session_dir, ignore_errors=True)
            return render_template(
                "result.html",
                success=False,
                error=str(e),
                username=session.get("username")
            )

    if "last_form_data_log_parser" in session:
        form_data = session["last_form_data_log_parser"]

    return render_template(
        "log_parser.html",
        **form_data,
        username=session.get("username")
    )

@log_parser_router.route("/download/<session_id>/<path:filename>")
@utils.login_required
def download(session_id, filename):

    sessions = os.path.join(os.getcwd(), "sessions")

    base_path = os.path.join(sessions, session_id)
    if '/' in filename or '\\' in filename:
        first_separator_idx = -1
        for sep in ['/', '\\']:
            idx = filename.find(sep)
            if idx != -1 and (first_separator_idx == -1 or idx < first_separator_idx):
                first_separator_idx = idx
        
        if first_separator_idx != -1:
            subdirectory = filename[:first_separator_idx]
            actual_filename = filename[first_separator_idx + 1:]
            download_dir = os.path.join(base_path, subdirectory)

        else:
            download_dir = base_path
            actual_filename = filename
    else:
        download_dir = base_path
        actual_filename = filename
    
    file_full_path = os.path.join(download_dir, actual_filename)
    if not os.path.exists(file_full_path):
        flash(f"File not found: {actual_filename} in {download_dir}", "danger")
        return redirect(url_for("main_menu"))
    

    response = send_from_directory(download_dir, actual_filename, as_attachment=True)

    @response.call_on_close
    def cleanup():
        shutil.rmtree(base_path, ignore_errors=True)
    return response

def get_sort_key(filename):

    match = re.match(
        r'^(?P<base_prefix>.*?\.log)(?:\.(?P<number>\d+))?(?P<gz>\.gz)?(?P<other_suffix>.*)?$',
        filename
    )
    if match:
        base_prefix = match.group("base_prefix")
        number = int(match.group("number")) if match.group("number") else 0
        sort_number = -number
        gz = 1 if match.group("gz") else 0
        other_suffix = match.group("other_suffix") if match.group("other_suffix") else ""
        return (sort_number, base_prefix, gz, other_suffix)
    else:
        return (999999, filename, 999, "")


def fetch_remote_log_filenames(base_url, start_dt, end_dt, token=None):
    headers = {"User-Agent": "Mozilla/5.0"}
    params = {"token": token} if token else None

    resp = requests.get(base_url, headers=headers, params=params, timeout=30)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    pre = soup.find("pre")
    if not pre:
        return []

    filtered_filenames = []

    # Fixme
    # pattern = re.compile(
    #     r'(?P<filename>[a-zA-Z0-9_\-\.]+)\.log(?:\.\d+)?(?:\.gz)?\s+'
    #     r'(?P<day>\d{2})-(?P<month>[A-Za-z]{3})-(?P<year>\d{4})\s+'
    #     r'(?P<time>\d{2}:\d{2}).*'
    # )
    pattern = re.compile(
        r'^(?P<filename>\S+)\s+'
        r'(?P<day>\d{2})-(?P<month>[A-Za-z]{3})-(?P<year>\d{4})\s+'
        r'(?P<time>\d{2}:\d{2})'
    )

    month_map = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4,
        "May": 5, "Jun": 6, "Jul": 7, "Aug": 8,
        "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    start_date_only = start_dt.date()
    end_date_only = end_dt.date()

    for line in pre.text.splitlines():
        print(line)
        if line.strip() == "../":
            continue
        match = pattern.match(line)


        if match:
            filename = match.group("filename")
            if not (filename.endswith(".log") or filename.endswith(".log.gz")):
                continue
            day = int(match.group("day"))
            month = month_map[match.group("month")]
            year = int(match.group("year"))

            file_date_from_list = datetime(year, month, day).date()

            print(file_date_from_list)

            if start_date_only <= file_date_from_list <= end_date_only:
                filtered_filenames.append(filename)

    sorted_filenames = sorted(list(set(filtered_filenames)), key=get_sort_key)
    return sorted_filenames


def parse_nginx_timestamp(line):
    m = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\]', line)
    if m:
        dt = datetime.strptime(m.group(1), "%d/%b/%Y:%H:%M:%S %z")
        return dt.replace(tzinfo=None)
    m = re.search(r'^(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})', line)
    if m:
        return datetime.strptime(m.group(1), "%Y/%m/%d %H:%M:%S")
    return None

# Fixme
def extract_status_code(line):
    m = re.search(r'"\s(\d{3})\s', line)
    if m:
        return m.group(1)

    parts = line.split()
    if len(parts) > 8 and parts[8].isdigit():
        return parts[8]
    return None

# Fixme
def extract_client_ip(line):
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})', line)
    return m.group(1) if m else None


def stream_and_filter_log(base_url, filename, token, start_dt, end_dt, out_fp, status_counter, client_ip_counter):
    url = f"{base_url.rstrip('/')}/{filename}"

    print(f"Processing {filename}")
    print("\n\n\n")

    with requests.get(url, stream=True, timeout=120) as resp:
        resp.raise_for_status()

        if filename.endswith(".gz"):
            # raw = BytesIO(resp.content)
            raw = BytesIO()
            for chunk in resp.iter_content(chunk_size=8192):
                raw.write(chunk)
            raw.seek(0)

            try:
                f = gzip.open(raw, mode="rt", encoding="utf-8", errors="replace")
            except gzip.BadGzipFile:
                print(f"[ERROR] {filename} is not a valid gzip file")
                return False
            except Exception as e:
                print(f"[ERROR] Failed to open gzip file {filename}: {e}")
                return False
            
        else:
            f = resp.iter_lines(decode_unicode=True)

        for line in f:

            if token and token not in line:
                continue

            ts = parse_nginx_timestamp(line)
            if not ts:
                continue

            if ts > end_dt:
                break
            if ts < start_dt:
                continue

            print(f"{line}")

            out_fp.write(line + "\n") # Fixme
            code = extract_status_code(line)
            if code:
                status_counter[code] += 1

            ip = extract_client_ip(line)
            if ip:
                client_ip_counter[ip] += 1



def run_nginx_log_analysis(base_url, token, start_time_str, end_time_str, output_dir):
    os.makedirs(output_dir, exist_ok=True)

    start_dt = datetime.strptime(start_time_str, "%Y/%m/%d %H:%M:%S")
    end_dt   = datetime.strptime(end_time_str, "%Y/%m/%d %H:%M:%S")

    filenames = fetch_remote_log_filenames(base_url, start_dt, end_dt, token)
    print("Fetched log filenames:", filenames)

    combined_path = os.path.join(output_dir, "combined.log")
    summary_path  = os.path.join(output_dir, "summary.log")

    status_counter = Counter()
    client_ip_counter = Counter()

    with open(combined_path, "w", encoding="utf-8") as out:
        for fname in filenames:
            stream_and_filter_log(base_url, fname, token, start_dt, end_dt, out, status_counter, client_ip_counter)


    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("HTTP Status Code Summary:\n")
        f.write("-------------------------\n")
        if status_counter:
            for code, count in sorted(status_counter.items()):
                f.write(f"{code}: {count}\n")
        else:
            f.write("No http status code found in the specified time range.\n\n")
            

        f.write("\nClient IP Address Summary:\n")
        f.write("--------------------------\n")
        if client_ip_counter:
            for ip, count in sorted(client_ip_counter.items()):
                f.write(f"{ip}: {count}\n")
        else:
            f.write("No client IP address found in the specified time range.\n\n")
            

    return combined_path, summary_path

if __name__ == "__main__":
    combined, summary = run_nginx_log_analysis(
        base_url="http://your-nginx/logs/",
        token="YOUR_TOKEN",
        start_time_str="2026/01/20 14:15:00",
        end_time_str="2026/01/20 14:20:59",
        output_dir="./output"
    )