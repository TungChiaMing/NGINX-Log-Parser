import os
import re
import json
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup

from project import utils


# Define a default timeout value for requests
REQUEST_TIMEOUT = 1  # seconds

# Common headers for requests
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

# Regex patterns for Nginx config analysis
SERVER_80_PATTERN = re.compile(r"server\s+[^;]*:80\b", re.IGNORECASE)
SERVER_443_PATTERN = re.compile(r"server\s+[^;]*:443\b", re.IGNORECASE)

SPECIAL_PORTS = [211, 214, 1433, 8082, 8083, 445]
SPECIAL_PORTS_REGEX = r"(?:" + "|".join(map(str, SPECIAL_PORTS)) + r")"
SERVER_SPECIAL_PORTS_PATTERN = re.compile(
    rf"server\s+[^;]*:{SPECIAL_PORTS_REGEX}\b", re.IGNORECASE
)

ALL_EXCLUDED_PORTS = [80, 443] + SPECIAL_PORTS
ALL_EXCLUDED_PORTS_REGEX = r"(?!" + "|".join(map(str, ALL_EXCLUDED_PORTS)) + r"\b)"
SERVER_OTHER_PORTS_PATTERN = re.compile(
    rf"server\s+[^;]*:{ALL_EXCLUDED_PORTS_REGEX}\d+\b",
    re.IGNORECASE
)

LISTEN_PATTERN = re.compile(r"^\s*listen\s+[^;]+;", re.MULTILINE | re.IGNORECASE)

NGINX_CONFIG_INDICATOR = re.compile(
    r"^\s*(user|worker_processes|error_log|events|http|stream|server|location|proxy_pass|listen)\b",
    re.MULTILINE | re.IGNORECASE
)

def _analyze_conf_content(content: str) -> dict:
    """
    Analyze nginx config content.

    Args:
        content (str): Text content of a .conf file.

    Returns:
        dict: Analysis results.
    """
    has_access_log_off = "access_log off" in content.lower()

    found_80_servers = [m.group(0).strip() for m in SERVER_80_PATTERN.finditer(content)]
    found_443_servers = [m.group(0).strip() for m in SERVER_443_PATTERN.finditer(content)]
    found_special_port_servers = [
        m.group(0).strip() for m in SERVER_SPECIAL_PORTS_PATTERN.finditer(content)
    ]
    found_other_port_servers = [
        m.group(0).strip() for m in SERVER_OTHER_PORTS_PATTERN.finditer(content)
    ]
    found_listens = [m.group(0).strip() for m in LISTEN_PATTERN.finditer(content)]

    return {
        "has_access_log_off": has_access_log_off,
        "found_80_servers": found_80_servers,
        "found_443_servers": found_443_servers,
        "found_special_port_servers": found_special_port_servers,
        "found_other_port_servers": found_other_port_servers,
        "found_listens": found_listens,
    }


def find_conf_files_and_process(base_url: str, server_name: str) -> dict:
    """
    Fetch nginx config files from a base URL (directory listing or single file)
    and analyze them.

    Args:
        base_url (str): Starting URL.
        server_name (str): For logging.

    Returns:
        dict: Results summary.
    """
    results_list = []
    visited_urls = set()
    successful_config_base_url = None

    def _fetch_and_process_file(file_url, content=None):
        nonlocal successful_config_base_url

        if content is None:
            try:
                print(f"Fetching {server_name} - {file_url}")
                resp = requests.get(file_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                content = resp.text
            except requests.exceptions.Timeout:
                print(f"Timeout fetching {file_url}")
                return False
            except requests.exceptions.RequestException as e:
                print(f"Error fetching {file_url}: {e}")
                return False

        try:
            analysis = _analyze_conf_content(content)
            results_list.append({"file": file_url, **analysis})

            if successful_config_base_url is None:
                successful_config_base_url = file_url

            return True
        except Exception as e:
            print(f"Error analyzing {file_url}: {e}")
            return False

    def process_url_recursive(current_url):
        nonlocal successful_config_base_url

        if current_url in visited_urls:
            return
        visited_urls.add(current_url)

        try:
            print(f"Processing {server_name}: {current_url}")
            response = requests.get(current_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Access error {current_url}: {e}")
            return

        content_type = response.headers.get("Content-Type", "").lower()
        content = response.text

        # Directory listing
        if "text/html" in content_type:
            if successful_config_base_url is None:
                successful_config_base_url = current_url

            soup = BeautifulSoup(content, "html.parser")
            for link in soup.find_all("a"):
                href = link.get("href")
                if not href:
                    continue

                absolute_url = urljoin(current_url, href)

                if not absolute_url.startswith(base_url):
                    continue

                if absolute_url.endswith("/"):
                    process_url_recursive(absolute_url)
                elif absolute_url.endswith(".conf") or \
                        NGINX_CONFIG_INDICATOR.search(os.path.basename(absolute_url)):
                    _fetch_and_process_file(absolute_url)

        # Direct file
        elif current_url.endswith(".conf") or \
                "text/plain" in content_type or \
                NGINX_CONFIG_INDICATOR.search(content):
            _fetch_and_process_file(current_url, content)

    process_url_recursive(base_url)

    return {
        "server_name": server_name,
        "base_url": base_url,
        "successful_config_base_url": successful_config_base_url,
        "results": results_list,
    }


def scan_nginx_log_directory(base_url: str, server_name: str) -> dict:
    """
    Scan nginx log directory listing and extract log file metadata.

    Args:
        base_url (str): Directory URL
        server_name (str): For logging

    Returns:
        dict
    """
    log_files_info = []
    
    try:
        response = requests.get(base_url, headers=HEADERS, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        return {"error": str(e), "log_files": []}

    soup = BeautifulSoup(response.text, "html.parser")
    pre_tag = soup.find("pre")
    
	
    if not pre_tag:
        return {
            "error": "No <pre> tag found in Nginx log directory listing.",
            "log_files": []
        }

    pre_content = pre_tag.get_text()

    pattern = re.compile(
        r'(?P<filename>[^ ]+\.log(?:\.gz|\.\d+)*)\s+'
        r'(?P<date>\d{2}-[A-Za-z]{3}-\d{4})\s+'
        r'(?P<time>\d{2}:\d{2})\s+'
        r'(?P<size>[0-9]+|-)'
    )


    for line in pre_content.splitlines():
        if line.strip().startswith("../"):
            continue

        match = pattern.search(line)
        if match:
            log_files_info.append({
                "filename": match.group("filename"),
                "date": match.group("date"),
                "time": match.group("time"),
                "size": match.group("size")
            })

    return {
        "error": None,
        "log_files": log_files_info
    }



def parse_server_names(server_list_str):
    return [
        name.strip()
        for name in server_list_str.split("\n")
        if name.strip()
    ]


def scan_server_config(server_name):
    full_server_name = f"{server_name}.example.com"
    config_scan_result = None
    config_target_url_dir = f"http://{full_server_name}/nginx_conf/"

    print(f"Attempting to scan Nginx config directory for {server_name} at {config_target_url_dir}")

    try:
        temp_result_dir = find_conf_files_and_process(
            base_url=config_target_url_dir, 
            server_name=server_name
        )

        if temp_result_dir and temp_result_dir.get("file_analysis"):
            config_scan_result = temp_result_dir
        else:
            print(f"No config files found at {config_target_url_dir}. Trying fallback.")

    except Exception as e:
        print(f"Error scanning {config_target_url_dir} for {server_name}: {e}. Trying fallback.")

    if config_scan_result is None or not config_scan_result.get("file_analysis"):
        config_target_url_file = f"http://{full_server_name}/nginx_config"
        print(f"Attempting to scan single Nginx config file for {server_name} at {config_target_url_file}")

        try:
            temp_result_dir = find_conf_files_and_process(
                base_url=config_target_url_file, 
                server_name=server_name
            )

            if temp_result_dir and temp_result_dir.get("file_analysis"):
                config_scan_result = temp_result_dir
            else:
                print(f"No config file found at {config_target_url_file}.")
        except Exception as e:
            print(f"Error scanning {config_target_url_file} for {server_name}: {e}.")

    if config_scan_result is None or not config_scan_result.get("file_analysis"):
        config_scan_result = {
            "server_name": server_name,
            "file_analysis": [],
            "summary": {
                "total_files": 0,
                "files_with_access_log_off": 0,
                "total_80_servers": 0,
                "total_443_servers": 0,
                "total_other_ports_servers": 0,
                "total_special_ports_servers": 0,
                "total_other_port_servers": 0,
                "total_listen_directives": 0
            },

            "config_base_url": "N/A",
            "error": f"Failed to retrieve config from any expected path."
        }

    config_scan_result["full_server_name"] = full_server_name

    log_dir_scan_result = scan_nginx_log_directory(
        base_url=f"http://{full_server_name}/nginx_logs/",
        server_name=server_name
    )

    config_scan_result["log_dir_info"] = log_dir_scan_result

    return config_scan_result


def preserve_existing_memo(server_name):
    profile_json_filename = f"{server_name}.json"
    profile_json_path = os.path.join(utils.PROFILE_SAVE_DIR, profile_json_filename)
    existing_memo = ""

    if os.path.exists(profile_json_path):
        try:
            with open(profile_json_path, "r", encoding="utf-8") as f_old:
                existing_profile_data = json.load(f_old)
                existing_memo = existing_profile_data.get("memo", "")
        except json.JSONDecodeError as e:
            print(f"Error decoding existing profile JSON for {server_name} to preserve memo: {e}")
        except Exception as e:
            print(f"Error loading existing profile for {server_name} to preserve memo: {e}")

    return existing_memo


def save_profile(profile_data, server_name):
    profile_json_filename = f"{server_name}.json"
    profile_json_path = os.path.join(utils.PROFILE_SAVE_DIR, profile_json_filename)

    with open(profile_json_path, "w", encoding="utf-8") as f:
        json.dump(profile_data, f, indent=4)

