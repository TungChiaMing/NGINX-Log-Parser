

from datetime import datetime
import json
from project import utils

import re
import os
import math


FAB_REGEX_PATTERNS = {
    "F12": re.compile(r"^[A-Za-z]12", re.IGNORECASE),
    "F14": re.compile(r"^[A-Za-z]14", re.IGNORECASE),
    "F15": re.compile(r"^[A-Za-z]15", re.IGNORECASE),
    "F16": re.compile(r"^[A-Za-z]16", re.IGNORECASE),
    "F18": re.compile(r"^[A-Za-z]18", re.IGNORECASE),
    "F20": re.compile(r"^[A-Za-z]20", re.IGNORECASE),
    "F21": re.compile(r"^[A-Za-z]21", re.IGNORECASE),
    "F22": re.compile(r"^[A-Za-z]22", re.IGNORECASE),
    "F23": re.compile(r"^[A-Za-z]23", re.IGNORECASE)
}


def extract_fab_from_query(query_string):
    match = re.match(r'^(F\d+)', query_string, re.IGNORECASE)
    return match.group(1).upper() if match else None

def extract_port(upstream_str):
    parts = upstream_str.split(":")
    if len(parts) > 1:
        try:
            return int(parts[-1])
        except ValueError:
            pass
    return None

# --- Helper Functions ---
def load_profiles(fab_filter):
    """Load all profiles from disk, filtered by fab_filter."""
    all_loaded_profiles = []
    for filename in os.listdir(utils.PROFILE_SAVE_DIR):
        if filename.endswith(".json"):
            server_name = filename.replace(".json", '')
            profile_path = os.path.join(utils.PROFILE_SAVE_DIR, filename)
            profile_passes_fab_filter = False
            if not fab_filter or fab_filter == "Other":
                profile_passes_fab_filter = True
            else:
                pattern = FAB_REGEX_PATTERNS.get(fab_filter)
                if pattern and pattern.match(server_name):
                    profile_passes_fab_filter = True
            if not profile_passes_fab_filter:
                continue
            try:
                with open(profile_path, "r", encoding="utf-8") as f:
                    profile_data = json.load(f)
                    all_loaded_profiles.append({
                        "server_name": server_name,
                        "filename": filename,
                        "data": profile_data
                    })
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON from {filename}: {e}")
            except Exception as e:
                print(f"Error reading profile {filename}: {e}")
    all_loaded_profiles.sort(key=lambda x: x["server_name"])
    return all_loaded_profiles

def apply_upstream_filter(profiles, query, port):
    """Filter profiles by upstream search query and port."""
    if not query:
        print(f"Upstream search is not active. Number of profiles: {len(profiles)}")
        return profiles
    print(f"Applying Upstream search filter: '{query}'")
    filtered = []
    for profile_entry in profiles:
        server_name = profile_entry["server_name"]
        profile_data = profile_entry["data"]
        found_upstream_match = False
        for file_analysis in profile_data.get('file_analysis', []):
            current_file_upstreams = []
            current_file_upstreams.extend(file_analysis.get("found_upstream_servers", []))
            current_file_upstreams.extend(file_analysis.get("found_special_port_servers", []))
            current_file_upstreams.extend(file_analysis.get("found_80_servers", []))
            current_file_upstreams.extend(file_analysis.get("found_443_servers", []))
            current_file_upstreams.extend(file_analysis.get("found_other_port_servers", []))
            cleaned_upstreams = []
            for item in current_file_upstreams:
                cleaned_item = item[len("server "):].strip() if item.lower().startswith("server ") else item.strip()
                if port:
                    item_port = extract_port(cleaned_item)
                    if item_port == port:
                        cleaned_upstreams.append(cleaned_item)
                else:
                    cleaned_upstreams.append(cleaned_item)
            for upstream_server in cleaned_upstreams:
                if query.lower() in upstream_server.lower():
                    found_upstream_match = True
                    print(f"Match found for '{server_name}' with upstream '{upstream_server}'")
                    break
            if found_upstream_match:
                break
        if found_upstream_match:
            filtered.append(profile_entry)
    print(f"\n--- After Upstream Filtering ---")
    print(f"Number of profiles remaining after upstream filter: {len(filtered)}")
    return filtered

def apply_name_filter(profiles, search_query):
    """Filter profiles by server name search query."""
    if not search_query:
        print(f"Nginx Server Name search is not active. Number of profiles: {len(profiles)}")
        return profiles
    print(f"Applying Nginx Server Name search filter: \"{search_query}\"")
    filtered = [
        profile_entry for profile_entry in profiles
        if search_query.lower() in profile_entry["server_name"].lower()
    ]
    print(f"Number of profiles after Nginx Server Name search: {len(filtered)}")
    return filtered

def format_profile_for_display(profile_entry):
    """Format a profile entry for display in the list."""
    server_name = profile_entry['server_name']
    profile_data = profile_entry['data']
    filename = profile_entry['filename']
    summary = profile_data.get('summary', {})
    special_ports_list = []
    other_ports_list = []
    nginx_listen_ports = []
    http_ports_list = []
    for file_analysis in profile_data.get("file_analysis", []):
        # Extract Nginx listen ports
        for listen_directive in file_analysis.get('found_listens', []):
            match = re.search(r':?(\d+)\b', listen_directive)
            if match:
                nginx_listen_ports.append(match.group(1))
        # Extract 80 and 443 ports
        for server_directive in file_analysis.get('found_80_servers', []):
            match = re.search(r':?(\d+)\b', server_directive)
            if match:
                http_ports_list.append(match.group(1))
        for server_directive in file_analysis.get('found_443_servers', []):
            match = re.search(r':?(\d+)\b', server_directive)
            if match:
                http_ports_list.append(match.group(1))
        for server_directive in file_analysis.get("found_special_ports_servers", []):
            match = re.search(r":?(\d+)\b", server_directive)
            if match:
                special_ports_list.append(match.group(1))
        for server_directive in file_analysis.get('found_other_port_servers', []):
            match = re.search(r':?(\d+)\b', server_directive)
            if match:
                other_ports_list.append(match.group(1))
    # Format Nginx Listen Ports
    unique_nginx_listen_ports = sorted(list(set(nginx_listen_ports)))
    formatted_nginx_listen_ports = ", ".join(unique_nginx_listen_ports) if unique_nginx_listen_ports else "N/A"
    total_http_servers = summary.get('total_80_servers', 0) + summary.get('total_443_servers', 0)
    unique_http_ports = sorted(list(set(http_ports_list)))
    formatted_http_ports = str(total_http_servers)
    if unique_http_ports:
        formatted_http_ports += f" ({', '.join(unique_http_ports)})"
    elif total_http_servers == 0:
        formatted_http_ports = "0"
    unique_special_ports = sorted(list(set(special_ports_list)))
    formatted_special_ports = f"{summary.get('total_special_ports_servers', 0)}"
    if unique_special_ports:
        formatted_special_ports += f" ({', '.join(unique_special_ports)})"
    elif summary.get('total_special_ports_servers', 0) == 0:
        formatted_special_ports = "0"
    unique_other_ports = sorted(list(set(other_ports_list)))
    formatted_other_ports = f"{summary.get('total_other_ports_servers', 0)}"
    if unique_other_ports:
        formatted_other_ports += f" ({', '.join(unique_other_ports)})"
    elif summary.get('total_other_ports_servers', 0) == 0:
        formatted_other_ports = "0"
    log_files_to_display = []
    latest_log_date = "N/A"
    max_date_obj = None
    log_dir_info = profile_data.get("log_dir_info")
    if log_dir_info and log_dir_info.get("log_files"):
        for log_file_entry in log_dir_info['log_files']:
            log_filename = log_file_entry.get('filename')
            if log_filename and re.fullmatch(r'[^. ]+\.log$', log_filename):
                log_files_to_display.append(log_filename)
            date_str = log_file_entry.get('date')
            if date_str:
                try:
                    current_log_date = datetime.strptime(date_str, '%d-%b-%Y').date()
                    if max_date_obj is None or current_log_date > max_date_obj:
                        max_date_obj = current_log_date
                except ValueError as e:
                    print(f"Error parsing date for {log_filename}: {date_str} - {e}")
    if max_date_obj:
        latest_log_date = max_date_obj.strftime('%Y-%m-%d')
    log_files_to_display.sort()
    return {
        'name': server_name,
        'filename': filename,
        'summary': summary,
        'formatted_http_ports': formatted_http_ports,
        'formatted_special_ports': formatted_special_ports,
        'formatted_other_ports': formatted_other_ports,
        'formatted_nginx_listen_ports': formatted_nginx_listen_ports,
        'log_files_list': log_files_to_display,
        'latest_log_date': latest_log_date,
        'memo': profile_data.get("memo", ""),
    }

def paginate_profiles(profiles, page, per_page):
    """Paginate the list of profiles."""
    total_profiles = len(profiles)
    total_pages = math.ceil(total_profiles / per_page)
    if page < 1:
        page = 1
    if total_pages > 0 and page > total_pages:
        page = total_pages
    elif total_pages == 0:
        page = 1
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    return profiles[start_index:end_index], total_pages
