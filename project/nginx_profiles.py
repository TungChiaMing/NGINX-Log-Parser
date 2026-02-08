
from datetime import datetime
import json
from project import utils
from flask import Blueprint, flash, jsonify, redirect, render_template, request, send_from_directory, session, url_for
import re
import os
import math


nginx_profile_router = Blueprint("nginx_profiles", __name__)

FAB_OPTIONS = [
    "F12", "F14", "F15", "F16", "F18", "F20", "F21", "F22", "F23", "Other"
]

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


@nginx_profile_router.route("/")
@utils.login_required
def index():
    page = request.args.get('page', session.get('last_profile_page', 1), type=int)
    search_query = request.args.get('search', session.get('last_profile_search', '')).strip()

    default_fab_filter = "F14"

    if default_fab_filter not in FAB_OPTIONS:
        default_fab_filter = FAB_OPTIONS[0]

    fab_filter = request.args.get('fab_filter', session.get('last_fab_filter', default_fab_filter)).strip()
    
    upstream_search_query = request.args.get('upstream_search', session.get('last_upstream_search', '')).strip()
    session['last_upstream_search'] = upstream_search_query

    per_page = 10

    session['last_profile_page'] = page
    session['last_profile_search'] = search_query
    session['last_fab_filter'] = fab_filter

    query_fab_from_upstream_search = None
    query_port_from_upstream_search = None

    if upstream_search_query:
        query_fab_from_upstream_search = extract_fab_from_query(upstream_search_query)
        query_port_from_upstream_search = extract_port(upstream_search_query)

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

    profiles_after_upstream_filter = []
    if upstream_search_query:
        print(f"Applying Upstream search filter: '{upstream_search_query}'")
        for profile_entry in all_loaded_profiles:
            server_name = profile_entry["server_name"]
            profile_data = profile_entry["data"]

            found_upstream_match = False
            all_upstreams_in_profile_debug = []     # collect all upstreams for debug


            for file_analysis in profile_data.get('file_analysis', []):
                current_file_upstreams = []

                # Add all types of upstream servers to the list for searching
                current_file_upstreams.extend(file_analysis.get("found_upstream_servers", []))
                current_file_upstreams.extend(file_analysis.get("found_special_port_servers", []))
                current_file_upstreams.extend(file_analysis.get("found_80_servers", []))  # Add HTTP ports
                current_file_upstreams.extend(file_analysis.get("found_443_servers", []))  # Add HTTPS ports
                current_file_upstreams.extend(file_analysis.get("found_other_port_servers", []))  # Add other ports
                cleaned_upstreams = []


                for item in current_file_upstreams:
                    cleaned_item = item[len("server "): ].strip() if item.lower().startswith("server ") else item.strip()
                    if query_port_from_upstream_search:
                        item_port = extract_port(cleaned_item)
                        if item_port == query_port_from_upstream_search:
                            cleaned_upstreams.append(cleaned_item)
                    else:
                        cleaned_upstreams.append(cleaned_item)
                
                
                all_upstreams_in_profile_debug.extend(cleaned_upstreams)


                for upstream_server in cleaned_upstreams:
                    if upstream_search_query.lower() in upstream_server.lower():
                        found_upstream_match = True
                        print(f"Match found for '{server_name}' with upstream '{upstream_server}'")
                        break
                if found_upstream_match:
                    break


            if found_upstream_match:
                profiles_after_upstream_filter.append(profile_entry)

    else:
        profiles_after_upstream_filter = all_loaded_profiles
        print (f"Upstream search is not active. Number of profiles: {len(profiles_after_upstream_filter)}")


    print(f"\n--- After Upstream Filtering ---")
    print(f"Number of profiles remaining after upstream filter: {len(profiles_after_upstream_filter)}")


    # --- Step 3: Apply general search_query (Nginx server name) if active ---
    filtered_profiles = []
    if search_query:
        print(f"Applying Nginx Server Name search filter: \"{search_query}\"")
        
        filtered_profiles = [
            profile_entry for profile_entry in profiles_after_upstream_filter
            if search_query.lower() in profile_entry["server_name"].lower()
        ]
        print(f"Number of profiles after Nginx Server Name search: {len(filtered_profiles)}")
    else:
        filtered_profiles = profiles_after_upstream_filter
        print(f"Nginx Server Name search is not active. Number of profiles: {len(filtered_profiles)}")


    # --- Step 4: Prepare for Pagination and final display ---
    # Format the data for display
    final_profiles_for_display = []
    for profile_entry in filtered_profiles:
        server_name = profile_entry['server_name']
        profile_data = profile_entry['data']
        filename = profile_entry['filename']
        summary = profile_data.get('summary', {})


        special_ports_list = []
        other_ports_list = []
        nginx_listen_ports = []
        http_ports_list = [] # List to collect 80 and 443 ports


        for file_analysis in profile_data.get("file_analysis", []):
            # Extract Nginx listen ports
            for listen_directive in file_analysis.get('found_listens', []):
                match = re.search(r':?(\d+) \b', listen_directive)
                if match:
                    nginx_listen_ports.append(match.group(1))


        # Extract 80 and 443 ports
        for server_directive in file_analysis.get('found_80_servers', []):
            match = re.search(r':?(\d+) \b', server_directive)
            if match:
                http_ports_list.append(match.group(1))


        for server_directive in file_analysis.get('found_443_servers', []):
            match = re.search(r':?(\d+) \b', server_directive)
            if match:
                http_ports_list.append(match.group(1))


        for server_directive in file_analysis.get("found_special_ports_servers", []):
            match = re.search(r":?(\d+) \b", server_directive)
            if match:
                special_ports_list.append(match.group(1))

        for server_directive in file_analysis.get('found_other_port_servers', []):
            match = re.search(r':?(\d+) \b', server_directive)
            if match:
                other_ports_list.append(match.group(1))


        # Format Nginx Listen Ports
        unique_nginx_listen_ports = sorted(list(set(nginx_listen_ports)))
        formatted_nginx_listen_ports = ", ".join(unique_nginx_listen_ports) if unique_nginx_listen_ports else "N/A"
        total_http_servers = summary.get('total_80_servers', 0) + summary.get('total_443_servers', 0)
        unique_http_ports = sorted(list(set(http_ports_list)))

        
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


        final_profiles_for_display.append({
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
        })

    
    total_profiles = len(final_profiles_for_display)
    total_pages = math.ceil(total_profiles / per_page)
    print(f"Total profiles for display: {total_profiles}, Total pages: {total_pages}")

    if page < 1:
        page = 1
    if total_pages > 0 and page > total_pages:
        page = total_pages
    elif total_pages == 0:
        page = 1
    
    start_index = (page - 1) * per_page
    end_index = start_index + per_page
    profile_for_page = final_profiles_for_display[start_index:end_index] if final_profiles_for_display else []


    return render_template(
        "nginx_profiles_list.html",
        profiles=profile_for_page,
        username=session.get("username"),
        current_page=page,
        total_pages=total_pages,
        search_query=search_query,
        fab_options=FAB_OPTIONS,
        selected_fab_filter=fab_filter,
        upstream_search_query=upstream_search_query
    )
    

@nginx_profile_router.route("/<server_name>")
@utils.login_required
def nginx_profile_detail(server_name):
    profile_json_filename = f"{server_name}.json"
    profile_json_path = os.path.join(utils.PROFILE_SAVE_DIR, profile_json_filename)

    default_fab_filter = "F14"

    if default_fab_filter not in FAB_OPTIONS:
        default_fab_filter = FAB_OPTIONS[0]

    if not os.path.exists(profile_json_path):
        flash(f"Profile data for {server_name} not found.", "danger")
        return redirect(url_for('nginx_profiles.index',
                                page=session.get("last_profile_page", 1),
                                search=session.get("last_profile_search", ""),
                                fab_filter=session.get("last_fab_filter", default_fab_filter),
                                upstream_search=session.get("last_upstream_search", "")))
    try:
        with open(profile_json_path, "r", encoding="utf-8") as f:
            profile_data = json.load(f)
    except json.JSONDecodeError as e:
        flash(f"Error reading profile data for {server_name}: {e}", "danger")
        return redirect(url_for('nginx_profiles.index',
                                page=session.get("last_profile_page", 1),
                                search=session.get("last_profile_search", ""),
                                fab_filter=session.get("last_fab_filter", default_fab_filter),
                                upstream_search=session.get("last_upstream_search", "")))
    except Exception as e:
        flash(f"An unexpected error occurred loading profile for {server_name}: {e}", "danger")
        return redirect(url_for('nginx_profiles.index',
                                page=session.get("last_profile_page", 1),
                                search=session.get("last_profile_search", ""),
                                fab_filter=session.get("last_fab_filter", default_fab_filter),
                                upstream_search=session.get("last_upstream_search", "")))

    return render_template(
        "config_scan_result_partial.html",
        success=True,
        all_scan_results=[profile_data],
        username=session.get("username"),
        current_page=session.get('last_profile_page', 1),
        search_query=session.get("last_profile_search", ""),
        fab_filter=session.get("last_fab_filter", default_fab_filter),
        upstream_search_query=session.get("last_upstream_search", "")
    )

@nginx_profile_router.route("/update_profile_field", methods=["POST"])
@utils.login_required
def update_profile_field():
    data = request.get_json()
    server_name = data.get("server_name")
    field = data.get("field")
    value = data.get("value")

    if not all([server_name, field, value is not None]):
        return jsonify({"success": False, "message": "Missing data"}), 400

    if field != "memo":
        return jsonify({"success": False, "message": "Invalid field"}), 400

    profile_json_filename = f"{server_name}.json"
    profile_json_path = os.path.join(utils.PROFILE_SAVE_DIR, profile_json_filename)

    if not os.path.exists(profile_json_path):
        return jsonify({"success": False, "message": "Profile not found"}), 404

    try:
        with open(profile_json_path, "r+", encoding="utf-8") as f:
            profile_data = json.load(f)
            profile_data[field] = value
            f.seek(0)
            json.dump(profile_data, f, indent=4)
            f.truncate()

        return jsonify({"success": True, "message": f"{field} for {server_name} updated."})
    except json.JSONDecodeError:
        return jsonify({"success": False, "message": "Error decoding profile JSON"}), 500
    except Exception as e:
        return jsonify({"success": False, "message": f"An error occurred: {str(e)}"}), 500
