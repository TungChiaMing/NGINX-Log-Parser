from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, flash, jsonify
)
from functools import wraps
from datetime import datetime, timedelta
import os
import uuid
import shutil

from project.nginx_parser import run_nginx_log_analysis
from project.nginx_config_scanner import find_conf_files_and_process, scan_nginx_log_directory
import re
import json

import math

PROFILE_SAVE_DIR = os.path.join('static', "profiles")

class NginxLogAnalyzerApp:

    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
        self.app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "sessions")

        os.makedirs(self.app.config["UPLOAD_FOLDER"], exist_ok=True)

        self._register_routes()

        self._create_profile_save_dir()

    # -------------------------
    # Utils
    # -------------------------
    def read_text_file_safe(self, path, max_bytes=200_000):
        if not os.path.exists(path):
            return ""
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(max_bytes)

    def login_required(self, f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("logged_in"):
                flash("please login first", "warning")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper
    
    def _create_profile_save_dir(self):
        if not os.path.exists(PROFILE_SAVE_DIR):
            os.makedirs(PROFILE_SAVE_DIR)

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

    def extract_fab_from_query(self, query_string):
        match = re.match(r'^(F\d+)', query_string, re.IGNORECASE)
        return match.group(1).upper() if match else None
    
    def extract_port(self, upstream_str):
        parts = upstream_str.split(":")
        if len(parts) > 1:
            try:
                return int(parts[-1])
            except ValueError:
                pass
        return None
    

    # -------------------------
    # Routes
    # -------------------------
    def _register_routes(self):

        @self.app.route("/login", methods=["GET", "POST"])
        def login():
            if request.method == "POST":
                username = request.form.get("username")
                password = request.form.get("password")

                if username and password:
                    session["logged_in"] = True
                    session["username"] = username
                    return redirect(url_for("main_menu"))

                flash("請輸入帳號密碼", "danger")

            return render_template("login.html")

        @self.app.route("/logout")
        def logout():
            session.clear()
            flash("已登出", "success")
            return redirect(url_for("login"))
        
        @self.app.route("/")
        @self.login_required
        def main_menu():
            return render_template("main_menu.html", username=session.get("username"))

        @self.app.route("/log_parser", methods=["GET", "POST"])
        @self.login_required
        def log_parser():
            default_end = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
            default_start = (datetime.now() - timedelta(hours=1)).strftime("%Y/%m/%d %H:%M:%S")

            form_data = {
                "base_url": "",
                "token": "",
                "start_time": default_start,
                "end_time": default_end
            }

            if request.method == "POST":
                form_data.update({
                    "base_url": request.form.get("base_url", ""),
                    "token": request.form.get("token", ""),
                    "start_time": request.form.get("start_time", default_start),
                    "end_time": request.form.get("end_time", default_end),
                })

                session["last_form_data_log_parser"] = form_data

                session_id = str(uuid.uuid4())
                session_dir = os.path.join(self.app.config["UPLOAD_FOLDER"], session_id)
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
                          "combined_content": self.read_text_file_safe(combined_log),
                          "summary_content": self.read_text_file_safe(summary_log),
                          "url_id": url_id
                      })

                    
                  return render_template(
                      "result.html",
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
                "index.html",
                **form_data,
                username=session.get("username")
            )

        @self.app.route("/download/<session_id>/<path:filename>")
        @self.login_required
        def download(session_id, filename):
            base_path = os.path.join(self.app.config["UPLOAD_FOLDER"], session_id)
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

        @self.app.route("/nginx_profiles")
        @self.login_required
        def nginx_profiles():
            page = request.args.get('page', session.get('last_profile_page', 1), type=int)
            search_query = request.args.get('search', session.get('last_profile_search', '')).strip()

            default_fab_filter = "F14"

            if default_fab_filter not in self.FAB_OPTIONS:
                default_fab_filter = self.FAB_OPTIONS[0]
            
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
                query_fab_from_upstream_search = self.extract_fab_from_query(upstream_search_query)
                query_port_from_upstream_search = self.extract_port(upstream_search_query)

            all_loaded_profiles = []

            for filename in os.listdir(PROFILE_SAVE_DIR):
                if filename.endswith(".json"):
                    server_name = filename.replace(".json", '')
                    profile_path = os.path.join(PROFILE_SAVE_DIR, filename)

                    profile_passes_fab_filter = False

                    if not fab_filter or fab_filter == "Other":
                        profile_passes_fab_filter = True
                    else:
                        pattern = self.FAB_REGEX_PATTERNS.get(fab_filter)
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
                                item_port = self.extract_port(cleaned_item)
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
                fab_options=self.FAB_OPTIONS,
                selected_fab_filter=fab_filter,
                upstream_search_query=upstream_search_query
            )
            

        @self.app.route("/nginx_profiles/<server_name>")
        @self.login_required
        def nginx_profile_detail(server_name):
            profile_json_filename = f"{server_name}.json"
            profile_json_path = os.path.join(PROFILE_SAVE_DIR, profile_json_filename)

            default_fab_filter = "F14"

            if default_fab_filter not in self.FAB_OPTIONS:
                default_fab_filter = self.FAB_OPTIONS[0]

            if not os.path.exists(profile_json_path):
                flash(f"Profile data for {server_name} not found.", "danger")
                return redirect(url_for('nginx_profiles',
                                        page=session.get("last_profile_page", 1),
                                        search=session.get("last_profile_search", ""),
                                        fab_filter=session.get("last_fab_filter", default_fab_filter),
                                        upstream_search=session.get("last_upstream_search", "")))
            try:
                with open(profile_json_path, "r", encoding="utf-8") as f:
                    profile_data = json.load(f)
            except json.JSONDecodeError as e:
                flash(f"Error reading profile data for {server_name}: {e}", "danger")
                return redirect(url_for('nginx_profiles',
                                        page=session.get("last_profile_page", 1),
                                        search=session.get("last_profile_search", ""),
                                        fab_filter=session.get("last_fab_filter", default_fab_filter),
                                        upstream_search=session.get("last_upstream_search", "")))
            except Exception as e:
                flash(f"An unexpected error occurred loading profile for {server_name}: {e}", "danger")
                return redirect(url_for('nginx_profiles',
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


        @self.app.route("/config_scanner", methods=["GET", "POST"])
        @self.login_required
        def config_scanner():
            form_data = {
                "server_list": ""
            }

            if request.method == "POST":
                form_data.update({
                    "server_list": request.form.get("server_list", "")
                })

                session["last_form_data_config_scanner"] = form_data
                try:
                    all_scan_results = []
                    raw_server_names = form_data["server_list"]
                    server_names = [
                        name.strip()
                        for name in raw_server_names.split("\n")
                        if name.strip()
                    ]



                    for server_name in server_names:
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

                        profile_json_filename = f"{server_name}.json"

                        profile_json_path = os.path.join(PROFILE_SAVE_DIR, profile_json_filename)

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

                        config_scan_result["memo"] = existing_memo
                        all_scan_results.append(config_scan_result)

                        with open(profile_json_path, "w", encoding="utf-8") as f:
                            json.dump(config_scan_result, f, indent=4)

                        flash("Scan completed and profile saved.", "success")
                        return redirect(url_for('nginx_profiles'))
                    
                except Exception as e:
                    flash(f"An error occurred during scanning: {e}", "danger")
                    return render_template(
                        "config_scan_result.html",
                        success=False,
                        error=str(e),
                        username=session.get("username")
                    )

            if "last_form_data_config_scanner" in session:
                form_data = session["last_form_data_config_scanner"]
            
            return render_template(
                "config_scan.html",
                **form_data,
                username=session.get("username")
            )

        @self.app.route("/update_profile_field", methods=["POST"])
        @self.login_required
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
            profile_json_path = os.path.join(PROFILE_SAVE_DIR, profile_json_filename)

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


    def run(self):
        self.app.run(debug=True, host="127.0.0.1", port=8080)



if __name__ == "__main__":
    NginxLogAnalyzerApp().run()
#
# app = NginxLogAnalyzerApp().app