
import json
from project import utils
from flask import Blueprint, flash, jsonify, redirect, render_template, request, session, url_for

import os


from project.nginx_profiles.filter import *



nginx_profile_router = Blueprint("nginx_profiles", __name__)

FAB_OPTIONS = [
    "F12", "F14", "F15", "F16", "F18", "F20", "F21", "F22", "F23", "Other"
]



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
    query_port_from_upstream_search = extract_port(upstream_search_query) if upstream_search_query else None
    # Step 1: Load all profiles
    all_loaded_profiles = load_profiles(fab_filter)
    # Step 2: Apply upstream filter
    profiles_after_upstream_filter = apply_upstream_filter(all_loaded_profiles, upstream_search_query, query_port_from_upstream_search)
    # Step 3: Apply name filter
    filtered_profiles = apply_name_filter(profiles_after_upstream_filter, search_query)
    # Step 4: Format for display
    final_profiles_for_display = [format_profile_for_display(profile_entry) for profile_entry in filtered_profiles]
    # Step 5: Paginate
    profile_for_page, total_pages = paginate_profiles(final_profiles_for_display, page, per_page)
    print(f"Total profiles for display: {len(final_profiles_for_display)}, Total pages: {total_pages}")
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
