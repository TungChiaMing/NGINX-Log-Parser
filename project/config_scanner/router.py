from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from project import utils

from project.config_scanner.scanner import *

import os
import json


config_scanner_router = Blueprint("config_scanner", __name__)


@config_scanner_router.route("/", methods=["GET", "POST"])
@utils.login_required
def index():
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
            server_names = parse_server_names(raw_server_names)

            for server_name in server_names:
                config_scan_result = scan_server_config(server_name)

                existing_memo = preserve_existing_memo(server_name)
                config_scan_result["memo"] = existing_memo

                all_scan_results.append(config_scan_result)

                save_profile(config_scan_result, server_name)

                flash("Scan completed and profile saved.", "success")
                return redirect(url_for('nginx_profiles.index'))
            
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
