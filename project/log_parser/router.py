from project import utils
from flask import Blueprint, flash, redirect, render_template, request, send_from_directory, session, url_for

import shutil
import uuid
from datetime import datetime, timedelta
import os

from project.log_parser.parser import run_nginx_log_analysis

log_parser_router = Blueprint("log_parser", __name__)

def parse_base_urls(base_urls_str):
    return [
        u.strip()
        for u in base_urls_str.split(",")
        if u.strip()
    ]

def generate_url_id(base_url):
    return base_url.replace("://", "_").replace("/", "_").replace(".", "_").replace(":", "_").replace("?", "_").replace("&", "_").replace("=", "_")

def run_log_analysis_for_url(base_url, token, start_time, end_time, output_dir):
    combined_log, summary_log = run_nginx_log_analysis(
        base_url=base_url,
        token=token,
        start_time_str=start_time,
        end_time_str=end_time,
        output_dir=output_dir
    )
    return combined_log, summary_log

def resolve_download_path(base_path, filename):
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
    return download_dir, actual_filename

def prepare_form_data(request, default_start, default_end):
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
    elif "last_form_data_log_parser" in session:
        form_data = session["last_form_data_log_parser"]
    return form_data

def create_session_dir(sessions_path):
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(sessions_path, session_id)
    os.makedirs(session_dir, exist_ok=True)
    return session_id, session_dir

def process_base_urls(form_data, session_dir):
    results = []
    raw_base_urls = form_data["base_url"]
    base_urls = parse_base_urls(raw_base_urls)
    for base_url in base_urls:
        url_id = generate_url_id(base_url)
        url_dir = os.path.join(session_dir, url_id)
        os.makedirs(url_dir, exist_ok=True)
        combined_log, summary_log = run_log_analysis_for_url(
            base_url=base_url,
            token=form_data["token"],
            start_time=form_data["start_time"],
            end_time=form_data["end_time"],
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
    return results

@log_parser_router.route("/", methods=["GET", "POST"])
@utils.login_required
def index():
    default_end = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    default_start = (datetime.now() - timedelta(hours=1)).strftime("%Y/%m/%d %H:%M:%S")
    sessions = os.path.join(os.getcwd(), "sessions")

    form_data = prepare_form_data(request, default_start, default_end)

    if request.method == "POST":
        try:
            session_id, session_dir = create_session_dir(sessions)
            results = process_base_urls(form_data, session_dir)
            return render_template(
                "log_parser_result.html",
                success=True,
                session_id=session_id,
                results=results,
                username=session.get("username")
            )
        except Exception as e:
            if 'session_dir' in locals():
                shutil.rmtree(session_dir, ignore_errors=True)
            return render_template(
                "result.html",
                success=False,
                error=str(e),
                username=session.get("username")
            )

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
    download_dir, actual_filename = resolve_download_path(base_path, filename)
    
    file_full_path = os.path.join(download_dir, actual_filename)
    if not os.path.exists(file_full_path):
        flash(f"File not found: {actual_filename} in {download_dir}", "danger")
        return redirect(url_for("main_menu"))
    

    response = send_from_directory(download_dir, actual_filename, as_attachment=True)

    @response.call_on_close
    def cleanup():
        shutil.rmtree(base_path, ignore_errors=True)
    return response