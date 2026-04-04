from project import utils
from flask import Blueprint, flash, redirect, render_template, request, send_from_directory, session, url_for

import json
import shutil
import uuid
from datetime import datetime, timedelta
import os

from project.log_parser.parser import run_nginx_log_analysis

log_parser_router = Blueprint("log_parser", __name__)

SAVED_RESULTS_DIR = os.path.join(os.getcwd(), "saved_results")

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

def create_session_dir(base_path):
    session_id = str(uuid.uuid4())
    session_dir = os.path.join(base_path, session_id)
    os.makedirs(session_dir, exist_ok=True)
    return session_id, session_dir

def save_meta(session_dir, session_id, form_data, results):
    meta = {
        "session_id": session_id,
        "created_at": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
        "form_data": form_data,
        "results": [
            {
                "base_url": r["base_url"],
                "url_id": r["url_id"],
                "combined_log": r["combined_log"],
                "summary_log": r["summary_log"],
                "combined_content": r["combined_content"],
                "summary_content": r["summary_content"],
            }
            for r in results
        ],
    }
    with open(os.path.join(session_dir, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, ensure_ascii=False, indent=2)

def load_meta(session_id):
    path = os.path.join(SAVED_RESULTS_DIR, session_id, "meta.json")
    if not os.path.exists(path):
        return None
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def list_saved_sessions():
    if not os.path.isdir(SAVED_RESULTS_DIR):
        return []
    sessions = []
    for name in os.listdir(SAVED_RESULTS_DIR):
        meta_path = os.path.join(SAVED_RESULTS_DIR, name, "meta.json")
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
            sessions.append({
                "session_id": meta["session_id"],
                "created_at": meta["created_at"],
                "base_urls": [r["base_url"] for r in meta["results"]],
                "start_time": meta["form_data"].get("start_time", ""),
                "end_time": meta["form_data"].get("end_time", ""),
            })
    sessions.sort(key=lambda x: x["created_at"], reverse=True)
    return sessions

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

    form_data = prepare_form_data(request, default_start, default_end)

    if request.method == "POST":
        session_dir = None
        try:
            os.makedirs(SAVED_RESULTS_DIR, exist_ok=True)
            session_id, session_dir = create_session_dir(SAVED_RESULTS_DIR)
            results = process_base_urls(form_data, session_dir)
            save_meta(session_dir, session_id, form_data, results)
            return redirect(url_for("log_parser.results", session_id=session_id))
        except Exception as e:
            if session_dir:
                shutil.rmtree(session_dir, ignore_errors=True)
            return render_template(
                "log_parser_result.html",
                success=False,
                error=str(e),
                username=session.get("username")
            )

    return render_template(
        "log_parser.html",
        **form_data,
        username=session.get("username")
    )


@log_parser_router.route("/results/<session_id>")
@utils.login_required
def results(session_id):
    meta = load_meta(session_id)
    if meta is None:
        flash("Result not found. It may have been deleted.", "danger")
        return redirect(url_for("log_parser.index"))
    return render_template(
        "log_parser_result.html",
        success=True,
        session_id=session_id,
        results=meta["results"],
        form_data=meta["form_data"],
        created_at=meta["created_at"],
        username=session.get("username")
    )


@log_parser_router.route("/saved")
@utils.login_required
def saved():
    sessions = list_saved_sessions()
    return render_template(
        "log_parser_saved.html",
        sessions=sessions,
        username=session.get("username")
    )


@log_parser_router.route("/saved/delete/<session_id>", methods=["POST"])
@utils.login_required
def delete_saved(session_id):
    target = os.path.join(SAVED_RESULTS_DIR, session_id)
    if os.path.isdir(target):
        shutil.rmtree(target, ignore_errors=True)
        flash("Record deleted.", "success")
    else:
        flash("Record not found.", "danger")
    return redirect(url_for("log_parser.saved"))


@log_parser_router.route("/download/<session_id>/<path:filename>")
@utils.login_required
def download(session_id, filename):
    base_path = os.path.join(SAVED_RESULTS_DIR, session_id)
    download_dir, actual_filename = resolve_download_path(base_path, filename)

    file_full_path = os.path.join(download_dir, actual_filename)
    if not os.path.exists(file_full_path):
        flash(f"File not found: {actual_filename}", "danger")
        return redirect(url_for("log_parser.results", session_id=session_id))

    return send_from_directory(download_dir, actual_filename, as_attachment=True)