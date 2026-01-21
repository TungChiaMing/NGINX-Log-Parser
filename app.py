from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, flash
)
from functools import wraps
from datetime import datetime, timedelta
import os
import uuid
import shutil

from nginx_parser import run_nginx_log_analysis


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
    app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "sessions")

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    # -------------------------
    # Login required decorator
    # -------------------------
    def login_required(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not session.get("logged_in"):
                flash("請先登入", "warning")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper

    # -------------------------
    # Login
    # -------------------------
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username")
            password = request.form.get("password")

            if username and password:
                session["logged_in"] = True
                session["username"] = username
                return redirect(url_for("index"))

            flash("請輸入帳號密碼", "danger")

        return render_template("login.html")

    @app.route("/logout")
    def logout():
        session.clear()
        flash("已登出", "success")
        return redirect(url_for("login"))

    # -------------------------
    # Main page
    # -------------------------
    @app.route("/", methods=["GET", "POST"])
    @login_required
    def index():

        default_end = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        default_start = (datetime.now() - timedelta(hours=1)).strftime("%Y/%m/%d %H:%M:%S")

        form_data = {
            "base_url": "",
            "token": "",
            "start_time": default_start,
            "end_time": default_end
        }

        if request.method == "POST":
            form_data["base_url"] = request.form.get("base_url", "")
            form_data["token"] = request.form.get("token", "")
            form_data["start_time"] = request.form.get("start_time", default_start)
            form_data["end_time"] = request.form.get("end_time", default_end)

            session_id = str(uuid.uuid4())
            session_dir = os.path.join(app.config["UPLOAD_FOLDER"], session_id)
            os.makedirs(session_dir, exist_ok=True)

            try:
                combined_log, summary_log = run_nginx_log_analysis(
                    base_url=form_data["base_url"],
                    token=form_data["token"],
                    start_time_str=form_data["start_time"],
                    end_time_str=form_data["end_time"],
                    output_dir=session_dir
                )

                session["last_form_data"] = form_data

                return render_template(
                    "result.html",
                    success=True,
                    session_id=session_id,
                    combined_log=os.path.basename(combined_log),
                    summary_log=os.path.basename(summary_log),
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

        if "last_form_data" in session:
            form_data = session["last_form_data"]

        return render_template(
            "index.html",
            base_url=form_data["base_url"],
            token=form_data["token"],
            default_start=form_data["start_time"],
            default_end=form_data["end_time"],
            username=session.get("username")
        )

    # -------------------------
    # Download
    # -------------------------
    @app.route("/download/<session_id>/<filename>")
    @login_required
    def download(session_id, filename):
        base_path = os.path.join(app.config["UPLOAD_FOLDER"], session_id)
        file_path = os.path.join(base_path, filename)

        if not os.path.exists(file_path):
            flash("檔案不存在", "danger")
            return redirect(url_for("index"))
        
        response = send_from_directory(base_path, filename, as_attachment=True)

        @response.call_on_close
        def remove_session_directory():
            if os.path.exists(base_path):
                shutil.rmtree(base_path, ignore_errors=True)

        # response.call_on_close(remove_session_directory)

        return response

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True, host="127.0.0.1")