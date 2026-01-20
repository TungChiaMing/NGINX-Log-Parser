from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, flash
)
from functools import wraps
from datetime import datetime, timedelta
import os
import uuid
import shutil

from parser import run_nginx_pipe_analysis  # 確保 parser 已更新成回傳 (combined, summary)


def create_app():
    app = Flask(__name__)
    app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
    app.config["UPLOAD_FOLDER"] = "./sessions"

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
        return redirect(url_for("login"))

    # -------------------------
    # Main page
    # -------------------------
    @app.route("/", methods=["GET", "POST"])
    @login_required
    def index():
        if request.method == "POST":
            base_url = request.form["base_url"]
            token = request.form["token"]
            start_time = request.form["start_time"]
            end_time = request.form["end_time"]

            session_id = str(uuid.uuid4())
            session_dir = os.path.join(app.config["UPLOAD_FOLDER"], session_id)
            os.makedirs(session_dir, exist_ok=True)

            try:
                combined_log, summary_log = run_nginx_pipe_analysis(
                    base_url=base_url,
                    token=token,
                    start_time_str=start_time,
                    end_time_str=end_time,
                    output_dir=session_dir
                )

                # render result.html with two download links
                return render_template(
                    "result.html",
                    success=True,
                    session_id=session_id,
                    combined_log=os.path.basename(combined_log),
                    summary_log=os.path.basename(summary_log)
                )

            except Exception as e:
                shutil.rmtree(session_dir, ignore_errors=True)
                return render_template(
                    "result.html",
                    success=False,
                    error=str(e)
                )

        default_end = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
        default_start = (datetime.now() - timedelta(hours=1)).strftime("%Y/%m/%d %H:%M:%S")

        return render_template(
            "index.html",
            default_start=default_start,
            default_end=default_end
        )

    # -------------------------
    # Download
    # -------------------------
    @app.route("/download/<session_id>/<filename>")
    @login_required
    def download(session_id, filename):
        base = os.path.join(app.config["UPLOAD_FOLDER"], session_id)
        return send_from_directory(base, filename, as_attachment=True)

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)