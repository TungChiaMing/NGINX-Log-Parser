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


class NginxLogAnalyzerApp:

    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
        self.app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "sessions")

        os.makedirs(self.app.config["UPLOAD_FOLDER"], exist_ok=True)

        self._register_routes()

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
                flash("請先登入", "warning")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapper

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
                    return redirect(url_for("index"))

                flash("請輸入帳號密碼", "danger")

            return render_template("login.html")

        @self.app.route("/logout")
        def logout():
            session.clear()
            flash("已登出", "success")
            return redirect(url_for("login"))

        @self.app.route("/", methods=["GET", "POST"])
        @self.login_required
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
                form_data.update({
                    "base_url": request.form.get("base_url", ""),
                    "token": request.form.get("token", ""),
                    "start_time": request.form.get("start_time", default_start),
                    "end_time": request.form.get("end_time", default_end),
                })

                session["last_form_data"] = form_data

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
                      url_id = base_url.replace("://", "_").replace("/", "_")

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

            if "last_form_data" in session:
                form_data = session["last_form_data"]

            return render_template(
                "index.html",
                **form_data,
                username=session.get("username")
            )

        @self.app.route("/download/<session_id>/<path:filename>")
        @self.login_required
        def download(session_id, filename):
            base_path = os.path.join(self.app.config["UPLOAD_FOLDER"], session_id)
            file_path = os.path.join(base_path, filename)

            if not os.path.exists(file_path):
                flash("檔案不存在", "danger")
                return redirect(url_for("index"))

            response = send_from_directory(base_path, filename, as_attachment=True)

            @response.call_on_close
            def cleanup():
                shutil.rmtree(base_path, ignore_errors=True)

            return response

    def run(self):
        self.app.run(debug=True, host="127.0.0.1")


if __name__ == "__main__":
    NginxLogAnalyzerApp().run()