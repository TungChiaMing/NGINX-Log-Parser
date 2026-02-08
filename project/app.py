from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)

import os
from project.nginx_parser import log_parser_router
from project.nginx_profiles import nginx_profile_router
from project.nginx_config_scanner import config_scanner_router

from project import utils


PROFILE_SAVE_DIR = os.path.join('static', "profiles")

class NginxLogAnalyzerApp:

    def __init__(self):
        self.app = Flask(__name__)
        self.app.register_blueprint(log_parser_router, url_prefix="/log_parser")
        self.app.register_blueprint(nginx_profile_router, url_prefix="/nginx_profiles")
        self.app.register_blueprint(config_scanner_router, url_prefix="/config_scanner")
        self.app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")
        self.app.config["UPLOAD_FOLDER"] = os.path.join(os.getcwd(), "sessions")

        os.makedirs(self.app.config["UPLOAD_FOLDER"], exist_ok=True)

        self._register_routes()
        

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

                flash("please enter username and password", "danger")

            return render_template("login.html")

        @self.app.route("/logout")
        def logout():
            session.clear()
            flash("logged out successfully", "success")
            return redirect(url_for("login"))
        
        @self.app.route("/")
        @utils.login_required
        def main_menu():
            return render_template("main_menu.html", username=session.get("username"))

    def run(self):
        self.app.run(debug=True, host="127.0.0.1", port=8080)


if __name__ == "__main__":
    NginxLogAnalyzerApp().run()
#
# app = NginxLogAnalyzerApp().app