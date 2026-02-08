from flask import (
    Flask, render_template, request, redirect,
    url_for, session, send_from_directory, flash, jsonify
)


import os
from functools import wraps


PROFILE_SAVE_DIR = os.path.join('static', "profiles")

def read_text_file_safe(path, max_bytes=200_000):
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

def create_profile_save_dir():
    if not os.path.exists(PROFILE_SAVE_DIR):
        os.makedirs(PROFILE_SAVE_DIR)