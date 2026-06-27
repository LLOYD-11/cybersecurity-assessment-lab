from __future__ import annotations

import sqlite3

from flask import Flask, render_template, request
from werkzeug.security import check_password_hash

from database import get_connection, initialize_database


app = Flask(__name__)


@app.route("/")
def index() -> str:
    return render_template("index.html")


@app.route("/vulnerable-login", methods=["GET", "POST"])
def vulnerable_login() -> str:
    if request.method == "GET":
        return render_template("login.html", mode="vulnerable")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = (
        "SELECT id, username FROM users "
        f"WHERE username = '{username}' AND password = '{password}'"
    )

    try:
        with get_connection() as connection:
            user = connection.execute(query).fetchone()
    except sqlite3.Error as exc:
        return render_template(
            "result.html",
            mode="vulnerable",
            success=False,
            message=f"Database error: {exc}",
            query=query,
        )

    return render_template(
        "result.html",
        mode="vulnerable",
        success=user is not None,
        message=login_message(user),
        query=query,
    )


@app.route("/secure-login", methods=["GET", "POST"])
def secure_login() -> str:
    if request.method == "GET":
        return render_template("login.html", mode="secure")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = (
        "SELECT id, username FROM users "
        "WHERE username = ? AND password = ?"
    )

    with get_connection() as connection:
        user = connection.execute(query, (username, password)).fetchone()

    return render_template(
        "result.html",
        mode="secure",
        success=user is not None,
        message=login_message(user),
        query=query,
    )


@app.route("/vulnerable-comment", methods=["GET", "POST"])
def vulnerable_comment() -> str:
    comment = ""
    if request.method == "POST":
        comment = request.form.get("comment", "")

    return render_template(
        "comment.html",
        mode="vulnerable",
        comment=comment,
    )


@app.route("/secure-comment", methods=["GET", "POST"])
def secure_comment() -> str:
    comment = ""
    if request.method == "POST":
        comment = request.form.get("comment", "")

    return render_template(
        "comment.html",
        mode="secure",
        comment=comment,
    )


@app.route("/weak-auth-login", methods=["GET", "POST"])
def weak_auth_login() -> str:
    if request.method == "GET":
        return render_template("auth_login.html", mode="weak")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = (
        "SELECT id, username, password FROM weak_auth_users "
        "WHERE username = ?"
    )

    with get_connection() as connection:
        user = connection.execute(query, (username,)).fetchone()

    success = user is not None and user["password"] == password

    return render_template(
        "auth_result.html",
        mode="weak",
        success=success,
        message=login_message(user if success else None),
        stored_value_label="Stored password",
        stored_value=user["password"] if user is not None else None,
    )


@app.route("/secure-auth-login", methods=["GET", "POST"])
def secure_auth_login() -> str:
    if request.method == "GET":
        return render_template("auth_login.html", mode="secure")

    username = request.form.get("username", "")
    password = request.form.get("password", "")

    query = (
        "SELECT id, username, password_hash FROM secure_auth_users "
        "WHERE username = ?"
    )

    with get_connection() as connection:
        user = connection.execute(query, (username,)).fetchone()

    success = user is not None and check_password_hash(user["password_hash"], password)

    return render_template(
        "auth_result.html",
        mode="secure",
        success=success,
        message=login_message(user if success else None),
        stored_value_label="Stored password hash",
        stored_value=user["password_hash"] if user is not None else None,
    )


def login_message(user: sqlite3.Row | None) -> str:
    if user is None:
        return "Login failed."
    return f"Login successful. Welcome, {user['username']}."


if __name__ == "__main__":
    initialize_database()
    app.run(host="127.0.0.1", port=5000, debug=False)
