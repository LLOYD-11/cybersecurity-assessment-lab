from __future__ import annotations

import sqlite3

from flask import Flask, render_template, request

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


def login_message(user: sqlite3.Row | None) -> str:
    if user is None:
        return "Login failed."
    return f"Login successful. Welcome, {user['username']}."


if __name__ == "__main__":
    initialize_database()
    app.run(host="127.0.0.1", port=5000, debug=False)
