from __future__ import annotations

import sqlite3
from pathlib import Path

from werkzeug.security import generate_password_hash


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "demo.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute("DROP TABLE IF EXISTS users")
        connection.execute("DROP TABLE IF EXISTS weak_auth_users")
        connection.execute("DROP TABLE IF EXISTS secure_auth_users")
        connection.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO users (username, password) VALUES (?, ?)",
            [
                ("alice", "password123"),
                ("bob", "hunter2"),
            ],
        )
        connection.execute(
            """
            CREATE TABLE weak_auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE secure_auth_users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL
            )
            """
        )
        connection.executemany(
            "INSERT INTO weak_auth_users (username, password) VALUES (?, ?)",
            [
                ("carol", "letmein123"),
                ("dave", "sunshine"),
            ],
        )
        connection.executemany(
            "INSERT INTO secure_auth_users (username, password_hash) VALUES (?, ?)",
            [
                ("carol", generate_password_hash("letmein123")),
                ("dave", generate_password_hash("sunshine")),
            ],
        )


if __name__ == "__main__":
    initialize_database()
    print(f"Initialized database at {DATABASE_PATH}")
