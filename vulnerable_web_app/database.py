from __future__ import annotations

import sqlite3
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "demo.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_database() -> None:
    with get_connection() as connection:
        connection.execute("DROP TABLE IF EXISTS users")
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


if __name__ == "__main__":
    initialize_database()
    print(f"Initialized database at {DATABASE_PATH}")
