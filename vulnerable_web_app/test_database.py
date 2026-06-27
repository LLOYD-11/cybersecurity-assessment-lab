import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database


class DatabaseTests(unittest.TestCase):
    def test_initialize_database_creates_demo_users(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_database = Path(temp_dir) / "demo.db"

            with patch.object(database, "DATABASE_PATH", temp_database):
                database.initialize_database()

                with database.get_connection() as connection:
                    users = connection.execute(
                        "SELECT username FROM users ORDER BY username"
                    ).fetchall()

        self.assertEqual([user["username"] for user in users], ["alice", "bob"])

    def test_vulnerable_query_can_be_bypassed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_database = Path(temp_dir) / "demo.db"

            with patch.object(database, "DATABASE_PATH", temp_database):
                database.initialize_database()

                username = "' OR '1'='1' --"
                password = "anything"
                query = (
                    "SELECT id, username FROM users "
                    f"WHERE username = '{username}' AND password = '{password}'"
                )

                with database.get_connection() as connection:
                    user = connection.execute(query).fetchone()

        self.assertIsNotNone(user)
        self.assertEqual(user["username"], "alice")

    def test_parameterized_query_rejects_injection_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_database = Path(temp_dir) / "demo.db"

            with patch.object(database, "DATABASE_PATH", temp_database):
                database.initialize_database()

                username = "' OR '1'='1' --"
                password = "anything"
                query = (
                    "SELECT id, username FROM users "
                    "WHERE username = ? AND password = ?"
                )

                with database.get_connection() as connection:
                    user = connection.execute(query, (username, password)).fetchone()

        self.assertIsNone(user)


if __name__ == "__main__":
    unittest.main()
