import unittest

from app import app
from database import initialize_database


class AppTests(unittest.TestCase):
    def setUp(self) -> None:
        initialize_database()
        self.client = app.test_client()

    def test_home_page_loads(self) -> None:
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Vulnerable Web App", response.get_data(as_text=True))

    def test_vulnerable_login_accepts_valid_credentials(self) -> None:
        response = self.client.post(
            "/vulnerable-login",
            data={
                "username": "alice",
                "password": "password123",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful. Welcome, alice.", response.get_data(as_text=True))

    def test_vulnerable_login_can_be_bypassed_with_sql_injection(self) -> None:
        response = self.client.post(
            "/vulnerable-login",
            data={
                "username": "' OR '1'='1' --",
                "password": "anything",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful. Welcome, alice.", response.get_data(as_text=True))

    def test_secure_login_rejects_sql_injection_payload(self) -> None:
        response = self.client.post(
            "/secure-login",
            data={
                "username": "' OR '1'='1' --",
                "password": "anything",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Login failed.", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
