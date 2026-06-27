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

    def test_vulnerable_comment_renders_raw_script_tag(self) -> None:
        payload = "<script>alert('xss')</script>"

        response = self.client.post(
            "/vulnerable-comment",
            data={"comment": payload},
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(payload, response.get_data(as_text=True))

    def test_secure_comment_escapes_script_tag(self) -> None:
        payload = "<script>alert('xss')</script>"

        response = self.client.post(
            "/secure-comment",
            data={"comment": payload},
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(payload, body)
        self.assertIn("&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;", body)

    def test_weak_auth_login_accepts_valid_credentials_and_shows_plaintext(self) -> None:
        response = self.client.post(
            "/weak-auth-login",
            data={
                "username": "carol",
                "password": "letmein123",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful. Welcome, carol.", body)
        self.assertIn("Stored password", body)
        self.assertIn("letmein123", body)

    def test_secure_auth_login_accepts_valid_credentials_and_shows_hash(self) -> None:
        response = self.client.post(
            "/secure-auth-login",
            data={
                "username": "carol",
                "password": "letmein123",
            },
        )

        body = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful. Welcome, carol.", body)
        self.assertIn("Stored password hash", body)
        self.assertNotIn("<code>letmein123</code>", body)

    def test_secure_auth_login_rejects_wrong_password(self) -> None:
        response = self.client.post(
            "/secure-auth-login",
            data={
                "username": "carol",
                "password": "wrong-password",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn("Login failed.", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
