import os
import tempfile
import unittest
from io import BytesIO

_runtime = tempfile.TemporaryDirectory()
os.environ["SCAMSHIELD_DATA_DIR"] = _runtime.name
os.environ["ADMIN_PASSWORD"] = "test-only-password-12345"
from app import app, normalize_phone

class SecurityTests(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
    def token(self, path="/report"):
        self.client.get(path)
        with self.client.session_transaction() as s:
            return s["csrf_token"]
    def test_pages_and_admin_guard(self):
        for path in ("/", "/report", "/check-number", "/admin/login"):
            self.assertEqual(self.client.get(path).status_code, 200)
        self.assertEqual(self.client.get("/admin/dashboard").status_code, 302)
    def test_csrf_required(self):
        self.assertEqual(self.client.post("/report", data={"message":"hello"}).status_code, 400)
    def test_phone_normalization(self):
        self.assertEqual(normalize_phone("00 94-771234567"), "+94771234567")
        with self.assertRaises(ValueError): normalize_phone("abc")
    def test_report_access_isolation(self):
        response = self.client.post("/report", data={"csrf_token": self.token(), "phone_number":"+94770000000", "message":"Meeting at ten tomorrow", "category":"Other"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get(response.location).status_code, 200)
        self.assertEqual(app.test_client().get(response.location).status_code, 404)
    def test_fake_image_rejected(self):
        response = self.client.post("/report", data={"csrf_token": self.token(), "phone_number":"+94770000000", "message":"test", "screenshot":(BytesIO(b"not an image"),"fake.png")})
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("/result/", response.headers.get("Location", ""))
    def test_admin_login_and_post_logout(self):
        response=self.client.post("/admin/login", data={"csrf_token":self.token("/admin/login"), "username":"admin", "password":"test-only-password-12345"})
        self.assertEqual(response.status_code, 302)
        self.assertEqual(self.client.get("/admin/dashboard").status_code, 200)
        self.assertEqual(self.client.get("/admin/logout").status_code, 405)

if __name__ == "__main__": unittest.main()
