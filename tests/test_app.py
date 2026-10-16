import io
import re
import sqlite3
import tempfile
import unittest
import zipfile
from pathlib import Path

from app import create_app, MAX_UPLOAD_BYTES

PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\ntrailer\n%%EOF\n"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


def make_docx():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w/>")
    return buf.getvalue()


class NaLockerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.app = create_app({
            "TESTING": True, "SECRET_KEY": "test-key",
            "DATABASE": str(Path(self.tmp.name) / "t.db"),
            "UPLOAD_FOLDER": str(Path(self.tmp.name) / "up"),
        })
        self.client = self.app.test_client()

    def tearDown(self):
        self.tmp.cleanup()

    # helpers
    def token(self, client=None, path="/login"):
        c = client or self.client
        html = c.get(path).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def register(self, client=None, name="Asha", email="asha@example.com", pw="secret123", confirm=None):
        c = client or self.client
        return c.post("/register", data={"csrf_token": self.token(c, "/register"), "name": name, "email": email,
                                         "password": pw, "confirm_password": confirm or pw}, follow_redirects=True)

    def login(self, client=None, email="asha@example.com", pw="secret123"):
        c = client or self.client
        return c.post("/login", data={"csrf_token": self.token(c), "email": email, "password": pw}, follow_redirects=True)

    def upload(self, name="cv.pdf", data=PDF, category="Resume", display="", client=None):
        c = client or self.client
        return c.post("/upload", data={"csrf_token": self.token(c, "/dashboard"), "category": category,
                                       "display_name": display, "document": (io.BytesIO(data), name)},
                      content_type="multipart/form-data", follow_redirects=True)

    def second_client(self):
        c = self.app.test_client()
        self.register(c, "Ravi", "ravi@example.com")
        self.login(c, "ravi@example.com")
        return c

    # registration
    def test_register_valid_and_password_hashed(self):
        r = self.register()
        self.assertIn("Account created", r.get_data(as_text=True))
        row = sqlite3.connect(self.app.config["DATABASE"]).execute("SELECT password_hash FROM users").fetchone()
        self.assertNotIn("secret123", row[0])
        self.assertTrue(row[0].startswith(("scrypt:", "pbkdf2:")))

    def test_register_invalid_inputs(self):
        self.assertIn("valid email", self.register(email="nope").get_data(as_text=True))
        self.assertIn("at least 8", self.register(pw="a1").get_data(as_text=True))
        self.assertIn("letter and one number", self.register(pw="abcdefgh").get_data(as_text=True))
        self.assertIn("do not match", self.register(confirm="different1").get_data(as_text=True))
        self.assertIn("name", self.register(name="A").get_data(as_text=True).lower())

    def test_duplicate_email(self):
        self.register()
        r = self.register(email="ASHA@example.com")
        self.assertIn("already exists", r.get_data(as_text=True))

    # login / logout / auth
    def test_login_success_and_failure(self):
        self.register()
        self.assertIn("Welcome, Asha", self.login().get_data(as_text=True))
        c = self.app.test_client()
        self.assertIn("Incorrect email or password", self.login(c, pw="wrongpass1").get_data(as_text=True))

    def test_logout_and_protected_routes(self):
        self.register(); self.login()
        c = self.client
        r = c.post("/logout", data={"csrf_token": self.token(c, "/dashboard")}, follow_redirects=True)
        self.assertIn("logged out", r.get_data(as_text=True))
        for path in ("/dashboard", "/download/1"):
            self.assertEqual(c.get(path).status_code, 302)
        self.assertEqual(c.post("/upload", data={}).status_code, 302)

    # CSRF
    def test_missing_or_bad_csrf_rejected(self):
        self.register()
        r = self.client.post("/login", data={"email": "asha@example.com", "password": "secret123"}, follow_redirects=True)
        self.assertIn("session expired", r.get_data(as_text=True))
        r = self.client.post("/login", data={"csrf_token": "bad", "email": "asha@example.com", "password": "secret123"}, follow_redirects=True)
        self.assertIn("session expired", r.get_data(as_text=True))
        self.assertNotIn("Welcome, Asha", r.get_data(as_text=True))

    def test_delete_requires_csrf(self):
        self.register(); self.login(); self.upload()
        self.client.post("/delete/1", data={})
        self.assertIn("cv.pdf", self.client.get("/dashboard").get_data(as_text=True))

    # uploads
    def test_upload_supported_types(self):
        self.register(); self.login()
        self.assertIn("uploaded successfully", self.upload().get_data(as_text=True))
        self.assertIn("uploaded successfully", self.upload("pic.png", PNG, "Personal").get_data(as_text=True))
        self.assertIn("uploaded successfully", self.upload("d.docx", make_docx(), "Education").get_data(as_text=True))
        self.assertIn("uploaded successfully", self.upload("n.txt", b"hello", "Other").get_data(as_text=True))
        self.assertIn("Total documents</span><span class=\"stat-value\">4", self.client.get("/dashboard").get_data(as_text=True))

    def test_server_filename_is_random(self):
        self.register(); self.login(); self.upload("../../evil name.pdf")
        files = list(Path(self.app.config["UPLOAD_FOLDER"]).iterdir())
        self.assertEqual(len(files), 1)
        self.assertNotIn("evil", files[0].name)
        self.assertRegex(files[0].name, r"^[0-9a-f]{32}\.pdf$")

    def test_reject_bad_extension_content_category_and_empty(self):
        self.register(); self.login()
        self.assertIn("Unsupported file type", self.upload("run.exe", b"MZ").get_data(as_text=True))
        self.assertIn("Unsupported file type", self.upload("noext", b"abc").get_data(as_text=True))
        self.assertIn("do not match", self.upload("fake.pdf", b"not a pdf").get_data(as_text=True))
        self.assertIn("do not match", self.upload("fake.png", PDF).get_data(as_text=True))
        self.assertIn("do not match", self.upload("fake.docx", b"plain text").get_data(as_text=True))
        self.assertIn("valid category", self.upload(category="Hacking").get_data(as_text=True))
        self.assertIn("empty", self.upload("e.txt", b"").get_data(as_text=True))
        self.assertEqual(list(Path(self.app.config["UPLOAD_FOLDER"]).iterdir()), [])

    def test_reject_oversized(self):
        self.register(); self.login()
        big = PDF + b"0" * (MAX_UPLOAD_BYTES + 10)
        self.assertIn("too large", self.upload("big.pdf", big).get_data(as_text=True))
        huge = PDF + b"0" * (MAX_UPLOAD_BYTES + 200_000)  # over the request limit -> 413 handler
        self.assertIn("too large", self.upload("huge.pdf", huge).get_data(as_text=True))
        self.assertEqual(list(Path(self.app.config["UPLOAD_FOLDER"]).iterdir()), [])

    # search / filter
    def test_search_filter_and_like_escaping(self):
        self.register(); self.login()
        self.upload("resume_final.pdf", PDF, "Resume")
        self.upload("degree.pdf", PDF, "Education")
        self.upload("100%_sure.pdf", PDF, "Other")
        html = self.client.get("/dashboard?q=resume").get_data(as_text=True)
        self.assertIn("resume_final.pdf", html); self.assertNotIn("degree.pdf", html)
        html = self.client.get("/dashboard?category=Education").get_data(as_text=True)
        self.assertIn("degree.pdf", html); self.assertNotIn("resume_final.pdf", html)
        html = self.client.get("/dashboard?q=%25").get_data(as_text=True)  # literal '%'
        self.assertIn("100%_sure.pdf", html); self.assertNotIn("degree.pdf", html)
        self.assertIn("No matching documents", self.client.get("/dashboard?q=zzz").get_data(as_text=True))
        self.assertIn("degree.pdf", self.client.get("/dashboard?category=Bogus").get_data(as_text=True))

    def test_empty_state(self):
        self.register(); self.login()
        self.assertIn("Your locker is empty", self.client.get("/dashboard").get_data(as_text=True))

    # download / delete / ownership
    def test_download_and_delete(self):
        self.register(); self.login(); self.upload("cv.pdf", PDF)
        r = self.client.get("/download/1")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.data, PDF)
        self.assertIn("attachment", r.headers["Content-Disposition"])
        c = self.client
        r = c.post("/delete/1", data={"csrf_token": self.token(c, "/dashboard")}, follow_redirects=True)
        self.assertIn("Document deleted", r.get_data(as_text=True))
        self.assertEqual(list(Path(self.app.config["UPLOAD_FOLDER"]).iterdir()), [])
        self.assertEqual(c.get("/download/1").status_code, 404)

    def test_other_user_cannot_access_document(self):
        self.register(); self.login(); self.upload("secret.pdf", PDF)
        other = self.second_client()
        self.assertEqual(other.get("/download/1").status_code, 404)
        r = other.post("/delete/1", data={"csrf_token": self.token(other, "/dashboard")})
        self.assertEqual(r.status_code, 404)
        self.assertNotIn("secret.pdf", other.get("/dashboard").get_data(as_text=True))
        self.assertEqual(self.client.get("/download/1").status_code, 200)  # still there for owner

    # persistence / migration
    def test_data_persists_across_app_restart(self):
        self.register(); self.login(); self.upload("keep.pdf", PDF)
        app2 = create_app({"TESTING": True, "SECRET_KEY": "test-key", "DATABASE": self.app.config["DATABASE"],
                           "UPLOAD_FOLDER": self.app.config["UPLOAD_FOLDER"]})
        c = app2.test_client()
        self.login(c)
        self.assertIn("keep.pdf", c.get("/dashboard").get_data(as_text=True))

    def test_migrates_legacy_database_without_losing_users(self):
        from werkzeug.security import generate_password_hash
        path = Path(self.tmp.name) / "legacy.db"
        conn = sqlite3.connect(path)
        conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT, password TEXT)")
        conn.execute("INSERT INTO users (email, password) VALUES (?, ?)", ("old@example.com", generate_password_hash("oldpass123")))
        conn.commit(); conn.close()
        app = create_app({"TESTING": True, "SECRET_KEY": "k", "DATABASE": str(path),
                          "UPLOAD_FOLDER": str(Path(self.tmp.name) / "up2")})
        c = app.test_client()
        r = self.login(c, "old@example.com", "oldpass123")
        self.assertIn("Welcome, old", r.get_data(as_text=True))

    def test_security_headers_and_css_link(self):
        r = self.client.get("/login")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        self.assertIn("/static/css/style.css", r.get_data(as_text=True))
        self.assertEqual(self.client.get("/static/css/style.css").status_code, 200)

    def test_uploads_not_served_statically(self):
        self.register(); self.login(); self.upload()
        name = next(Path(self.app.config["UPLOAD_FOLDER"]).iterdir()).name
        self.assertEqual(self.client.get(f"/static/{name}").status_code, 404)
        self.assertEqual(self.client.get(f"/uploads/{name}").status_code, 404)


if __name__ == "__main__":
    unittest.main()
