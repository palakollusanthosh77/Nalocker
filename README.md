# Na Locker – Personal Document Locker

A Flask web application where users register, log in and keep their personal documents
(certificates, resume, education records, etc.) organised in one place.

## Features
- User registration and login with Werkzeug password hashing
- Per-user dashboard: total documents, storage used, account status
- Upload documents (drag-and-drop or file picker) with a category
- Categories: Certificates, Resume, Education, Personal, Other
- Search by document name and filter by category
- Download and delete (with a confirmation prompt); every operation is limited to the owner
- Responsive purple-and-white UI (desktop, tablet, mobile)

## Security measures implemented
- CSRF token on every POST form
- Extension allow-list (PDF, PNG, JPG/JPEG, DOCX, XLSX, PPTX, DOC, TXT), 10 MB limit,
  and file-signature (magic byte) check so the content must match the extension
- Files saved outside `static/` under random server-generated names
- Parameterized SQL queries; category validated against a server-side allow-list
- Ownership check on download/delete (other users get a 404)
- HttpOnly + SameSite cookies, `Secure` cookie in production mode, security headers (CSP, nosniff, X-Frame-Options)
- Simple login throttling (5 failed attempts / 5 minutes per email + IP; in-memory)
- Secret key read from `SECRET_KEY` (a random key is generated locally for development only)

> Files are **not encrypted at rest**. This is a learning/portfolio project and has not had an
> independent security review.

## Tech stack
Python, Flask, SQLite, HTML5, CSS3, a little vanilla JavaScript.

## Setup (Windows PowerShell)
```powershell
cd D:\nalocker
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000

If PowerShell blocks activation, run once: `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`

### Optional environment variables
| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Session signing key (required when `NALOCKER_PRODUCTION=1`) |
| `NALOCKER_PRODUCTION=1` | Secure cookies (needs HTTPS); refuses to start without `SECRET_KEY` |
| `NALOCKER_DEBUG=1` | Flask debug mode, local development only |

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_hex(32))"
```

## Run the tests
```powershell
python -m unittest discover -s tests -t . -v
```
The tests use a temporary database and upload folder, so your real data is untouched.

## Screenshots
Add your own screenshots to `docs/screenshots/` and link them here:
- `docs/screenshots/login.png`
- `docs/screenshots/dashboard.png`

## Project structure
```
nalocker/
├── app.py
├── requirements.txt
├── static/css/style.css
├── static/js/app.js
├── templates/            base, login, register, dashboard, error
├── tests/test_app.py
└── uploads/              (private; not committed)
```

## Limitations / future work
Files are not encrypted at rest, there is no password reset or email verification,
and login throttling is in-memory. For real deployment use a production WSGI server
(e.g. Waitress) behind HTTPS.
