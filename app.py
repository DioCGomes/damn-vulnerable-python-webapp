import os
import pickle
import base64
import sqlite3
import subprocess
import urllib.request
from functools import wraps
from xml.etree import ElementTree as ET

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, make_response, g, send_file
)

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret key (Sensitive Data Exposure)
app.secret_key = "super_secret_key_12345"

DATABASE = "vulnerable.db"


# ═══════════════════════════════════════════════════════════════════════════════
# DATABASE SETUP
# ═══════════════════════════════════════════════════════════════════════════════

def get_db():
    """Get database connection."""
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db


@app.teardown_appcontext
def close_connection(exception):
    """Close database connection."""
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database with vulnerable schema."""
    with app.app_context():
        db = get_db()
        db.executescript('''
            DROP TABLE IF EXISTS users;
            DROP TABLE IF EXISTS posts;
            DROP TABLE IF EXISTS secrets;
            
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL,  -- VULNERABILITY: Plaintext passwords
                email TEXT,
                role TEXT DEFAULT 'user',
                api_key TEXT
            );
            
            CREATE TABLE posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                title TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            
            CREATE TABLE secrets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                secret_data TEXT
            );
            
            -- Default users (VULNERABILITY: Weak passwords)
            INSERT INTO users (username, password, email, role, api_key) VALUES 
                ('admin', 'admin123', 'admin@vulnerable.local', 'admin', 'sk_live_admin_key_12345'),
                ('user', 'password', 'user@vulnerable.local', 'user', 'sk_live_user_key_67890'),
                ('guest', 'guest', 'guest@vulnerable.local', 'guest', NULL);
            
            INSERT INTO posts (user_id, title, content) VALUES
                (1, 'Welcome Post', 'Welcome to our vulnerable application!'),
                (2, 'User Post', 'This is a regular user post.');
            
            INSERT INTO secrets (user_id, secret_data) VALUES
                (1, 'Admin secret: The nuclear codes are 12345'),
                (2, 'User secret: My password is also password');
        ''')
        db.commit()


# ═══════════════════════════════════════════════════════════════════════════════
# AUTHENTICATION (BROKEN)
# ═══════════════════════════════════════════════════════════════════════════════

def login_required(f):
    """Simple login decorator - VULNERABILITY: No proper session validation."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# ═══════════════════════════════════════════════════════════════════════════════
# ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        db = get_db()
        # VULNERABILITY: SQL Injection - string concatenation
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
        
        try:
            user = db.execute(query).fetchone()
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['role'] = user['role']
                flash(f'Welcome back, {user["username"]}!', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid credentials'
        except sqlite3.Error as e:
            # VULNERABILITY: Verbose error messages
            error = f'Database error: {str(e)}'
    
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        email = request.form.get('email', '')
        
        db = get_db()
        query = f"INSERT INTO users (username, password, email) VALUES ('{username}', '{password}', '{email}')"
        
        try:
            db.execute(query)
            db.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except sqlite3.Error as e:
            flash(f'Error: {str(e)}', 'danger')
    
    return render_template('register.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    posts = db.execute('SELECT * FROM posts ORDER BY created_at DESC').fetchall()
    return render_template('dashboard.html', posts=posts)


@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []
    
    if query:
        db = get_db()
        # VULNERABILITY: SQL Injection + XSS
        sql = f"SELECT * FROM posts WHERE title LIKE '%{query}%' OR content LIKE '%{query}%'"
        try:
            results = db.execute(sql).fetchall()
        except sqlite3.Error:
            pass
    
    # VULNERABILITY: Query reflected without sanitization
    return render_template('search.html', query=query, results=results)


@app.route('/post/new', methods=['GET', 'POST'])
@login_required
def new_post():
    if request.method == 'POST':
        title = request.form.get('title', '')
        content = request.form.get('content', '')
        
        db = get_db()
        # VULNERABILITY: SQL Injection + Stored XSS
        query = f"INSERT INTO posts (user_id, title, content) VALUES ({session['user_id']}, '{title}', '{content}')"
        db.execute(query)
        db.commit()
        
        flash('Post created!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('new_post.html')


@app.route('/profile/<int:user_id>')
@login_required
def profile(user_id):
    db = get_db()
    user = db.execute(f'SELECT * FROM users WHERE id = {user_id}').fetchone()
    secrets = db.execute(f'SELECT * FROM secrets WHERE user_id = {user_id}').fetchall()
    
    if user:
        # VULNERABILITY: Exposing sensitive data including API keys
        return render_template('profile.html', user=user, secrets=secrets)
    
    return "User not found", 404


@app.route('/admin')
@login_required
def admin():
    db = get_db()
    users = db.execute('SELECT * FROM users').fetchall()
    return render_template('admin.html', users=users)


@app.route('/cmd')
@login_required
def cmd():
    host = request.args.get('host', '')
    output = ''
    
    if host:
        # VULNERABILITY: Direct command execution with user input
        try:
            result = subprocess.run(
                f'ping -c 1 {host}',
                shell=True,  # DANGEROUS!
                capture_output=True,
                text=True,
                timeout=10
            )
            output = result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            output = "Command timed out"
        except Exception as e:
            output = str(e)
    
    return render_template('cmd.html', host=host, output=output)


@app.route('/file')
@login_required
def file_view():
    filename = request.args.get('name', '')
    content = ''
    
    if filename:
        # VULNERABILITY: No path validation
        filepath = os.path.join('uploads', filename)
        try:
            with open(filepath, 'r') as f:
                content = f.read()
        except Exception as e:
            content = f"Error reading file: {e}"
    
    return render_template('file.html', filename=filename, content=content)


@app.route('/download')
@login_required
def download():
    filename = request.args.get('file', '')
    
    if filename:
        # VULNERABILITY: No validation of file path
        filepath = os.path.join('uploads', filename)
        try:
            return send_file(filepath, as_attachment=True)
        except:
            return "File not found", 404
    
    return "No file specified", 400


@app.route('/api/fetch')
def api_fetch():
    url = request.args.get('url', '')
    content = ''
    
    if url:
        try:
            # VULNERABILITY: Fetching arbitrary URLs
            with urllib.request.urlopen(url, timeout=5) as response:
                content = response.read().decode('utf-8')
        except Exception as e:
            content = f"Error: {e}"
    
    return render_template('fetch.html', url=url, content=content)


@app.route('/api/deserialize', methods=['POST'])
def deserialize():
    data = request.form.get('data', '')
    result = ''
    
    if data:
        try:
            # VULNERABILITY: Deserializing untrusted data
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            result = f"Deserialized object: {obj}"
        except Exception as e:
            result = f"Error: {e}"
    
    return render_template('deserialize.html', result=result)


@app.route('/api/xml', methods=['GET', 'POST'])
def xml_parse():
    result = ''
    
    if request.method == 'POST':
        xml_data = request.form.get('xml', '')
        
        if xml_data:
            try:
                # VULNERABILITY: Parsing XML with external entities enabled
                # Note: ElementTree is somewhat safe by default, but this shows the pattern
                root = ET.fromstring(xml_data)
                result = f"Parsed XML: {ET.tostring(root, encoding='unicode')}"
            except Exception as e:
                result = f"Error parsing XML: {e}"
    
    return render_template('xml.html', result=result)


@app.route('/api/user', methods=['GET'])
def api_user():
    db = get_db()
    users = db.execute('SELECT id, username, password, email, api_key FROM users').fetchall()
    
    # VULNERABILITY: Returning passwords and API keys
    return {
        'users': [dict(u) for u in users]
    }


@app.route('/debug')
def debug():
    return {
        'secret_key': app.secret_key,
        'database': DATABASE,
        'session': dict(session),
        'environment': dict(os.environ),
        'config': {k: str(v) for k, v in app.config.items()}
    }


@app.route('/backup')
def backup():
    return send_file(DATABASE, as_attachment=True)


# ═══════════════════════════════════════════════════════════════════════════════
# ERROR HANDLERS
# ═══════════════════════════════════════════════════════════════════════════════

@app.errorhandler(500)
def internal_error(error):
    return f"""
    <h1>Internal Server Error</h1>
    <p>Error details: {error}</p>
    <pre>{error.__traceback__}</pre>
    """, 500


# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == '__main__':
    # Create uploads directory
    os.makedirs('uploads', exist_ok=True)
    
    # Create a sample file in uploads
    with open('uploads/readme.txt', 'w') as f:
        f.write('This is a sample file in the uploads directory.\n')
        f.write('Try to read files outside this directory using path traversal!\n')
    
    # Initialize database
    init_db()
    
    # VULNERABILITY: Debug mode enabled, binding to all interfaces
    app.run(host='0.0.0.0', port=5000, debug=True)

