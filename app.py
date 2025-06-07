import sqlite3
from flask import Flask, request, session, redirect, url_for, render_template, jsonify, g
import hashlib, os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

DB_PATH = "myaqlite.db"

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db: db.close()

def hash_pw(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    with app.app_context():
        db = get_db()
        db.execute("""CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT
        )""")
        db.execute("""CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            prompt TEXT,
            response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""")
        db.commit()

def get_user_id(username):
    db = get_db()
    cur = db.execute("SELECT id FROM users WHERE username=?", (username,))
    r = cur.fetchone()
    return r["id"] if r else None

@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        db = get_db()
        if db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone():
            error = "Username already exists."
        else:
            db.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", (username, hash_pw(password)))
            db.commit()
            session['username'] = username
            return redirect(url_for('chat'))
    return render_template('signup.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip().lower()
        password = request.form['password']
        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username=? AND password_hash=?", (username, hash_pw(password))).fetchone()
        if user:
            session['username'] = username
            return redirect(url_for('chat'))
        else:
            error = "Invalid username or password."
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html', username=session['username'])

@app.route('/api/chat', methods=['POST'])
def api_chat():
    if 'username' not in session:
        return jsonify({"error": "Not logged in"}), 401
    data = request.json
    prompt = data.get("prompt", "")
    history = data.get("history", [])
    username = session['username']

    # SVG intent detection (for image/drawing requests)
    import re
    svg_mode = bool(re.search(r"\b(draw|sketch|diagram|icon|logo|illustrat(e|ion)|map|graph|picture|image|scene|visual|show.*how|design|vector)\b", prompt, re.I))
    messages = list(history)
    if svg_mode:
        messages = [{"role": "system", "content": "You are an SVG image generator. Only output valid SVG images as responses."}] + messages
    messages.append({"role": "user", "content": prompt})

    import requests
    payload = {
        "messages": messages,
        "model": "claude-3-7-sonnet",
        "testMode": True
    }
    try:
        r = requests.post("https://api.puter.com/v2/ai/chat", json=payload, timeout=45)
        r.raise_for_status()
        result = r.json()
        response = result.get("text", "")
    except Exception as e:
        response = f"Error: {e}"

    db = get_db()
    user_id = get_user_id(username)
    db.execute("INSERT INTO messages (user_id, prompt, response) VALUES (?, ?, ?)", (user_id, prompt, response))
    db.commit()
    return jsonify({"response": response, "svg_mode": svg_mode})

@app.route('/api/messages')
def api_messages():
    if 'username' not in session:
        return jsonify([])
    db = get_db()
    user_id = get_user_id(session['username'])
    cur = db.execute("SELECT prompt, response, created_at FROM messages WHERE user_id=? ORDER BY created_at ASC", (user_id,))
    rows = cur.fetchall()
    return jsonify([{"prompt": r["prompt"], "response": r["response"], "created_at": r["created_at"]} for r in rows])

if __name__ == "__main__":
    init_db()
    # For AWS, use port 80. Run as root or use a reverse proxy in production.
    app.run(host="0.0.0.0", port=80)