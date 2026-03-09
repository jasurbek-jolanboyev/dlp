import sqlite3
from datetime import datetime

DB_NAME = "dlp_system.db"

def init_db():
    """Barcha kerakli jadvallarni yaratish"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # 1. Foydalanuvchilar jadvali
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            full_name TEXT,
            phone TEXT,
            reg_date TEXT,
            last_seen TEXT
        )
    ''')
    
    # 2. Guruhlar jadvali
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            chat_id INTEGER PRIMARY KEY,
            title TEXT,
            added_date TEXT
        )
    ''')
    
    # 3. Kiberxavfsizlik hodisalari (Incidentlar) jadvali
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_id INTEGER,
            chat_title TEXT,
            user_info TEXT,
            threat_type TEXT,
            content TEXT,
            timestamp TEXT
        )
    ''')
    
    conn.commit()
    conn.close()

# --- FOYDALANUVCHILAR BILAN ISHLASH ---

def register_user(user_id, name, phone):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT OR REPLACE INTO users VALUES (?, ?, ?, ?, ?)", 
                   (user_id, name, phone, now, now))
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    res = cursor.fetchone()
    conn.close()
    return res

def update_last_seen(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("UPDATE users SET last_seen = ? WHERE user_id = ?", (now, user_id))
    conn.commit()
    conn.close()

def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT user_id FROM users")
    res = cursor.fetchall()
    conn.close()
    return res

def get_all_users_detailed():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users ORDER BY last_seen DESC")
    res = cursor.fetchall()
    conn.close()
    return res

# --- GURUHLAR BILAN ISHLASH ---

def add_group(chat_id, title):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d")
    cursor.execute("INSERT OR IGNORE INTO groups VALUES (?, ?, ?)", (chat_id, title, now))
    conn.commit()
    conn.close()

def get_all_groups():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM groups")
    res = cursor.fetchall()
    conn.close()
    return res

# --- INCIDENTLAR (XAVFLAR) BILAN ISHLASH ---

def add_incident(chat_id, title, user, threat, content, time):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO incidents (chat_id, chat_title, user_info, threat_type, content, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                   (chat_id, title, user, threat, content, time))
    conn.commit()
    conn.close()

def get_total_logs_count():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM incidents")
    res = cursor.fetchone()[0]
    conn.close()
    return res

def get_log_by_offset(offset):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Oxirgi qo'shilganidan boshlab ko'rsatish
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1 OFFSET ?", (offset,))
    res = cursor.fetchone()
    conn.close()
    return res

# --- STATISTIKA ---

def get_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM users")
    u = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM groups")
    g = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM incidents")
    t = cursor.fetchone()[0]
    conn.close()
    return u, g, t