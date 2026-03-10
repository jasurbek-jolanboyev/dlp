import sqlite3
from datetime import datetime

DB_NAME = "dlp_system.db"

def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Foydalanuvchilar jadvali
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        name TEXT,
        phone TEXT,
        reg_date TEXT,
        last_seen TEXT
    )''')
    
    # Guruhlar jadvali
    cursor.execute('''CREATE TABLE IF NOT EXISTS groups (
        id INTEGER PRIMARY KEY,
        title TEXT,
        added_date TEXT
    )''')
    
    # Hodisalar (Tahdidlar) jadvali
    cursor.execute('''CREATE TABLE IF NOT EXISTS incidents (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        chat_id INTEGER,
        chat_title TEXT,
        user_info TEXT,
        threat_type TEXT,
        content TEXT,
        timestamp TEXT
    )''')
    
    conn.commit()
    conn.close()

def register_user(user_id, name, phone):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT OR REPLACE INTO users (id, name, phone, reg_date, last_seen) VALUES (?, ?, ?, ?, ?)",
                   (user_id, name, phone, now, now))
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

def update_last_seen(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("UPDATE users SET last_seen = ? WHERE id = ?", (now, user_id))
    conn.commit()
    conn.close()

def add_group(chat_id, title):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("INSERT OR IGNORE INTO groups (id, title, added_date) VALUES (?, ?, ?)", (chat_id, title, now))
    conn.commit()
    conn.close()

def add_incident(chat_id, chat_title, user_info, threat_type, content, timestamp):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO incidents (chat_id, chat_title, user_info, threat_type, content, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
                   (chat_id, chat_title, user_info, threat_type, content, timestamp))
    conn.commit()
    conn.close()

def get_user_history(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # User_info ichidan ID ni qidirish (Sizning kodingizda user_info da [ID:xxx] bor)
    cursor.execute("SELECT COUNT(*) FROM incidents WHERE user_info LIKE ?", (f"%ID:{user_id}%",))
    count = cursor.fetchone()[0]
    conn.close()
    return count

def get_stats():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    u = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    g = cursor.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
    t = cursor.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    conn.close()
    return u, g, t

def get_all_users():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users")
    users = cursor.fetchall()
    conn.close()
    return users

def get_all_users_detailed():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, name, phone, reg_date, last_seen FROM users ORDER BY last_seen DESC")
    users = cursor.fetchall()
    conn.close()
    return users

def get_all_groups():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, title FROM groups")
    groups = cursor.fetchall()
    conn.close()
    return groups

def get_total_logs_count():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    count = cursor.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    conn.close()
    return count

def get_log_by_offset(offset):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    # Oxirgi qo'shilgan xavfni birinchi ko'rsatish
    cursor.execute("SELECT * FROM incidents ORDER BY id DESC LIMIT 1 OFFSET ?", (offset,))
    log = cursor.fetchone()
    conn.close()
    return log