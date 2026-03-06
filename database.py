import sqlite3
from datetime import datetime

def init_db():
    conn = sqlite3.connect("shieldpro.db")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS users (user_id INTEGER PRIMARY KEY, name TEXT, phone TEXT, reg_date TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS groups (group_id INTEGER PRIMARY KEY, title TEXT)")
    cursor.execute("CREATE TABLE IF NOT EXISTS threats (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id INTEGER, user_id INTEGER, threat_type TEXT, date TEXT)")
    conn.commit()
    conn.close()

def register_user(user_id, name, phone):
    conn = sqlite3.connect("shieldpro.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO users (user_id, name, phone, reg_date) VALUES (?, ?, ?, ?)", 
                   (user_id, name, phone, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def get_user(user_id):
    conn = sqlite3.connect("shieldpro.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
    res = cursor.fetchone()
    conn.close()
    return res

def add_group(group_id, title):
    conn = sqlite3.connect("shieldpro.db")
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO groups (group_id, title) VALUES (?, ?)", (group_id, title))
    conn.commit()
    conn.close()

def log_threat(group_id, user_id, threat_type):
    conn = sqlite3.connect("shieldpro.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO threats (group_id, user_id, threat_type, date) VALUES (?, ?, ?, ?)", 
                   (group_id, user_id, threat_type, datetime.now().strftime("%H:%M:%S")))
    conn.commit()
    conn.close()

def get_stats():
    conn = sqlite3.connect("shieldpro.db")
    cursor = conn.cursor()
    u = cursor.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    g = cursor.execute("SELECT COUNT(*) FROM groups").fetchone()[0]
    t = cursor.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    conn.close()
    return u, g, t