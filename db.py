import psycopg2
from psycopg2.extras import RealDictCursor
from datetime import datetime
import hashlib

DB_CONFIG = {
    'dbname': 'timp_rgr',
    'user': 'postgres',
    'password': '123',
    'host': 'localhost',
    'port': '5432'
}

def get_connection():
    return psycopg2.connect(**DB_CONFIG)

def save_scan_to_db(aps):
    conn = get_connection()
    cur = conn.cursor()
    open_count = sum(1 for ap in aps if ap.get('is_open'))
    suspicious_count = sum(1 for ap in aps if ap.get('is_suspicious'))
    cur.execute("""
        INSERT INTO scan_logs (scan_time, total_found, open_found, suspicious_found)
        VALUES (NOW(), %s, %s, %s) RETURNING id
    """, (len(aps), open_count, suspicious_count))
    scan_id = cur.fetchone()[0]
    for ap in aps:
        cur.execute("""
            SELECT id FROM access_points WHERE bssid = %s
        """, (ap.get('bssid'),))
        row = cur.fetchone()
        now = datetime.now()
        # Преобразуем signal и channel к int, если возможно, иначе None
        signal = ap.get('signal')
        try:
            signal = int(signal)
        except (TypeError, ValueError):
            signal = None
        channel = ap.get('channel')
        try:
            channel = int(channel)
        except (TypeError, ValueError):
            channel = None
        # Преобразуем encryption к строке
        encryption = ap.get('encryption')
        if encryption is None:
            encryption = ''
        ssid = ap.get('ssid') or ''
        bssid = ap.get('bssid') or ''
        if row:
            ap_id = row[0]
            cur.execute("""
                UPDATE access_points SET last_seen = %s WHERE id = %s
            """, (now, ap_id))
        else:
            cur.execute("""
                INSERT INTO access_points (ssid, bssid, signal_strength, channel, encryption, is_open, is_suspicious, first_seen, last_seen)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s) RETURNING id
            """, (
                ssid, bssid, signal, channel, encryption,
                ap.get('is_open', False), ap.get('is_suspicious', False), now, now
            ))
            ap_id = cur.fetchone()[0]
        cur.execute("""
            INSERT INTO ap_scan_rel (scan_id, ap_id) VALUES (%s, %s)
        """, (scan_id, ap_id))
    conn.commit()
    cur.close()
    conn.close()

def get_scan_history():
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, scan_time, total_found, open_found, suspicious_found FROM scan_logs ORDER BY scan_time DESC LIMIT 20")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return rows

def get_access_points(filter_open=None, filter_suspicious=None):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    query = "SELECT ssid, bssid, signal_strength, channel, encryption, is_open, is_suspicious FROM access_points"
    conditions = []
    params = []
    if filter_open is not None:
        conditions.append("is_open = %s")
        params.append(filter_open)
    if filter_suspicious is not None:
        conditions.append("is_suspicious = %s")
        params.append(filter_suspicious)
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY last_seen DESC LIMIT 100"
    cur.execute(query, params)
    rows = cur.fetchall()
    cur.close()
    conn.close()
    # Заменяем None на пустую строку для нужных полей
    for ap in rows:
        for key in ['ssid', 'bssid', 'encryption']:
            if ap[key] is None:
                ap[key] = ''
        for key in ['signal_strength', 'channel']:
            if ap[key] is None:
                ap[key] = ''
    return rows

def get_access_points_by_scan(scan_id):
    conn = get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT ap.ssid, ap.bssid, ap.signal_strength, ap.channel, ap.encryption, ap.is_open, ap.is_suspicious
        FROM access_points ap
        JOIN ap_scan_rel rel ON ap.id = rel.ap_id
        WHERE rel.scan_id = %s
        ORDER BY ap.ssid
    """, (scan_id,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    # Заменяем None на пустую строку для нужных полей
    for ap in rows:
        for key in ['ssid', 'bssid', 'encryption']:
            if ap[key] is None:
                ap[key] = ''
        for key in ['signal_strength', 'channel']:
            if ap[key] is None:
                ap[key] = ''
    return rows

def check_user_credentials(username, password):
    conn = get_connection()
    cur = conn.cursor()
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    cur.execute("SELECT id FROM users WHERE username = %s AND password_hash = %s", (username, password_hash))
    user = cur.fetchone()
    cur.close()
    conn.close()
    return user is not None 