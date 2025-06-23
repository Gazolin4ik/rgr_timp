import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT

DB_NAME = "timp_rgr"
DB_USER = "postgres"
DB_PASSWORD = "123"
DB_HOST = "localhost"
DB_PORT = "5432"

def create_database():
    # Подключаемся к postgres, чтобы создать БД
    conn = psycopg2.connect(dbname='postgres', user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
    conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
    cur = conn.cursor()
    cur.execute(f"SELECT 1 FROM pg_database WHERE datname = '{DB_NAME}'")
    exists = cur.fetchone()
    if not exists:
        cur.execute(f"CREATE DATABASE {DB_NAME}")
        print(f"База данных {DB_NAME} создана.")
    else:
        print(f"База данных {DB_NAME} уже существует.")
    cur.close()
    conn.close()

def create_tables():
    conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(64) UNIQUE NOT NULL,
        password_hash VARCHAR(128) NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS access_points (
        id SERIAL PRIMARY KEY,
        ssid VARCHAR(64),
        bssid VARCHAR(17) NOT NULL,
        signal_strength INTEGER,
        channel INTEGER,
        encryption VARCHAR(32),
        is_open BOOLEAN,
        is_suspicious BOOLEAN,
        first_seen TIMESTAMP,
        last_seen TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS scan_logs (
        id SERIAL PRIMARY KEY,
        scan_time TIMESTAMP NOT NULL DEFAULT NOW(),
        total_found INTEGER,
        open_found INTEGER,
        suspicious_found INTEGER
    );
    CREATE TABLE IF NOT EXISTS ap_scan_rel (
        id SERIAL PRIMARY KEY,
        scan_id INTEGER REFERENCES scan_logs(id) ON DELETE CASCADE,
        ap_id INTEGER REFERENCES access_points(id) ON DELETE CASCADE
    );
    """)
    conn.commit()
    cur.close()
    conn.close()
    print("Все таблицы созданы (или уже существуют).")

def add_test_user():
    import hashlib
    conn = psycopg2.connect(dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT)
    cur = conn.cursor()
    username = 'admin'
    password = '123456'
    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    cur.execute("SELECT 1 FROM users WHERE username = %s", (username,))
    if not cur.fetchone():
        cur.execute("INSERT INTO users (username, password_hash) VALUES (%s, %s)", (username, password_hash))
        print(f"Пользователь {username} добавлен с паролем {password}")
    else:
        print(f"Пользователь {username} уже существует.")
    conn.commit()
    cur.close()
    conn.close()

if __name__ == '__main__':
    create_database()
    create_tables()
    add_test_user() 