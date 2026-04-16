import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'taskmanager.db')


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    conn = get_db()
    cursor = conn.cursor()

    cursor.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            pin_hash TEXT,
            profile_pic TEXT,
            role TEXT NOT NULL DEFAULT 'user',
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            assigned_to INTEGER,
            created_by INTEGER NOT NULL,
            group_id INTEGER,
            status TEXT NOT NULL DEFAULT 'pending',
            priority TEXT NOT NULL DEFAULT 'medium',
            accepted_at TIMESTAMP,
            started_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            completed_at TIMESTAMP,
            FOREIGN KEY (assigned_to) REFERENCES users(id),
            FOREIGN KEY (created_by) REFERENCES users(id),
            FOREIGN KEY (group_id) REFERENCES task_groups(id) ON DELETE SET NULL
        );

        CREATE TABLE IF NOT EXISTS task_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            color TEXT NOT NULL DEFAULT '#0d6efd',
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            ip_address TEXT,
            details TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS delivery_persons (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            mobile TEXT,
            iqama_id TEXT,
            vehicle_no TEXT,
            is_active INTEGER NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS deliveries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            delivery_note_number TEXT NOT NULL,
            description TEXT,
            customer_name TEXT NOT NULL,
            delivery_date DATE,
            delivery_person_id INTEGER,
            transportation_charge REAL DEFAULT 0,
            charge_paid INTEGER DEFAULT 0,
            paid_date DATE,
            paid_by TEXT,
            payment_method TEXT,
            narration TEXT,
            signed_note_status TEXT DEFAULT 'pending',
            created_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (delivery_person_id) REFERENCES delivery_persons(id),
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            message TEXT NOT NULL,
            type TEXT NOT NULL DEFAULT 'info',
            is_read INTEGER NOT NULL DEFAULT 0,
            link TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            message TEXT,
            attachment TEXT,
            is_read INTEGER NOT NULL DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id),
            FOREIGN KEY (receiver_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    ''')

    # Add phone column if missing (migration)
    try:
        conn.execute("SELECT phone FROM users LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE users ADD COLUMN phone TEXT")

    # Add group_id column if missing (migration)
    try:
        conn.execute("SELECT group_id FROM tasks LIMIT 1")
    except Exception:
        conn.execute("ALTER TABLE tasks ADD COLUMN group_id INTEGER REFERENCES task_groups(id) ON DELETE SET NULL")

    # Ensure settings table has defaults
    defaults = {
        'print_paper_size': 'A4',
        'print_orientation': 'portrait',
        'print_company_name': 'AIRSCENT ARABIA MANUFACTURING CO.',
        'print_show_logo': '1',
        'auto_backup': '1',
        'backup_interval_minutes': '30',
    }
    for k, v in defaults.items():
        conn.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

    conn.commit()
    conn.close()
