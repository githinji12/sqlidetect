# db_init.py
import sqlite3

conn = sqlite3.connect('scan_logs.db')  # This will create the file in the current directory
c = conn.cursor()

c.execute('''
    CREATE TABLE IF NOT EXISTS scan_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT NOT NULL,
        method TEXT,
        payload TEXT,
        result TEXT,
        timestamp TEXT
    )
''')

conn.commit()
conn.close()
print("✅ Database initialized as 'scan_logs.db'")
