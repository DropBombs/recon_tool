import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), '../data/scans.db')

def init_db():
	"""Initializes database and creates the audit table."""
	os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
	with sqlite3.connect(DB_PATH) as conn:
		cursor = conn.cursor()
		cursor.execute('''
			CREATE TABLE IF NOT EXISTS network_scans (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				target TEXT NOT NULL,
				timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
				status TEXT NOT NULL,
				log_output TEXT
			)
		''')
		conn.commit()


def log_scan_result(target, status, log_output):
	"""Persists the recon results with SQLite."""
	with sqlite3.connect(DB_PATH) as conn:
		cursor = conn.cursor()
		cursor.execute(
			"INSERT INTO network_scans (target, status, log_output) VALUES (?, ?, ?)",
			(target, status, log_output)
		)
		conn.commit()


