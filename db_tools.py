"""
db_tools.py
Database utilities for authentication, metrics collection, and query execution.
"""

import os
import json
import psycopg2
import pyodbc

# ---------------------------------------------------------------------
# Config + Secrets Loaders
# ---------------------------------------------------------------------
def load_config():
    """Load config.json from data/"""
    path = os.path.join("data", "config.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)["databases"]

def load_secrets():
    """Load secrets.json from data/"""
    path = os.path.join("data", "secrets.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def load_secret(db_name):
    """Return password for db_name from secrets.json"""
    secrets = load_secrets()
    return secrets.get(db_name, {}).get("password")

# ---------------------------------------------------------------------
# DB Connection
# ---------------------------------------------------------------------
def get_db_conn(db_cfg, password=None):
    """
    Open DB connection based on db_cfg.
    Supports postgres and sqlserver.
    """
    db_type = db_cfg.get("type")
    db_name = db_cfg.get("db_name")
    if password is None:
        password = load_secret(db_name)

    if db_type == "postgres":
        return psycopg2.connect(
            user=db_cfg.get("user", "postgres"),
            password=password,
            dbname=db_name,
            host=db_cfg.get("host", "localhost"),
            port=db_cfg.get("port", "5432")
        )
    elif db_type == "sqlserver":
        conn_str = (
            f"DRIVER={{ODBC Driver 17 for SQL Server}};"
            f"SERVER={db_cfg['server']};"
            f"DATABASE={db_name};"
            f"UID={db_cfg['user']};"
            f"PWD={password}"
        )
        return pyodbc.connect(conn_str)
    else:
        raise ValueError(f"Unsupported DB type: {db_type}")

# ---------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------
def login(username, password):
    """Simple login check against secrets.json (demo)."""
    secrets = load_secrets()
    for db, creds in secrets.items():
        if creds.get("username") == username and creds.get("password") == password:
            return True
    return False

def test_connection(db_cfg, password):
    """Try connecting once, return True/False."""
    try:
        conn = get_db_conn(db_cfg, password)
        conn.close()
        return True
    except Exception as e:
        print(f"Connection failed: {e}")
        return False

# ---------------------------------------------------------------------
# Run Queries
# ---------------------------------------------------------------------
def run_sample_query(db_cfg, limit=5):
    """Run SELECT query and return rows (list)."""
    conn = get_db_conn(db_cfg)
    cursor = conn.cursor()
    table = db_cfg.get("table")
    schema = db_cfg.get("schema")

    if db_cfg["type"] == "postgres":
        if schema and schema.lower() != 'public':
            # Use lowercase schema/table names quoted
            query = f'SELECT * FROM "{schema.lower()}"."{table.lower()}" LIMIT {limit};'
        else:
            query = f'SELECT * FROM "{table.lower()}" LIMIT {limit};'
    else:
        query = f"SELECT TOP {limit} * FROM {table};"

    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows


def execute_sample_query(db_cfg, password, limit=5):
    """Run SELECT with explicit password (used by agents)."""
    conn = get_db_conn(db_cfg, password)
    cursor = conn.cursor()
    table = db_cfg.get("table")

    if db_cfg["type"] == "postgres":
        query = f"SELECT * FROM {table} LIMIT {limit};"
    else:
        query = f"SELECT TOP {limit} * FROM {table};"

    cursor.execute(query)
    rows = cursor.fetchall()
    cursor.close()
    conn.close()
    return rows

# ---------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------
def save_log(text):
    """Append a line to execution_log.txt"""
    with open("execution_log.txt", "a", encoding="utf-8") as f:
        f.write(text + "\n")
