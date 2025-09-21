"""
workflow.py
Defines initial state setup and database configurations for monitoring runs.
"""

import json
import os

APP_NAME = "DBAutotuneApp"
USER_ID = "test_user"


def get_initial_state(username="admin", password="wrongpass"):
    """
    Return default starting state for a run.
    Includes login credentials, event metadata.
    """
    return {
        "username": username,
        "password": password,
        "eventid": "EVT_DB_1001",
        "userid": username,
        "problem": "DB login failed twice."
    }


def load_db_configs():
    """
    Load DB configs from data/config.json
    """
    path = os.path.join("data", "config.json")
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)["databases"]


# --- Configurations for databases (dynamic now) ---
DB_CONFIGS = load_db_configs()
