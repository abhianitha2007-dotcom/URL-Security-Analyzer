import sqlite3
import os

from datetime import datetime



# -------------------------
# Database Configuration
# -------------------------

DATABASE_DIR = "database"

DATABASE = os.path.join(
    DATABASE_DIR,
    "scans.db"
)



# -------------------------
# Database Connection
# -------------------------

def get_connection():

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    conn = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    return conn




# -------------------------
# Create Database
# -------------------------

def create_database():

    conn = get_connection()

    cursor = conn.cursor()


    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans(

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            url TEXT NOT NULL,

            risk_score INTEGER NOT NULL,

            verdict TEXT NOT NULL,

            scan_date TEXT NOT NULL

        )
        """
    )


    conn.commit()

    conn.close()




# -------------------------
# Save Scan
# -------------------------

def save_scan(
    url,
    risk_score,
    verdict
):

    conn = get_connection()

    cursor = conn.cursor()



    scan_date = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )



    cursor.execute(

        """
        INSERT INTO scans
        (
            url,
            risk_score,
            verdict,
            scan_date
        )

        VALUES (?,?,?,?)

        """,

        (
            url,
            risk_score,
            verdict,
            scan_date
        )

    )


    conn.commit()

    conn.close()




# -------------------------
# Get Scan History
# -------------------------

def get_all_scans():

    conn = get_connection()

    cursor = conn.cursor()



    cursor.execute(

        """
        SELECT *
        FROM scans
        ORDER BY id DESC
        """

    )



    scans = cursor.fetchall()


    conn.close()


    return scans