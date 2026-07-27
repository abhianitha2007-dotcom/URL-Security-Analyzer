import sqlite3
from datetime import datetime


DATABASE = "database/scans.db"



def create_database():

    conn = sqlite3.connect(DATABASE)

    cursor = conn.cursor()


    cursor.execute("""
    
    CREATE TABLE IF NOT EXISTS scans(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        url TEXT,

        risk_score INTEGER,

        verdict TEXT,

        scan_date TEXT

    )

    """)


    conn.commit()

    conn.close()




def save_scan(url, risk_score, verdict):

    conn = sqlite3.connect(DATABASE)

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




def get_all_scans():

    conn = sqlite3.connect(DATABASE)

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