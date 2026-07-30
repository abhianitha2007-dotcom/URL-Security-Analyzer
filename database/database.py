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

# -------------------------
# Get Scan By ID
# -------------------------

def get_scan_by_id(scan_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,

        (scan_id,)

    )

    scan = cursor.fetchone()

    conn.close()

    return scan

# -------------------------
# Delete Scan
# -------------------------

def delete_scan(scan_id):

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        """
        DELETE FROM scans
        WHERE id = ?
        """,

        (scan_id,)

    )

    conn.commit()

    conn.close()

    # -------------------------
# Clear History
# -------------------------

def clear_history():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        """
        DELETE FROM scans
        """

    )

    conn.commit()

    conn.close()

    # -------------------------
# Total Scans
# -------------------------

def get_total_scans():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        """
        SELECT COUNT(*)
        FROM scans
        """

    )

    total = cursor.fetchone()[0]

    conn.close()

    return total

# -------------------------
# Average Risk Score
# -------------------------

def get_average_risk():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        """
        SELECT AVG(risk_score)
        FROM scans
        """

    )

    average = cursor.fetchone()[0]

    conn.close()

    if average is None:

        return 0

    return round(average, 2)

# -------------------------
# Highest Risk
# -------------------------

def get_highest_risk():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        """
        SELECT MAX(risk_score)
        FROM scans
        """

    )

    highest = cursor.fetchone()[0]

    conn.close()

    return highest if highest is not None else 0

# -------------------------
# Lowest Risk
# -------------------------

def get_lowest_risk():

    conn = get_connection()

    cursor = conn.cursor()

    cursor.execute(

        """
        SELECT MIN(risk_score)
        FROM scans
        """

    )

    lowest = cursor.fetchone()[0]

    conn.close()

    return lowest if lowest is not None else 0

