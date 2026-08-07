import os
import sqlite3

from datetime import datetime, timedelta


# =========================================================
# DATABASE CONFIGURATION
# =========================================================

DATABASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE = os.path.join(
    DATABASE_DIR,
    "scans.db"
)


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():
    """
    Create and return a SQLite database connection.
    """

    os.makedirs(
        DATABASE_DIR,
        exist_ok=True
    )

    conn = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    return conn


# =========================================================
# CREATE / MIGRATE DATABASE
# =========================================================

def create_database():
    """
    Create the scans table.

    Older databases are automatically migrated by
    adding the session_id column if it does not exist.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                url TEXT NOT NULL,

                risk_score INTEGER NOT NULL,

                verdict TEXT NOT NULL,

                scan_date TEXT NOT NULL,

                session_id TEXT
            )
            """
        )

        cursor.execute(
            """
            PRAGMA table_info(scans)
            """
        )

        columns = [
            row[1]
            for row in cursor.fetchall()
        ]

        if "session_id" not in columns:

            cursor.execute(
                """
                ALTER TABLE scans
                ADD COLUMN session_id TEXT
                """
            )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_scans_session_id
            ON scans(session_id)
            """
        )

        conn.commit()

    finally:

        conn.close()


# =========================================================
# SAVE SCAN
# =========================================================

def save_scan(
    url,
    risk_score,
    verdict,
    session_id
):
    """
    Save a URL scan for one anonymous browser session.

    Accidental duplicate submissions are ignored when the
    same browser saves the same URL, risk score and verdict
    within two minutes.

    Returns:
        True  -> scan was inserted
        False -> duplicate scan was ignored
    """

    conn = get_connection()

    try:

        # BEGIN IMMEDIATE prevents two simultaneous requests
        # from both inserting the same scan before either one
        # can see the other's database row.
        conn.execute(
            "BEGIN IMMEDIATE"
        )

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                url,
                risk_score,
                verdict,
                scan_date

            FROM scans

            WHERE session_id = ?

            ORDER BY id DESC

            LIMIT 1
            """,
            (
                session_id,
            )
        )

        previous_scan = cursor.fetchone()

        now = datetime.now()

        if previous_scan:

            (
                previous_url,
                previous_risk,
                previous_verdict,
                previous_scan_date
            ) = previous_scan

            try:

                previous_time = datetime.strptime(
                    previous_scan_date,
                    "%d-%m-%Y %H:%M:%S"
                )

            except (
                TypeError,
                ValueError
            ):

                previous_time = None

            same_scan = (
                previous_url == url
                and int(previous_risk) == int(risk_score)
                and previous_verdict == verdict
            )

            recent_scan = (
                previous_time is not None
                and (
                    now - previous_time
                ) <= timedelta(minutes=2)
            )

            if (
                same_scan
                and recent_scan
            ):

                conn.rollback()

                return False

        scan_date = now.strftime(
            "%d-%m-%Y %H:%M:%S"
        )

        cursor.execute(
            """
            INSERT INTO scans
            (
                url,
                risk_score,
                verdict,
                scan_date,
                session_id
            )

            VALUES (?, ?, ?, ?, ?)
            """,
            (
                url,
                risk_score,
                verdict,
                scan_date,
                session_id
            )
        )

        conn.commit()

        return True

    except Exception:

        conn.rollback()

        raise

    finally:

        conn.close()


# =========================================================
# GET PRIVATE SCAN HISTORY
# =========================================================

def get_all_scans(
    session_id
):
    """
    Return scans belonging only to the supplied session.

    Only the original five columns are returned so the
    existing history.html continues working unchanged.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                url,
                risk_score,
                verdict,
                scan_date

            FROM scans

            WHERE session_id = ?

            ORDER BY id DESC
            """,
            (
                session_id,
            )
        )

        return cursor.fetchall()

    finally:

        conn.close()


# =========================================================
# GET SCAN BY ID
# =========================================================

def get_scan_by_id(
    scan_id,
    session_id
):
    """
    Return a scan only when it belongs to the current
    anonymous browser session.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT
                id,
                url,
                risk_score,
                verdict,
                scan_date

            FROM scans

            WHERE id = ?
            AND session_id = ?
            """,
            (
                scan_id,
                session_id
            )
        )

        return cursor.fetchone()

    finally:

        conn.close()


# =========================================================
# DELETE ONE SCAN
# =========================================================

def delete_scan(
    scan_id,
    session_id
):
    """
    Delete a scan only if it belongs to the supplied
    anonymous browser session.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM scans

            WHERE id = ?
            AND session_id = ?
            """,
            (
                scan_id,
                session_id
            )
        )

        conn.commit()

    finally:

        conn.close()


# =========================================================
# CLEAR PRIVATE HISTORY
# =========================================================

def clear_history(
    session_id
):
    """
    Delete only scans belonging to the supplied session.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM scans

            WHERE session_id = ?
            """,
            (
                session_id,
            )
        )

        conn.commit()

    finally:

        conn.close()


# =========================================================
# TOTAL SCANS
# =========================================================

def get_total_scans(
    session_id
):
    """
    Return total number of scans belonging to a session.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT COUNT(*)

            FROM scans

            WHERE session_id = ?
            """,
            (
                session_id,
            )
        )

        return cursor.fetchone()[0]

    finally:

        conn.close()


# =========================================================
# AVERAGE RISK
# =========================================================

def get_average_risk(
    session_id
):
    """
    Return average risk score for a session.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT AVG(risk_score)

            FROM scans

            WHERE session_id = ?
            """,
            (
                session_id,
            )
        )

        average = cursor.fetchone()[0]

        if average is None:
            return 0

        return round(
            average,
            2
        )

    finally:

        conn.close()


# =========================================================
# HIGHEST RISK
# =========================================================

def get_highest_risk(
    session_id
):
    """
    Return highest risk score for a session.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT MAX(risk_score)

            FROM scans

            WHERE session_id = ?
            """,
            (
                session_id,
            )
        )

        highest = cursor.fetchone()[0]

        if highest is None:
            return 0

        return highest

    finally:

        conn.close()


# =========================================================
# LOWEST RISK
# =========================================================

def get_lowest_risk(
    session_id
):
    """
    Return lowest risk score for a session.
    """

    conn = get_connection()

    try:

        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT MIN(risk_score)

            FROM scans

            WHERE session_id = ?
            """,
            (
                session_id,
            )
        )

        lowest = cursor.fetchone()[0]

        if lowest is None:
            return 0

        return lowest

    finally:

        conn.close()