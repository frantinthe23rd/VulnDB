import sqlite3
import requests
import json
import time
import logging
import argparse
import concurrent.futures
import os
import random
import asyncio
import aiohttp
import urllib.parse
from tqdm import tqdm

# Utility function to format seconds into DD:HH:MM:SS
def format_duration(seconds):
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{int(days):02d}:{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

# Sets up logging to both console and file for real-time monitoring and logs
def setup_logging(log_file="component_fetch_log.txt"):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

# Initializes SQLite Database and ensures required tables exist
def init_db():
    conn = sqlite3.connect("vulnerabilities.db", check_same_thread=False)
    cursor = conn.cursor()

    # Table for storing components and their versions
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS components (
            component_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT,
            artifact_id TEXT,
            version TEXT,
            UNIQUE(group_id, artifact_id, version)
        )
    ''')

    # Table for tracking failed batch fetches
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT,
            artifact_id TEXT,
            reason TEXT
        )
    ''')

    # Table for tracking last successful fetch for incremental updates
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fetch_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            last_fetch_date TEXT
        )
    ''')

    conn.commit()
    return conn

# Clears all components from the database when a full restart is needed
def clear_components(conn):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM components")
    conn.commit()
    logging.info("🗑️ Existing components cleared from database.")

# Clears the checkpoint file used for incremental fetching
def clear_checkpoint():
    checkpoint_file = "checkpoint_components.json"
    if os.path.exists(checkpoint_file):
        os.remove(checkpoint_file)
        logging.info("🗑️ Checkpoint file cleared.")

# Retrieves the last fetch date for incremental updates
def get_last_fetch_date(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT last_fetch_date FROM fetch_metadata ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    return row[0] if row else None

# Updates the last fetch date after a successful run
def update_last_fetch_date(conn, last_fetch_date):
    cursor = conn.cursor()
    cursor.execute("INSERT INTO fetch_metadata (last_fetch_date) VALUES (?)", (last_fetch_date,))
    conn.commit()

# Processes batches of components from Maven Central
async def process_batches(start_indices, rows):
    conn = init_db()
    total_processed = 0
    total_failed = 0
    async with aiohttp.ClientSession() as session:
        for start in tqdm(start_indices, desc="Processing Batches"):
            params = {
                "q": "*:*",
                "rows": rows,
                "start": start,
                "wt": "json"
            }
            try:
                async with session.get("https://search.maven.org/solrsearch/select", params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        for doc in data.get("response", {}).get("docs", []):
                            group_id = doc.get("g", "unknown_group")
                            artifact_id = doc.get("a", "unknown_artifact")
                            version = doc.get("v", "unknown_version")

                            cursor = conn.cursor()
                            cursor.execute('''
                                INSERT OR IGNORE INTO components (group_id, artifact_id, version) VALUES (?, ?, ?)
                            ''', (group_id, artifact_id, version))
                            total_processed += 1
                            conn.commit()
                    else:
                        logging.warning(f"⚠ Failed to fetch batch starting at {start}: HTTP {response.status}")
                        total_failed += 1
            except Exception as e:
                logging.error(f"🚨 Exception during batch processing at start {start}: {e}")
                total_failed += 1

    logging.info(f"✅ Total processed components: {total_processed}")
    logging.info(f"❌ Total failed batches: {total_failed}")
    conn.close()

# Retries failed components from previous runs
def retry_failed_components(conn, session):
    cursor = conn.cursor()
    cursor.execute("SELECT group_id, artifact_id FROM failed_batches")
    failed_components = cursor.fetchall()

    for group_id, artifact_id in failed_components:
        params = {
            "q": f"g:\"{group_id}\" AND a:\"{artifact_id}\"",
            "wt": "json"
        }
        try:
            response = requests.get("https://search.maven.org/solrsearch/select", params=params)
            if response.status_code == 200:
                data = response.json()
                for doc in data.get("response", {}).get("docs", []):
                    version = doc.get("v", "unknown_version")
                    cursor.execute('''
                        INSERT OR IGNORE INTO components (group_id, artifact_id, version) VALUES (?, ?, ?)
                    ''', (group_id, artifact_id, version))
                    conn.commit()
                cursor.execute("DELETE FROM failed_batches WHERE group_id = ? AND artifact_id = ?", (group_id, artifact_id))
                conn.commit()
            else:
                logging.error(f"⚠ Failed to retry component {group_id}/{artifact_id}: HTTP {response.status_code}")
        except Exception as e:
            logging.error(f"🚨 Exception during retry for {group_id}/{artifact_id}: {e}")

# Main entry point for fetching all Maven components
def main():
    parser = argparse.ArgumentParser(description="Fetch all Maven components using Maven Central API.")
    parser.add_argument("--restart", action="store_true", help="Restart from beginning and clear components.")
    parser.add_argument("--batch-size", type=int, default=500, help="Specify batch size for component fetching.")
    parser.add_argument("--max-workers", type=int, default=5, help="Specify the number of concurrent threads.")
    parser.add_argument("--log-file", type=str, default="component_fetch_log.txt", help="Specify log file name.")
    parser.add_argument("--start-index", type=int, default=0, help="Specify the starting index for batch fetching.")
    parser.add_argument("--retry-failed", action="store_true", help="Retry previously failed batches.")
    parser.add_argument("--incremental", action="store_true", help="Fetch only new or updated components.")
    args = parser.parse_args()

    setup_logging(args.log_file)

    conn = init_db()

    if args.restart:
        clear_components(conn)
        clear_checkpoint()
        logging.info("🔄 Full restart: cleared components and checkpoint.")

    if args.retry_failed:
        with aiohttp.ClientSession() as session:
            retry_failed_components(conn, session)
        logging.info("🔄 Retried failed components.")

    # Get last fetch date for incremental updates
    last_fetch_date = get_last_fetch_date(conn) if args.incremental else None

    total_docs = 0
    params = {"q": "*:*", "rows": 1, "wt": "json"}
    if last_fetch_date:
        params["fq"] = f"timestamp:[{last_fetch_date} TO NOW]"

    initial_response = requests.get("https://search.maven.org/solrsearch/select", params=params)
    if initial_response.status_code == 200:
        total_docs = initial_response.json().get("response", {}).get("numFound", 0)
    else:
        logging.error("⚠ Failed to get total number of components.")
        return

    logging.info(f"📊 Total components to fetch: {total_docs}")

    rows = args.batch_size
    start_indices = list(range(args.start_index, total_docs, rows))

    asyncio.run(process_batches(start_indices, rows))

    # Update last fetch date after successful run
    if args.incremental:
        update_last_fetch_date(conn, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    logging.info("✅ All batches processed.")

if __name__ == "__main__":
    main()

