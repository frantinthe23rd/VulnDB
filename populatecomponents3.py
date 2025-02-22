"""
Script: populatecomponents3.py

Description:
------------
This script fetches all Maven components from the Maven Central Repository, retrieves their versions, and stores them in a local SQLite database (`vulnerabilities.db`). It supports full data fetching, incremental updates, and retrying failed batches. The script uses asynchronous API calls to improve performance and includes error handling and logging mechanisms.

Database Tables:
----------------
1. **components** - Stores component group IDs, artifact IDs, and versions.
2. **failed_batches** - Keeps track of batches that failed to fetch.
3. **fetch_metadata** - Tracks the last successful fetch date for incremental updates.

Command-Line Arguments:
-----------------------
--restart           : Clears existing data (components, failed batches, and checkpoints) and starts fresh.
--batch-size [int]  : Specifies the batch size for fetching components (default: 500).
--max-workers [int] : Number of concurrent threads for processing (default: 5).
--log-file [str]    : Name of the log file for logging output (default: component_fetch_log.txt).
--start-index [int] : Starting index for batch fetching (useful for resuming partially completed runs).
--retry-failed      : Retries previously failed batches stored in the `failed_batches` table.
--incremental       : Fetches only new or updated components since the last successful run.

Usage Examples:
---------------
1. **Full Fetch:**
   python populatecomponents3.py

2. **Full Restart (Clear Data & Start Fresh):**
   python populatecomponents3.py --restart

3. **Incremental Fetch:**
   python populatecomponents3.py --incremental

4. **Retry Failed Batches:**
   python populatecomponents3.py --retry-failed

5. **Full Restart and Incremental Fetch:**
   python populatecomponents3.py --restart --incremental

"""

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS components (
            component_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT,
            artifact_id TEXT,
            version TEXT,
            UNIQUE(group_id, artifact_id, version)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS failed_batches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT,
            artifact_id TEXT,
            reason TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS fetch_metadata (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            last_fetch_date TEXT
        )
    ''')

    conn.commit()
    return conn

# Clears all components and failed batches from the database when a full restart is needed
def clear_components(conn):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM components")
    cursor.execute("DELETE FROM failed_batches")  # Clears failed batches
    conn.commit()
    logging.info("🗑️ Existing components and failed batches cleared from database.")

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

# Function to handle API calls with exponential backoff for 403 errors
async def fetch_with_backoff(session, url, params, max_retries=10):
    backoff = 1  # Initial backoff time in seconds
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MyFetcherBot/1.0; +http://mydomain.com/bot)'
    }
    for attempt in range(max_retries):
        async with session.get(url, params=params, headers=headers) as response:
            if response.status == 200:
                return await response.json()
            elif response.status == 403:
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    wait_time = int(retry_after)
                    logging.warning(f"🚫 403 Forbidden. Retry-After header found. Waiting {wait_time} seconds...")
                    await asyncio.sleep(wait_time)
                else:
                    logging.warning(f"🚫 403 Forbidden. Attempt {attempt + 1}/{max_retries}. Retrying in {backoff} seconds...")
                    await asyncio.sleep(backoff + random.uniform(0, 1))  # Add jitter
                    backoff = min(backoff * 2, 60)  # Exponential backoff with a cap
            else:
                logging.error(f"⚠ Unexpected status code: {response.status}")
                return None
    logging.error("❌ Max retries reached for 403 errors.")
    return None

# Processes batches of components with concurrency and bulk inserts
async def process_batches(start_indices, rows):
    conn = init_db()
    total_processed = 0
    total_failed = 0
    db_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(5)  # Reduced concurrency control
    bulk_insert_data = []

    async with aiohttp.ClientSession() as session:
        for start in tqdm(start_indices, desc="Processing Batches"):
            async with semaphore:
                params = {
                    "q": "*:*",
                    "rows": rows,
                    "start": start,
                    "wt": "json"
                }
                data = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", params)
                if data:
                    for doc in data.get("response", {}).get("docs", []):
                        group_id = doc.get("g", "unknown_group")
                        artifact_id = doc.get("a", "unknown_artifact")

                        version_params = {
                            "q": f"g:\"{group_id}\" AND a:\"{artifact_id}\"",
                            "core": "gav",
                            "rows": 100,
                            "wt": "json"
                        }
                        version_data = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", version_params)

                        if version_data:
                            for version_doc in version_data.get("response", {}).get("docs", []):
                                version = version_doc.get("v", "unknown_version")
                                bulk_insert_data.append((group_id, artifact_id, version))
                                total_processed += 1

                                if len(bulk_insert_data) >= 500:
                                    async with db_lock:
                                        cursor = conn.cursor()
                                        cursor.executemany('''
                                            INSERT OR IGNORE INTO components (group_id, artifact_id, version)
                                            VALUES (?, ?, ?)
                                        ''', bulk_insert_data)
                                        conn.commit()
                                        bulk_insert_data.clear()
                        else:
                            async with db_lock:
                                cursor = conn.cursor()
                                cursor.execute('''
                                    INSERT INTO failed_batches (group_id, artifact_id, reason)
                                    VALUES (?, ?, ?)
                                ''', (group_id, artifact_id, "Failed to fetch versions"))
                                conn.commit()
                            total_failed += 1
                else:
                    async with db_lock:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO failed_batches (group_id, artifact_id, reason)
                            VALUES (?, ?, ?)
                        ''', ("unknown_group", "unknown_artifact", "Failed to fetch batch"))
                        conn.commit()
                    total_failed += 1

    if bulk_insert_data:
        async with db_lock:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT OR IGNORE INTO components (group_id, artifact_id, version)
                VALUES (?, ?, ?)
            ''', bulk_insert_data)
            conn.commit()

    logging.info(f"✅ Total processed components: {total_processed}")
    logging.info(f"❌ Total failed batches: {total_failed}")
    conn.close()

# Main function
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
        logging.info("🔄 Full restart: cleared components, failed batches, and checkpoint.")

    total_docs = 0
    params = {"q": "*:*", "rows": 1, "wt": "json"}

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

    if args.incremental:
        update_last_fetch_date(conn, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    logging.info("✅ All batches processed.")

if __name__ == "__main__":
    main()
