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
   python.populatecomponents3.py --restart

3. **Incremental Fetch:**
   python.populatecomponents3.py --incremental

4. **Retry Failed Batches:**
   python.populatecomponents3.py --retry-failed

5. **Full Restart and Incremental Fetch:**
   python.populatecomponents3.py --restart --incremental

"""

import sqlite3
import requests
from typing import Optional
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

# Function to handle API calls with exponential backoff
async def fetch_with_backoff(session: aiohttp.ClientSession, url: str, params: dict, max_retries: int = 10) -> Optional[dict]:
    backoff = 1  # Initial backoff time in seconds
    headers = {
        'User-Agent': 'Mozilla/5.0 (compatible; MyMavenCentralFetcher/1.0; +http://mydomain.com/bot)'
    }
    for attempt in range(max_retries):
        try:
            async with session.get(url, params=params, headers=headers) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status in [403, 429]:
                    # Handle rate-limiting or forbidden responses with backoff
                    retry_after = response.headers.get('Retry-After', 30)  # Default to 30 seconds if missing
                    logging.warning(f"🚫 {response.status} Error. Retrying in {retry_after} seconds...")
                    await asyncio.sleep(int(retry_after))
                    backoff = min(backoff * 2, 60)  # Exponential backoff with a cap
                else:
                    logging.error(f"⚠ Unexpected status code: {response.status}")
                    await asyncio.sleep(backoff)
                    backoff = min(backoff * 2, 60)  # Exponential backoff with a cap
        except aiohttp.ClientError as e:
            logging.error(f"⚠ Network error: {e}")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 60)  # Exponential backoff with a cap
    logging.error("❌ Max retries reached for API errors.")
    return None

# Fetch all versions for a given group_id and artifact_id
# CHANGED: Limit attempts if repeated None returns, to avoid infinite loops
async def fetch_all_versions(session, group_id, artifact_id):
    versions = []
    version_params = {
        "q": f"g:\"{group_id}\" AND a:\"{artifact_id}\"",
        "core": "gav",
        "rows": 100,
        "wt": "json"
    }
    total_versions = 0
    start = 0
    max_version_retries = 3  # NEW: We'll allow a few attempts if we keep getting None

    attempts = 0
    while True:
        version_params["start"] = start
        version_data = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", version_params)

        if version_data:
            attempts = 0  # Reset attempts since we got a valid response
            response_info = version_data.get("response", {})
            total_versions = response_info.get("numFound", 0)

            # If there's no `response.docs`, we likely got an empty list
            docs = response_info.get("docs", [])
            versions.extend(docs)
            start += 100
            # If we've fetched all versions, break
            if start >= total_versions:
                break
        else:
            # version_data is None; increment attempt
            attempts += 1
            logging.warning(f"⚠ Failed to fetch versions for {group_id}:{artifact_id} (attempt {attempts}).")
            if attempts >= max_version_retries:
                # Break out to avoid infinite loop
                logging.error(f"❌ Aborting version fetch for {group_id}:{artifact_id} after {attempts} failed attempts.")
                return None
            await asyncio.sleep(5)  # small delay, then try again

    return versions

# Fetch components updated since the last fetch date
async def fetch_updated_components(session, last_fetch_date, start, rows):
    params = {
        "q": f"timestamp:[{last_fetch_date} TO NOW]",
        "rows": rows,
        "start": start,
        "wt": "json"
    }
    return await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", params)

# Save the checkpoint to a file
def save_checkpoint(index):
    checkpoint_file = "checkpoint_components.json"
    with open(checkpoint_file, "w") as f:
        json.dump({"last_index": index}, f)

# Load the checkpoint from a file
def load_checkpoint():
    checkpoint_file = "checkpoint_components.json"
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r") as f:
            data = json.load(f)
            return data.get("last_index", 0)
    return 0

# Fetch failed batches from the database
def fetch_failed_batches(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT group_id, artifact_id FROM failed_batches")
    return cursor.fetchall()

# Processes batches of components with concurrency and bulk inserts, with pagination for versions
# CHANGED: Added a retry mechanism for entire batch fetch if data comes back None.
async def process_batches(start_indices, rows, last_fetch_date=None):
    """
    This function fetches components in pages determined by start_indices.
    For each component, it also fetches all versions by paging in increments of 100.
    """
    conn = init_db()
    total_processed = 0
    total_failed = 0
    db_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(5)  # Concurrency control
    bulk_insert_data = []
    MAX_BATCH_FETCH_RETRIES = 3  # NEW: We'll attempt each batch multiple times

    async with aiohttp.ClientSession() as session:
        for start in tqdm(start_indices, desc="Processing Batches"):
            batch_data = None
            for attempt_num in range(MAX_BATCH_FETCH_RETRIES):
                async with semaphore:
                    # EITHER we fetch updated components OR all components
                    if last_fetch_date:
                        data = await fetch_updated_components(session, last_fetch_date, start, rows)
                    else:
                        params = {
                            "q": "*:*",
                            "rows": rows,
                            "start": start,
                            "wt": "json"
                        }
                        data = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", params)

                if data:
                    batch_data = data
                    break  # successful fetch
                else:
                    logging.warning(f"⚠ Failed to fetch batch (start={start}). Attempt {attempt_num+1}/{MAX_BATCH_FETCH_RETRIES}")
                    await asyncio.sleep(5)

            # If after multiple attempts we still have no data for this batch, mark as failed
            if batch_data is None:
                logging.error(f"❌ Entire batch starting at {start} failed after {MAX_BATCH_FETCH_RETRIES} attempts.")
                async with db_lock:
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO failed_batches (group_id, artifact_id, reason)
                        VALUES (?, ?, ?)
                    ''', ("unknown_batch", f"batch_start_{start}", "Failed entire batch fetch"))
                    conn.commit()
                total_failed += 1
                # save checkpoint so we can resume later
                save_checkpoint(start)
                continue

            # process the docs in the batch
            docs = batch_data.get("response", {}).get("docs", [])
            for doc in docs:
                group_id = doc.get("g", "unknown_group")
                artifact_id = doc.get("a", "unknown_artifact")

                # Fetch all versions for this artifact
                versions = await fetch_all_versions(session, group_id, artifact_id)
                if versions:
                    for version_doc in versions:
                        version = version_doc.get("v", "unknown_version")
                        bulk_insert_data.append((group_id, artifact_id, version))
                        total_processed += 1

                        # Insert data in chunks of 500
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
                    # versions == None => repeated failures for that artifact
                    async with db_lock:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT INTO failed_batches (group_id, artifact_id, reason)
                            VALUES (?, ?, ?)
                        ''', (group_id, artifact_id, "Failed to fetch versions"))
                        conn.commit()
                    total_failed += 1

            # -----------------------------------------------------
            # Save checkpoint after processing each batch
            # -----------------------------------------------------
            save_checkpoint(start)
            logging.info(f"Checkpoint saved. Last processed batch starting at index {start}.")

    # Final flush of any remaining data
    if bulk_insert_data:
        async with db_lock:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT OR IGNORE INTO components (group_id, artifact_id, version)
                VALUES (?, ?, ?)
            ''', bulk_insert_data)
            conn.commit()

    logging.info(f"✅ Total processed components: {total_processed}")
    logging.info(f"❌ Total failed batches/artifacts: {total_failed}")
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Fetch all Maven components using Maven Central API.")
    parser.add_argument("--restart", action="store_true", help="Restart from beginning and clear components.")
    parser.add_argument("--batch-size", type=int, default=500, help="Specify batch size for component fetching.")
    parser.add_argument("--max-workers", type=int, default=5, help="Specify the number of concurrent threads.")
    parser.add_argument("--log-file", type=str, default="component_fetch_log.txt", help="Specify log file name.")
    parser.add_argument("--start-index", type=int, default=None, help="Specify the starting index for batch fetching.")
    parser.add_argument("--retry-failed", action="store_true", help="Retry previously failed batches.")
    parser.add_argument("--incremental", action="store_true", help="Fetch only new or updated components.")
    args = parser.parse_args()

    setup_logging(args.log_file)
    conn = init_db()

    if args.restart:
        clear_components(conn)
        clear_checkpoint()
        logging.info("🔄 Full restart: cleared components, failed batches, and checkpoint.")

    last_fetch_date = None
    total_docs = 0

    # If incremental mode is specified, only fetch components updated after last_fetch_date
    if args.incremental:
        last_fetch_date = get_last_fetch_date(conn)
        if not last_fetch_date:
            logging.error("⚠ No last fetch date found for incremental fetch. Exiting.")
            return
        
        # For incremental fetch, only fetch the count of updated components
        inc_params = {
            "q": f"timestamp:[{last_fetch_date} TO NOW]",
            "rows": 1,
            "wt": "json"
        }
        inc_resp = requests.get("https://search.maven.org/solrsearch/select", params=inc_params)
        if inc_resp.status_code == 200:
            total_docs = inc_resp.json().get("response", {}).get("numFound", 0)
            logging.info(f"📊 Found {total_docs} new/updated components since {last_fetch_date}.")
        else:
            logging.error("⚠ Failed to get total number of updated components.")
            return
    else:
        # Full fetch: get total number of components
        params = {"q": "*:*", "rows": 1, "wt": "json"}
        initial_response = requests.get("https://search.maven.org/solrsearch/select", params=params)
        if initial_response.status_code == 200:
            total_docs = initial_response.json().get("response", {}).get("numFound", 0)
            logging.info(f"📊 Total components to fetch: {total_docs}")
        else:
            logging.error("⚠ Failed to get total number of components.")
            return

    # Retry any previously failed batches
    if args.retry_failed:
        failed_batches = fetch_failed_batches(conn)
        if not failed_batches:
            logging.info("✅ No failed batches to retry. Exiting.")
            return
        # Here you would implement logic to re-fetch just those group_id/artifact_id combos.
        # This example only logs them:
        for gb in failed_batches:
            logging.info(f"Will retry {gb[0]}:{gb[1]} in a future iteration.")
        return

    # If there are no docs to process (e.g., incremental found 0 new), exit.
    if total_docs == 0:
        logging.info("✅ No new or updated components to process. Exiting.")
        return

    rows = args.batch_size
    # If user supplied a --start-index, use that; otherwise load from the checkpoint
    start_index = args.start_index if args.start_index is not None else load_checkpoint()
    start_indices = list(range(start_index, total_docs, rows))

    # Process the batches
    asyncio.run(process_batches(start_indices, rows, last_fetch_date))

    # If we did an incremental fetch, update the last fetch date
    if args.incremental:
        # NEW: Use a small buffer so we don't miss anything that might appear at the boundary
        time_buffer_seconds = 60  # 1 minute buffer
        new_fetch_date = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - time_buffer_seconds)
        )
        update_last_fetch_date(conn, new_fetch_date)
        logging.info(f"Incremental mode: updated last fetch date to {new_fetch_date} (with {time_buffer_seconds}s buffer).")

    logging.info("✅ All batches processed.")
    conn.close()

if __name__ == "__main__":
    main()
