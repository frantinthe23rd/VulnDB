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
import os
import asyncio
import aiohttp
from tqdm import tqdm

# Define a global database lock for thread safety
db_lock = asyncio.Lock()

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS component_status (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT,
            artifact_id TEXT,
            status TEXT,
            UNIQUE(group_id, artifact_id)
        )
    ''')

    conn.commit()
    return conn

# Clears all components, failed batches, and component status from the database when a full restart is needed
def clear_components(conn):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM components")
    cursor.execute("DELETE FROM failed_batches")  # Clears failed batches
    cursor.execute("DELETE FROM component_status")  # Clears component status
    conn.commit()
    logging.info("🗑️ Existing components, failed batches, and component status cleared from database.")

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

# Fetches the status of a component
def fetch_component_status(conn, group_id, artifact_id):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT status FROM component_status
        WHERE group_id = ? AND artifact_id = ?
    ''', (group_id, artifact_id))
    row = cursor.fetchone()
    return row[0] if row else None

# Function to handle API calls with exponential backoff
async def fetch_with_backoff(session: aiohttp.ClientSession, url: str, params: dict, max_retries: int = 10) -> Optional[dict]:
    backoff = 1  # Initial backoff time in seconds
    for attempt in range(max_retries):
        try:
            async with session.get(url, params=params) as response:
                if (response.status == 200):
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
# Contains logic to handle repeated failures and avoid infinite loops
async def fetch_all_versions(session, group_id, artifact_id):
    versions = []
    version_params = {
        "q": f"g:\"{group_id}\" AND a:\"{artifact_id}\"",
        "core": "gav",
        "rows": 20,  # Set the batch size to 20
        "wt": "json"
    }
    total_versions = 0
    start = 0
    max_version_retries = 3

    attempts = 0
    while True:
        version_params["start"] = start
        version_data = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", version_params)

        if version_data:
            attempts = 0  # reset attempts
            response_info = version_data.get("response", {})
            total_versions = response_info.get("numFound", 0)
            docs = response_info.get("docs", [])
            versions.extend(docs)
            start += 20  # Move to the next batch
            if start >= total_versions:
                break
        else:
            attempts += 1
            if attempts >= max_version_retries:
                return None
            await asyncio.sleep(5)

        # Small delay to prevent rate limiting
        await asyncio.sleep(1)

    return versions

# Fetch components updated since the last fetch date
async def fetch_updated_components(session, last_fetch_date, start, rows):
    params = {
        "q": f"timestamp:[{last_fetch_date} TO NOW]",
        "rows": rows,
        "start": start,
        "wt": "json"
    }
    response = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", params)
    return response if response else {"response": {"docs": []}}

# Save and load checkpoint
async def save_checkpoint(index):
    checkpoint_file = "checkpoint_components.json"
    async with db_lock:
        with open(checkpoint_file, "w") as f:
            json.dump({"last_index": index}, f)

def load_checkpoint():
    checkpoint_file = "checkpoint_components.json"
    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r") as f:
            data = json.load(f)
            last_index = data.get("last_index", "")
            if isinstance(last_index, str):
                return last_index
            else:
                logging.warning(f"Invalid checkpoint value: {last_index}. Resetting to empty string.")
                return ""
    return ""

# Fetch failed batches from the database
def fetch_failed_batches(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT group_id, artifact_id FROM failed_batches")
    return cursor.fetchall()

# Fetch all components from Maven Central Repository
async def fetch_all_components(session, start, rows=20):
    """
    Fetches all Maven components with proper pagination and stores them in the component_status table as "unprocessed".
    Resumes from the last processed component if not restarting.
    """
    all_components = []
    conn = init_db()

    # Get the total count of components available
    params = {
        "q": "*:*",
        "rows": rows,
        "start": 0,
        "wt": "json"
    }
    response = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", params)

    if response and "response" in response:
        total_docs = response["response"].get("numFound", 0)
        logging.info(f"📊 Total components to fetch: {total_docs}")
    else:
        logging.error("⚠ Failed to get the total number of components.")
        return {"response": {"docs": []}}

    # Check the last processed component from the component_status table
    cursor = conn.cursor()
    if start:
        cursor.execute('''
            SELECT COUNT(*) FROM component_status WHERE group_id || ':' || artifact_id > ?
        ''', (start,))
    else:
        cursor.execute('''
            SELECT COUNT(*) FROM component_status
        ''')
    processed_count = cursor.fetchone()[0]
    start = processed_count if processed_count else 0

    # Loop through pages until we fetch everything
    while start < total_docs:
        params = {
            "q": "*:*",
            "rows": rows,
            "start": start,
            "wt": "json"
        }
        page_response = await fetch_with_backoff(session, "https://search.maven.org/solrsearch/select", params)

        if page_response and "response" in page_response:
            docs = page_response["response"].get("docs", [])
            logging.info(f"Fetched {len(docs)} components in this batch.")
            all_components.extend(docs)

            # Store components in the component_status table as "unprocessed"
            async with db_lock:
                cursor = conn.cursor()
                for doc in docs:
                    group_id = doc.get("g", "unknown_group")
                    artifact_id = doc.get("a", "unknown_artifact")
                    cursor.execute('''
                        INSERT OR REPLACE INTO component_status (group_id, artifact_id, status)
                        VALUES (?, ?, ?)
                    ''', (group_id, artifact_id, "unprocessed"))
                conn.commit()

            logging.info(f"✅ Fetched and inserted {len(docs)} components. Total fetched so far: {len(all_components)}")

        # Move to next batch
        start += rows
        logging.info(f"✅ Fetched {start}/{total_docs} components...")

        # Small delay to prevent rate limiting
        await asyncio.sleep(1)

    logging.info(f"✅ Finished fetching all {total_docs} components.")
    conn.close()
    return {"response": {"docs": all_components}}

async def process_batches(rows):
    conn = init_db()
    total_processed = 0
    total_failed = 0
    bulk_insert_data = []
    MAX_BATCH_FETCH_RETRIES = 3

    # We'll keep a concurrency limit for version fetches
    # so we don't overwhelm the server.
    version_fetch_semaphore = asyncio.Semaphore(3)

    async with aiohttp.ClientSession() as session:
        while True:
            # Fetch unprocessed components from the database
            docs = fetch_unprocessed_components(conn, rows)

            if not docs:
                break

            # -----------------------------------------------
            # 1) Build a list of tasks to fetch versions in parallel
            # -----------------------------------------------
            fetch_tasks = []
            for doc in docs:
                group_id, artifact_id = doc

                async def fetch_versions_for_artifact(gid, aid):
                    # Acquire semaphore to limit concurrency
                    async with version_fetch_semaphore:
                        versions = await fetch_all_versions(session, gid, aid)
                        return (gid, aid, versions)

                fetch_tasks.append(fetch_versions_for_artifact(group_id, artifact_id))

            # -----------------------------------------------
            # 2) Gather them concurrently with a progress bar
            # -----------------------------------------------
            with tqdm(total=len(fetch_tasks), desc=f"Fetching versions for {group_id}:{artifact_id}", leave=False, dynamic_ncols=True) as pbar:
                for future in asyncio.as_completed(fetch_tasks):
                    gid, aid, versions = await future
                    pbar.update(1)

                    # -----------------------------------------------
                    # 3) Process each fetch result
                    # -----------------------------------------------
                    if versions is None:
                        # Means repeated failures for that artifact
                        await record_failed_batch(conn, gid, aid, "Failed to fetch versions")
                        total_failed += 1
                        await update_component_status(conn, gid, aid, "failed")
                        continue

                    # If success, store them in our bulk insert buffer
                    for version_doc in versions:
                        version_str = version_doc.get("v", "unknown_version")
                        if isinstance(version_str, str):
                            bulk_insert_data.append((gid, aid, version_str))
                            total_processed += 1

                        # Insert in chunks
                        if len(bulk_insert_data) >= rows:
                            async with db_lock:
                                cursor = conn.cursor()
                                cursor.executemany('''
                                    INSERT OR IGNORE INTO components (group_id, artifact_id, version)
                                    VALUES (?, ?, ?)
                                ''', bulk_insert_data)
                                conn.commit()
                            bulk_insert_data.clear()

                    # Update component status to 'processed'
                    await update_component_status(conn, gid, aid, "processed")

            # Save checkpoint after processing each batch
            await save_checkpoint(docs[-1][0])

            # Show progress of component_status at the end of each batch
            processed_count, unprocessed_count = verify_component_count(conn)
            logging.info(f"📊 Processed components: {processed_count}, Unprocessed components: {unprocessed_count}")

    # Final flush of any remaining data
    if bulk_insert_data:
        async with db_lock:
            cursor = conn.cursor()
            cursor.executemany('''
                INSERT OR IGNORE INTO components (group_id, artifact_id, version)
                VALUES (?, ?, ?)
            ''', bulk_insert_data)
            conn.commit()

    conn.close()

# Update the following functions to use the db_lock
async def record_failed_batch(conn, group_id, artifact_id, reason):
    async with db_lock:  # Ensures only one operation modifies the DB at a time
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO failed_batches (group_id, artifact_id, reason)
            VALUES (?, ?, ?)
        ''', (group_id, artifact_id, reason))
        conn.commit()


async def update_component_status(conn, group_id, artifact_id, status):
    async with db_lock:
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO component_status (group_id, artifact_id, status)
            VALUES (?, ?, ?)
        ''', (group_id, artifact_id, status))
        conn.commit()

def fetch_unprocessed_components(conn, limit):
    cursor = conn.cursor()
    cursor.execute('''
        SELECT group_id, artifact_id FROM component_status
        WHERE status = 'unprocessed'
        LIMIT ?
    ''', (limit,))
    return cursor.fetchall()

def verify_component_count(conn):
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM component_status WHERE status = 'unprocessed'")
    unprocessed_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM component_status WHERE status = 'processed'")
    processed_count = cursor.fetchone()[0]
    logging.info(f"📊 Total components in component_status table: {processed_count + unprocessed_count}")
    logging.info(f"📊 Processed components: {processed_count}")
    logging.info(f"📊 Unprocessed components: {unprocessed_count}")
    return processed_count, unprocessed_count

async def async_main(args):
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
        if (initial_response.status_code == 200):
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
    if not isinstance(start_index, str):
        logging.error(f"Invalid start index: {start_index}. Resetting to empty string.")
        start_index = ""

    # Skip component population if the argument is provided
    if not args.skip_component_population:
        # Fetch all components and store them as unprocessed
        async with aiohttp.ClientSession() as session:
            await fetch_all_components(session, start_index, rows)

        # Verify the count of components in the component_status table
        verify_component_count(conn)

    # Process the batches (in an event loop)
    await process_batches(rows)

    # If we did an incremental fetch, update the last fetch date with a buffer
    if args.incremental:
        time_buffer_seconds = 60
        new_fetch_date = time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(time.time() - time_buffer_seconds)
        )
        update_last_fetch_date(conn, new_fetch_date)
        logging.info(f"Incremental mode: updated last fetch date to {new_fetch_date} (with {time_buffer_seconds}s buffer).")

    logging.info("✅ All batches processed.")
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="Fetch all Maven components using Maven Central API.")
    parser.add_argument("--restart", action="store_true", help="Restart from beginning and clear components.")
    parser.add_argument("--batch-size", type=int, default=20, help="Specify batch size for component fetching.")
    parser.add_argument("--max-workers", type=int, default=5, help="Specify the number of concurrent threads (currently not used for concurrency).")
    parser.add_argument("--log-file", type=str, default="component_fetch_log.txt", help="Specify log file name.")
    parser.add_argument("--start-index", type=int, default=None, help="Specify the starting index for batch fetching.")
    parser.add_argument("--retry-failed", action="store_true", help="Retry previously failed batches.")
    parser.add_argument("--incremental", action="store_true", help="Fetch only new or updated components.")
    parser.add_argument("--skip-component-population", action="store_true", help="Skip the component population and move directly to the version collection.")
    args = parser.parse_args()

    asyncio.run(async_main(args))

if __name__ == "__main__":
    main()
