"""
Script: sonatypetestAPIpart.py

Description:
------------
This script fetches vulnerability data for Maven components from the Sonatype OSS Index API and stores it in a local SQLite database (`vulnerabilities.db`). It supports full data fetching, clearing previous data, retrying failed batches, incremental updates to avoid duplicates, and includes mechanisms to handle API rate limits gracefully.

Features:
---------
- Asynchronous API requests with adaptive rate limiting and refined backoff strategy.
- Supports retries for failed batches and individual components within a batch.
- Handles API rate limits (429 errors) and respects 'Retry-After' headers.
- Incremental updates: ensures no duplicate vulnerabilities and picks up new vulnerabilities.
- Uses SQLite for storing component and vulnerability data.
- Introduces delays between batches to reduce throttling.
- Implements dynamic concurrency adjustment based on API responses.
- Logs operations for real-time monitoring and debugging.

Database Tables:
----------------
1. **components** - Stores component details (group ID, artifact ID, version).
2. **vulnerabilities** - Stores vulnerability data (CVE, CVSS score, severity, etc.).

Command-Line Arguments:
-----------------------
--restart           : Clears existing vulnerabilities and restarts the fetching process.
--retry-failed      : Retries previously failed API calls stored in 'failed_batches.json'.
--incremental       : Performs an incremental update to avoid duplicates and fetch new vulnerabilities.

Usage Examples:
---------------
1. **Full Fetch:**
   python sonatypetestAPIpart.py

2. **Full Restart (Clear Data & Start Fresh):**
   python sonatypetestAPIpart.py --restart

3. **Retry Failed Batches:**
   python sonatypetestAPIpart.py --retry-failed

4. **Incremental Update:**
   python sonatypetestAPIpart.py --incremental

"""

import sqlite3
import pandas as pd
import json
import logging
import argparse
import asyncio
import aiohttp
import random
import os
from base64 import b64encode
from tqdm import tqdm
import re

# Utility function to format seconds into DD:HH:MM:SS
def format_duration(seconds):
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{int(days):02d}:{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

# Setup logging
def setup_logging(log_file="fetch_log.txt"):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )

# Initialize SQLite Database
def init_db():
    conn = sqlite3.connect("vulnerabilities.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS components (
            component_id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id TEXT,
            artifact_id TEXT,
            version TEXT
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            vuln_id INTEGER PRIMARY KEY AUTOINCREMENT,
            component_id INTEGER,
            cve TEXT,
            cvss_score REAL,
            severity TEXT,
            published_date TEXT,
            payload TEXT,
            FOREIGN KEY (component_id) REFERENCES components (component_id)
        )
    ''')
    conn.commit()
    return conn

# Clear existing vulnerabilities from database
def clear_vulnerabilities(conn):
    cursor = conn.cursor()
    cursor.execute("DELETE FROM vulnerabilities")
    conn.commit()
    logging.info("🗑️ Existing vulnerabilities cleared from database.")

# Load Existing Components from Database
def load_components(conn):
    query = "SELECT component_id, group_id, artifact_id, version FROM components"
    df = pd.read_sql_query(query, conn)
    coordinates = [f"pkg:maven/{row['group_id']}/{row['artifact_id']}@{row['version']}" for _, row in df.iterrows()]
    logging.info(f"✅ Loaded {len(coordinates)} components from database.")
    return coordinates

# Retry individual components within a failed batch
async def retry_failed_components(session, failed_batch, headers, semaphore):
    successful = []
    failed = []

    for component in failed_batch:
        result = await fetch_vulnerabilities(session, [component], headers, semaphore)
        if result:
            successful.append(result)
        else:
            failed.append(component)

    return successful, failed

# Asynchronous function to fetch vulnerabilities with adaptive rate limiting
async def fetch_vulnerabilities(session, batch, headers, semaphore, retries=5, backoff_factor=2, max_backoff=30):
    url = "https://ossindex.sonatype.org/api/v3/component-report"
    backoff = 1
    async with semaphore:
        for attempt in range(retries):
            try:
                async with session.post(url, headers=headers, json={"coordinates": batch}) as response:
                    rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
                    if rate_limit_remaining and int(rate_limit_remaining) < 5:
                        logging.warning("⚠ Approaching API rate limit, pausing...")
                        await asyncio.sleep(10)

                    if response.status == 200:
                        return await response.json()
                    elif response.status == 429:
                        retry_after = response.headers.get('Retry-After')
                        wait_time = int(retry_after) if retry_after else backoff
                        wait_time = min(wait_time, max_backoff)
                        logging.warning(f"⚠ 429 Too Many Requests - Retrying in {wait_time} seconds...")
                        await asyncio.sleep(wait_time + random.uniform(0.5, 2.0))
                        backoff *= backoff_factor
                    else:
                        logging.error(f"⚠ Error {response.status}: {await response.text()}")
                        break
            except Exception as e:
                logging.error(f"🚨 Exception during API call: {str(e)}")
                await asyncio.sleep(backoff)
                backoff = min(backoff * backoff_factor, max_backoff)
    return []

# Process vulnerabilities with retry logic
async def process_vulnerabilities(coordinates, conn, username, api_token, incremental=False):
    headers = {"Content-Type": "application/json"}
    if username and api_token:
        token = f"{username}:{api_token}"
        encoded_token = b64encode(token.encode()).decode()
        headers["Authorization"] = f"Basic {encoded_token}"

    failed_batches_file = "failed_batches.json"
    cursor = conn.cursor()

    semaphore = asyncio.Semaphore(2)  # Further reduced concurrency
    batch_size = 50  # Reduced batch size
    failed_batches = []

    async with aiohttp.ClientSession() as session:
        for i in tqdm(range(0, len(coordinates), batch_size), desc="Fetching Vulnerabilities"):
            batch = coordinates[i:i + batch_size]
            vulnerabilities = await fetch_vulnerabilities(session, batch, headers, semaphore)

            if not vulnerabilities:
                logging.warning(f"⚠ Retrying individual components in failed batch.")
                successful, failed = await retry_failed_components(session, batch, headers, semaphore)
                vulnerabilities = successful
                failed_batches.extend(failed)

            for package in vulnerabilities:
                coordinate = package.get("coordinates", "")
                match = re.match(r'pkg:maven/(.*)/(.*)@(.*)', coordinate)
                if match:
                    group_id, artifact_id, version = match.groups()
                    cursor.execute('''
                        SELECT component_id FROM components 
                        WHERE group_id = ? AND artifact_id = ? AND version = ?
                    ''', (group_id, artifact_id, version))
                    result = cursor.fetchone()

                    if result:
                        component_id = result[0]
                        for vuln in package.get("vulnerabilities", []):
                            if incremental:
                                cursor.execute('''
                                    SELECT 1 FROM vulnerabilities 
                                    WHERE component_id = ? AND cve = ?
                                ''', (component_id, vuln.get("cve", "n/a")))
                                if cursor.fetchone():
                                    continue

                            cursor.execute('''
                                INSERT INTO vulnerabilities (component_id, cve, cvss_score, severity, published_date, payload) 
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (
                                component_id,
                                vuln.get("cve", "n/a"),
                                vuln.get("cvssScore", 0),
                                vuln.get("severity", "n/a"),
                                vuln.get("published", "n/a"),
                                json.dumps(vuln)
                            ))
                        conn.commit()
                    else:
                        logging.warning(f"⚠ Component not found in DB: {group_id}/{artifact_id}@{version}")

            # Delay between batches to reduce API pressure
            await asyncio.sleep(random.uniform(2, 5))

        if failed_batches:
            with open(failed_batches_file, "w") as f:
                json.dump(failed_batches, f)
            logging.warning(f"⚠ {len(failed_batches)} components failed after retries. Saved for future retry.")

# Main Function
def main():
    parser = argparse.ArgumentParser(description="Fetch vulnerabilities from Sonatype OSS Index.")
    parser.add_argument("--restart", action="store_true", help="Restart from beginning and clear vulnerabilities.")
    parser.add_argument("--retry-failed", action="store_true", help="Retry previously failed batches.")
    parser.add_argument("--incremental", action="store_true", help="Perform incremental update to avoid duplicates.")
    args = parser.parse_args()

    setup_logging()

    try:
        with open("config.json", "r") as f:
            config = json.load(f)
    except FileNotFoundError:
        logging.error("🚨 config.json not found. Please ensure it exists in the working directory.")
        return

    api_token = config.get("api_token")
    username = config.get("username")

    conn = init_db()

    if args.restart:
        clear_vulnerabilities(conn)
        if os.path.exists("checkpoint_vulnerabilities.json"):
            os.remove("checkpoint_vulnerabilities.json")
        logging.info("🔄 Restarting from beginning.")

    coordinates = load_components(conn)

    if not coordinates:
        logging.warning("⚠ No components found in the database. Exiting.")
        return

    if args.retry_failed and os.path.exists("failed_batches.json"):
        with open("failed_batches.json", "r") as f:
            failed_batches = json.load(f)
        logging.info(f"🔄 Retrying {len(failed_batches)} failed components.")
        asyncio.run(process_vulnerabilities(failed_batches, conn, username, api_token, incremental=args.incremental))
    else:
        asyncio.run(process_vulnerabilities(coordinates, conn, username, api_token, incremental=args.incremental))

    conn.close()
    logging.info("✅ Vulnerability fetching completed.")

if __name__ == "__main__":
    main()
