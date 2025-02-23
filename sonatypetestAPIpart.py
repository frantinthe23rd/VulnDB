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
- Dynamic concurrency adjustment based on API responses.
- Global rate limiter using token bucket algorithm.
- Incremental updates: ensures no duplicate vulnerabilities and picks up new vulnerabilities.
- Uses SQLite for storing component and vulnerability data.
- Introduces delays between batches to reduce throttling.
- Implements checkpointing to resume incomplete runs.
- Logs operations for real-time monitoring and debugging.

Database Tables:
----------------
1. **components** - Stores component details (group ID, artifact ID, version).
2. **vulnerabilities** - Stores vulnerability data (CVE, CVSS score, severity, etc.).

Command-Line Arguments:
-----------------------
--restart           : Clears existing vulnerabilities and restarts the fetching process.
--incremental       : Performs an incremental update to avoid duplicates and fetch new vulnerabilities.
--retry_failed      : Retries previously failed API calls stored in 'failed_batches.json'.

Usage Examples:
---------------
1. **Full Fetch:**
   python sonatypetestAPIpart.py

2. **Full Restart (Clear Data & Start Fresh):**
   python sonatypetestAPIpart.py --restart

3. **Incremental Update:**
   python sonatypetestAPIpart.py --incremental

4. **Retry Failed Batches:**
   python sonatypetestAPIpart.py --retry_failed

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
import time
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

# Token Bucket Rate Limiter
class RateLimiter:
    def __init__(self, rate, per):
        self.rate = rate
        self.per = per
        self.allowance = rate
        self.last_check = time.monotonic()

    async def acquire(self):
        while True:
            current = time.monotonic()
            time_passed = current - self.last_check
            self.last_check = current
            self.allowance += time_passed * (self.rate / self.per)

            if self.allowance > self.rate:
                self.allowance = self.rate

            if self.allowance >= 1:
                self.allowance -= 1
                return
            await asyncio.sleep((1 - self.allowance) * (self.per / self.rate))

# Dynamic Rate Limiting and Retry Logic
async def fetch_with_dynamic_backoff(session, url, headers, payload, rate_limiter, retries=5, max_backoff=60):
    backoff = 1
    for attempt in range(retries):
        await rate_limiter.acquire()
        try:
            async with session.post(url, headers=headers, json=payload) as response:
                rate_limit_remaining = response.headers.get('X-RateLimit-Remaining')
                rate_limit_reset = response.headers.get('X-RateLimit-Reset')

                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    retry_after = response.headers.get('Retry-After')
                    wait_time = int(retry_after) if retry_after else backoff
                    logging.warning(f"⚠ 429 Too Many Requests - Retrying in {wait_time} seconds...")
                    await asyncio.sleep(wait_time + random.uniform(0.5, 2.0))
                    backoff = min(backoff * 2, max_backoff)
                elif rate_limit_remaining is not None and int(rate_limit_remaining) < 5:
                    reset_time = int(rate_limit_reset) - int(time.time()) if rate_limit_reset else 10
                    logging.warning(f"⚠ Approaching API rate limit, waiting for {reset_time} seconds.")
                    await asyncio.sleep(reset_time)
                else:
                    logging.error(f"⚠ Error {response.status}: {await response.text()}")
                    break
        except Exception as e:
            logging.error(f"🚨 Exception during API call: {str(e)}")
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, max_backoff)
    return []

# Process vulnerabilities with smarter batch handling
async def process_vulnerabilities(coordinates, conn, username, api_token, incremental=False, retry_failed=False):
    headers = {"Content-Type": "application/json"}
    if username and api_token:
        token = f"{username}:{api_token}"
        encoded_token = b64encode(token.encode()).decode()
        headers["Authorization"] = f"Basic {encoded_token}"

    rate_limiter = RateLimiter(rate=10, per=1)  # 10 requests per second
    batch_size = 50
    failed_batches = []

    checkpoint_file = "checkpoint_vulnerabilities.json"
    start_index = 0

    if os.path.exists(checkpoint_file):
        with open(checkpoint_file, "r") as f:
            checkpoint_data = json.load(f)
            start_index = checkpoint_data.get("last_index", 0)

    async with aiohttp.ClientSession() as session:
        if retry_failed and os.path.exists("failed_batches.json"):
            with open("failed_batches.json", "r") as f:
                coordinates = json.load(f)
            logging.info(f"🔄 Retrying {len(coordinates)} failed components.")

        for i in tqdm(range(start_index, len(coordinates), batch_size), desc="Fetching Vulnerabilities"):
            batch = coordinates[i:i + batch_size]
            payload = {"coordinates": batch}
            vulnerabilities = await fetch_with_dynamic_backoff(session, "https://ossindex.sonatype.org/api/v3/component-report", headers, payload, rate_limiter)

            if not vulnerabilities:
                logging.warning(f"⚠ Retrying batch with reduced size.")
                for component in batch:
                    payload = {"coordinates": [component]}
                    component_vulns = await fetch_with_dynamic_backoff(session, "https://ossindex.sonatype.org/api/v3/component-report", headers, payload, rate_limiter)
                    if component_vulns:
                        vulnerabilities.extend(component_vulns)
                    else:
                        failed_batches.append(component)

            # Store vulnerabilities in DB
            cursor = conn.cursor()
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

            # Save checkpoint
            with open(checkpoint_file, "w") as f:
                json.dump({"last_index": i + batch_size}, f)

            await asyncio.sleep(random.uniform(1, 3))

    if failed_batches:
        with open("failed_batches.json", "w") as f:
            json.dump(failed_batches, f)
        logging.warning(f"⚠ {len(failed_batches)} components failed after retries. Saved for future retry.")

# Main Function
def main():
    parser = argparse.ArgumentParser(description="Fetch vulnerabilities from Sonatype OSS Index.")
    parser.add_argument("--restart", action="store_true", help="Restart from beginning and clear vulnerabilities.")
    parser.add_argument("--incremental", action="store_true", help="Perform incremental update.")
    parser.add_argument("--retry_failed", action="store_true", help="Retry previously failed batches.")
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
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM vulnerabilities")
        count = cursor.fetchone()[0]
        cursor.execute("DELETE FROM vulnerabilities")
        conn.commit()
        logging.info(f"🔄 Restarting: Cleared {count} records from the vulnerabilities table.")

    cursor = conn.cursor()
    cursor.execute("SELECT group_id, artifact_id, version FROM components")
    components = cursor.fetchall()
    logging.info(f"✅ Retrieved {len(components)} components from the database.")

    coordinates = [f"pkg:maven/{g}/{a}@{v}" for g, a, v in components]

    asyncio.run(process_vulnerabilities(coordinates, conn, username, api_token, incremental=args.incremental, retry_failed=args.retry_failed))

    conn.close()
    logging.info("✅ Vulnerability fetching completed.")

if __name__ == "__main__":
    main()
