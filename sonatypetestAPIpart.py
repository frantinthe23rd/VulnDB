import sqlite3
import pandas as pd
import json
import matplotlib.pyplot as plt
import seaborn as sns
import requests
import time
from base64 import b64encode
import re
import datetime
import os
import sys
import logging
import argparse
import asyncio
import aiohttp
from tqdm import tqdm

# Utility function to format seconds into DD:HH:MM:SS
def format_duration(seconds):
    days, seconds = divmod(seconds, 86400)
    hours, seconds = divmod(seconds, 3600)
    minutes, seconds = divmod(seconds, 60)
    return f"{int(days):02d}:{int(hours):02d}:{int(minutes):02d}:{int(seconds):02d}"

# Setup logging for both console and file
def setup_logging(log_file="fetch_log.txt"):
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler(sys.stdout)
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

# Asynchronous function to fetch vulnerabilities with adaptive rate limiting
async def fetch_vulnerabilities(session, batch, headers, retries=5, backoff_factor=2):
    url = "https://ossindex.sonatype.org/api/v3/component-report"
    backoff = 1
    for attempt in range(retries):
        try:
            async with session.post(url, headers=headers, json={"coordinates": batch}) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 429:
                    logging.warning(f"⚠ 429 Too Many Requests - Retrying in {backoff} seconds...")
                    await asyncio.sleep(backoff)
                    backoff *= backoff_factor
                elif response.status == 403:
                    logging.warning(f"⚠ 403 Forbidden - Backing off...")
                    await asyncio.sleep(backoff * 2)
                else:
                    logging.error(f"⚠ Error {response.status}: {await response.text()}")
                    break
        except Exception as e:
            logging.error(f"🚨 Exception during API call: {str(e)}")
            await asyncio.sleep(backoff)
            backoff *= backoff_factor
    return []

# Process vulnerabilities asynchronously with retry for failed batches
async def process_vulnerabilities(coordinates, conn, username, api_token):
    headers = {"Content-Type": "application/json"}
    if username and api_token:
        token = f"{username}:{api_token}"
        encoded_token = b64encode(token.encode()).decode()
        headers["Authorization"] = f"Basic {encoded_token}"

    checkpoint_file = "checkpoint_vulnerabilities.json"
    failed_batches_file = "failed_batches.json"
    cursor = conn.cursor()

    async with aiohttp.ClientSession() as session:
        tasks = []
        batch_size = 100
        failed_batches = []

        for i in range(0, len(coordinates), batch_size):
            batch = coordinates[i:i+batch_size]
            tasks.append(fetch_vulnerabilities(session, batch, headers))

        for future in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Fetching Vulnerabilities"):
            vulnerabilities = await future
            if not vulnerabilities:
                failed_batches.append(batch)
                continue

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

        if failed_batches:
            with open(failed_batches_file, "w") as f:
                json.dump(failed_batches, f)
            logging.warning(f"⚠ {len(failed_batches)} batches failed. Saved for retry.")

# Main Function
def main():
    parser = argparse.ArgumentParser(description="Fetch vulnerabilities from Sonatype OSS Index.")
    parser.add_argument("--restart", action="store_true", help="Restart from beginning and clear vulnerabilities.")
    parser.add_argument("--retry-failed", action="store_true", help="Retry previously failed batches.")
    args = parser.parse_args()

    setup_logging()
    api_token = "77751202da5417497f9b5d261969b86a325c965a"
    username = "REDACTED"

    conn = init_db()

    if args.restart:
        clear_vulnerabilities(conn)
        if os.path.exists("checkpoint_vulnerabilities.json"):
            os.remove("checkpoint_vulnerabilities.json")
        logging.info("🔄 Restarting from beginning.")

    coordinates = load_components(conn)

    if args.retry_failed and os.path.exists("failed_batches.json"):
        with open("failed_batches.json", "r") as f:
            failed_batches = json.load(f)
        logging.info(f"🔄 Retrying {len(failed_batches)} failed batches.")
        asyncio.run(process_vulnerabilities(failed_batches, conn, username, api_token))
    else:
        asyncio.run(process_vulnerabilities(coordinates, conn, username, api_token))

    conn.close()
    logging.info("✅ Vulnerability fetching completed.")

# Run Main if Script is Executed
if __name__ == "__main__":
    main()