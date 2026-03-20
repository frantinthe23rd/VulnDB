#!/usr/bin/env python3
"""
VulnDB Pipeline
---------------
Downloads the Maven vulnerability dataset from Google OSV (one bulk request,
no API key required), processes it into summary/detailed CSVs and a heatmap,
then uploads everything to S3 and invalidates CloudFront.

Run locally:
    S3_BUCKET=vulndb-dashboard python pipeline.py

Run in CI:
    Set env vars S3_BUCKET, AWS_DEFAULT_REGION, CLOUDFRONT_DISTRIBUTION_ID
"""

import io
import json
import os
import re
import logging
import zipfile
from datetime import datetime, timezone

import boto3
import botocore.exceptions
import pandas as pd
import requests

# ── Config ────────────────────────────────────────────────────────────────────
OSV_URL    = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
S3_BUCKET  = os.environ["S3_BUCKET"]
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
CF_ID      = os.environ.get("CLOUDFRONT_DISTRIBUTION_ID", "")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ── Helpers ───────────────────────────────────────────────────────────────────

def extract_cvss(record: dict) -> float:
    """Return a numeric CVSS base score from an OSV record."""
    # 1. database_specific.cvss_score (NVD-sourced records)
    score = record.get("database_specific", {}).get("cvss_score")
    if score is not None:
        try:
            return float(score)
        except (ValueError, TypeError):
            pass

    # 2. severity array — try CVSS v3/v2 vector via cvss library
    for sev in record.get("severity", []):
        vector = sev.get("score", "")
        try:
            if vector.startswith("CVSS:3"):
                from cvss import CVSS3
                return float(CVSS3(vector).base_score)
            elif "CVSS:2" in vector or vector.startswith("AV:"):
                from cvss import CVSS2
                return float(CVSS2(vector).base_score)
        except Exception:
            pass

    # 3. Fall back to severity label
    label = record.get("database_specific", {}).get("severity", "").upper()
    return {"CRITICAL": 9.5, "HIGH": 8.0, "MEDIUM": 5.5, "LOW": 2.0}.get(label, 0.0)


def score_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score >  0.0: return "LOW"
    return "UNKNOWN"


def extract_cve(record: dict) -> str:
    for alias in record.get("aliases", []):
        if alias.startswith("CVE-"):
            return alias
    return record.get("id", "")


# ── Stage 1: Download ─────────────────────────────────────────────────────────

def download_osv() -> io.BytesIO:
    log.info("Downloading OSV Maven bulk dataset …")
    try:
        resp = requests.get(OSV_URL, stream=True, timeout=600)
        resp.raise_for_status()
    except requests.exceptions.Timeout:
        raise RuntimeError(f"Timed out downloading OSV dataset from {OSV_URL}")
    except requests.exceptions.ConnectionError as e:
        raise RuntimeError(f"Network error downloading OSV dataset: {e}") from e
    except requests.exceptions.HTTPError as e:
        raise RuntimeError(f"HTTP {e.response.status_code} downloading OSV dataset: {e}") from e
    data = resp.content
    log.info(f"Downloaded {len(data)/1_048_576:.1f} MB")
    return io.BytesIO(data)


# ── Stage 2: Parse ────────────────────────────────────────────────────────────

def parse_osv(zip_buf: io.BytesIO) -> pd.DataFrame:
    rows = []
    try:
        zf_ctx = zipfile.ZipFile(zip_buf)
    except zipfile.BadZipFile as e:
        raise RuntimeError("Downloaded OSV data is not a valid ZIP archive") from e
    with zf_ctx as zf:
        names = zf.namelist()
        log.info(f"Parsing {len(names):,} OSV records …")
        for name in names:
            try:
                with zf.open(name) as f:
                    rec = json.load(f)
            except Exception as e:
                log.debug(f"Skip {name}: {e}")
                continue

            cvss   = extract_cvss(rec)
            sev    = score_to_severity(cvss)
            cve    = extract_cve(rec)
            pub    = rec.get("published", "")[:10]
            summary = rec.get("summary", "")[:300]

            for affected in rec.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("ecosystem") != "Maven":
                    continue
                name_field = pkg.get("name", "")
                if ":" not in name_field:
                    continue
                group_id, artifact_id = name_field.split(":", 1)
                versions = affected.get("versions", [])

                # Extract fixed version from ranges
                fixed_ver = ""
                for r in affected.get("ranges", []):
                    if r.get("type") in ("ECOSYSTEM", "SEMVER"):
                        for event in r.get("events", []):
                            if "fixed" in event:
                                fixed_ver = event["fixed"]
                                break
                    if fixed_ver:
                        break

                rows.append({
                    "osv_id":            rec["id"],
                    "cve":               cve,
                    "group_id":          group_id,
                    "artifact_id":       artifact_id,
                    "summary":           summary,
                    "cvss_score":        cvss,
                    "severity":          sev,
                    "published_date":    pub,
                    "versions":          versions,
                    "num_affected_versions": len(versions),
                    "fixed_version":     fixed_ver,
                })

    df = pd.DataFrame(rows)
    if df.empty:
        raise RuntimeError("No Maven vulnerability records found in OSV dataset")
    log.info(f"Parsed {len(df):,} vulnerability-package rows (pre-dedup)")

    # A single OSV record can have multiple affected entries for the same package
    # (e.g. separate version ranges for 10.x and 11.x). Collapse them into one
    # row per CVE+package, merging version lists and taking the best fixed version.
    key = ["osv_id", "group_id", "artifact_id"]
    scalar_cols = ["cve", "summary", "cvss_score", "severity", "published_date"]
    scalars = df.groupby(key)[scalar_cols].first()
    merged_versions = df.groupby(key)["versions"].apply(
        lambda s: list({v for vlist in s for v in vlist})
    )
    best_fix = df.groupby(key)["fixed_version"].apply(
        lambda s: _max_version([v for v in s if v]) or ""
    )
    df = scalars.join(merged_versions).join(best_fix).reset_index()
    df["num_affected_versions"] = df["versions"].apply(len)

    log.info(f"Parsed {len(df):,} vulnerability-package rows (post-dedup)")
    return df


# ── Helpers ───────────────────────────────────────────────────────────────────

def _max_version(versions: list) -> str:
    """Return the highest version string using semver-aware comparison."""
    from packaging.version import Version, InvalidVersion
    parsed = []
    for v in versions:
        try:
            parsed.append((Version(v), v))
        except InvalidVersion:
            pass
    if not parsed:
        return ""
    return max(parsed, key=lambda t: t[0])[1]


# ── Stage 3: Generate outputs ─────────────────────────────────────────────────

def generate_outputs(df: pd.DataFrame, out_dir: str = "/tmp") -> dict:
    try:
        os.makedirs(f"{out_dir}/csv", exist_ok=True)
    except OSError as e:
        raise RuntimeError(f"Cannot create output directory {out_dir}/csv: {e}") from e

    # ── Detailed CSV
    detailed = df[[
        "group_id", "artifact_id", "cve", "cvss_score", "severity",
        "published_date", "summary", "num_affected_versions", "fixed_version"
    ]].rename(columns={"group_id": "publisher", "artifact_id": "product"})
    try:
        detailed.to_csv(f"{out_dir}/csv/vulnerability_detailed.csv", index=False)
    except OSError as e:
        raise RuntimeError(f"Failed to write detailed CSV: {e}") from e
    log.info("Detailed CSV written")

    # ── Summary CSV
    two_years_ago = (datetime.now(timezone.utc) - pd.Timedelta(days=730)).strftime("%Y-%m-%d")
    one_year_ago  = (datetime.now(timezone.utc) - pd.Timedelta(days=365)).strftime("%Y-%m-%d")

    df["is_recent"]    = df["published_date"] >= two_years_ago
    df["is_last_year"] = df["published_date"] >= one_year_ago
    df["is_prev_year"] = (df["published_date"] >= two_years_ago) & (df["published_date"] < one_year_ago)
    df["sev_weight"]   = df["severity"].map({"CRITICAL": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 0}).fillna(0)
    df["recent_sev_weight"] = df["sev_weight"] * df["is_recent"].astype(int)

    def sev_count(series, label):
        return int((series == label).sum())

    summary = (
        df.groupby(["group_id", "artifact_id"])
        .agg(
            total_vulnerabilities  =("osv_id",           "count"),
            critical               =("severity",          lambda x: sev_count(x, "CRITICAL")),
            high                   =("severity",          lambda x: sev_count(x, "HIGH")),
            medium                 =("severity",          lambda x: sev_count(x, "MEDIUM")),
            low                    =("severity",          lambda x: sev_count(x, "LOW")),
            avg_cvss               =("cvss_score",        "mean"),
            latest_vuln_date       =("published_date",    "max"),
            total_affected_versions=("versions",          lambda x: len(set(v for vlist in x for v in vlist))),
            recent_cves            =("is_recent",         "sum"),
            last_year_cves         =("is_last_year",      "sum"),
            prev_year_cves         =("is_prev_year",      "sum"),
            risk_score             =("recent_sev_weight", "sum"),
            min_safe_version       =("fixed_version",     lambda x: _max_version(x[x != ""].tolist())),
            unfixed_cves           =("fixed_version",     lambda x: int((x == "").sum())),
        )
        .reset_index()
        .rename(columns={"group_id": "publisher", "artifact_id": "product"})
    )
    summary["avg_cvss"]   = summary["avg_cvss"].round(1)
    summary["risk_score"] = summary["risk_score"].astype(int)
    summary["recent_cves"]     = summary["recent_cves"].astype(int)
    summary["last_year_cves"]  = summary["last_year_cves"].astype(int)
    summary["prev_year_cves"]  = summary["prev_year_cves"].astype(int)
    summary["trend"] = summary.apply(
        lambda r: "up"   if r["last_year_cves"] > r["prev_year_cves"] else
                  "down" if r["last_year_cves"] < r["prev_year_cves"] else "flat",
        axis=1,
    )
    summary = summary.sort_values("risk_score", ascending=False)
    try:
        summary[[
            "publisher", "product", "risk_score", "total_vulnerabilities",
            "recent_cves", "last_year_cves", "prev_year_cves", "trend",
            "critical", "high", "medium", "low",
            "avg_cvss", "latest_vuln_date", "total_affected_versions",
            "min_safe_version", "unfixed_cves",
        ]].to_csv(f"{out_dir}/csv/vulnerability_summary.csv", index=False)
    except OSError as e:
        raise RuntimeError(f"Failed to write summary CSV: {e}") from e
    log.info("Summary CSV written")

    # ── Metadata JSON
    metadata = {
        "last_updated":         datetime.now(timezone.utc).strftime("%d %b %Y %H:%M UTC"),
        "total_vulnerabilities": int(df["osv_id"].nunique()),
        "total_packages":        int(df.groupby(["group_id","artifact_id"]).ngroups),
        "critical_count":        int((df["severity"] == "CRITICAL").sum()),
        "high_count":            int((df["severity"] == "HIGH").sum()),
        "medium_count":          int((df["severity"] == "MEDIUM").sum()),
        "low_count":             int((df["severity"] == "LOW").sum()),
    }
    try:
        with open(f"{out_dir}/metadata.json", "w") as fh:
            json.dump(metadata, fh, indent=2)
    except OSError as e:
        raise RuntimeError(f"Failed to write metadata.json: {e}") from e
    log.info(f"Metadata: {metadata}")

    return metadata


# ── Stage 4: Upload to S3 ─────────────────────────────────────────────────────

def upload_to_s3(out_dir: str = "/tmp"):
    s3 = boto3.client("s3", region_name=AWS_REGION)
    files = [
        (f"{out_dir}/csv/vulnerability_summary.csv",  "csv/vulnerability_summary.csv",  "text/csv"),
        (f"{out_dir}/csv/vulnerability_detailed.csv", "csv/vulnerability_detailed.csv", "text/csv"),
        (f"{out_dir}/metadata.json",                  "metadata.json",                  "application/json"),
    ]
    for local, key, content_type in files:
        try:
            s3.upload_file(
                local, S3_BUCKET, key,
                ExtraArgs={"ContentType": content_type, "CacheControl": "max-age=3600"},
            )
        except botocore.exceptions.NoCredentialsError:
            raise RuntimeError("No AWS credentials found — cannot upload to S3")
        except botocore.exceptions.ClientError as e:
            raise RuntimeError(f"S3 upload failed for {key}: {e}") from e
        log.info(f"  ↑ s3://{S3_BUCKET}/{key}")


def invalidate_cloudfront():
    if not CF_ID:
        return
    cf = boto3.client("cloudfront", region_name="us-east-1")
    try:
        cf.create_invalidation(
            DistributionId=CF_ID,
            InvalidationBatch={
                "Paths": {"Quantity": 1, "Items": ["/*"]},
                "CallerReference": str(datetime.now(timezone.utc).timestamp()),
            },
        )
    except botocore.exceptions.ClientError as e:
        raise RuntimeError(f"CloudFront invalidation failed for {CF_ID}: {e}") from e
    log.info(f"CloudFront invalidation created for {CF_ID}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    try:
        zip_buf  = download_osv()
        df       = parse_osv(zip_buf)
        generate_outputs(df)
        upload_to_s3()
        invalidate_cloudfront()
    except RuntimeError as e:
        log.error(f"Pipeline failed: {e}")
        raise
    log.info("Pipeline complete ✓")


def handler(event, context):
    """AWS Lambda entry point."""
    try:
        main()
    except Exception as e:
        log.error(f"Unhandled error in Lambda handler: {e}")
        return {"statusCode": 500, "body": str(e)}
    return {"statusCode": 200, "body": "Pipeline complete"}


if __name__ == "__main__":
    main()
