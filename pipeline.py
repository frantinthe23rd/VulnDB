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
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
import requests
import seaborn as sns

# ── Config ────────────────────────────────────────────────────────────────────
OSV_URL    = "https://osv-vulnerabilities.storage.googleapis.com/Maven/all.zip"
S3_BUCKET  = os.environ.get("S3_BUCKET", "vulndb-dashboard")
AWS_REGION = os.environ.get("AWS_DEFAULT_REGION", "eu-west-2")
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
    resp = requests.get(OSV_URL, stream=True, timeout=600)
    resp.raise_for_status()
    data = resp.content
    log.info(f"Downloaded {len(data)/1_048_576:.1f} MB")
    return io.BytesIO(data)


# ── Stage 2: Parse ────────────────────────────────────────────────────────────

def parse_osv(zip_buf: io.BytesIO) -> pd.DataFrame:
    rows = []
    with zipfile.ZipFile(zip_buf) as zf:
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
                })

    df = pd.DataFrame(rows)
    log.info(f"Parsed {len(df):,} vulnerability-package rows")
    return df


# ── Stage 3: Generate outputs ─────────────────────────────────────────────────

def generate_outputs(df: pd.DataFrame, out_dir: str = "/tmp") -> dict:
    os.makedirs(f"{out_dir}/csv",    exist_ok=True)
    os.makedirs(f"{out_dir}/images", exist_ok=True)

    # ── Detailed CSV
    detailed = df[[
        "group_id", "artifact_id", "cve", "cvss_score", "severity",
        "published_date", "summary", "num_affected_versions"
    ]].rename(columns={"group_id": "publisher", "artifact_id": "product"})
    detailed.to_csv(f"{out_dir}/csv/vulnerability_detailed.csv", index=False)
    log.info("Detailed CSV written")

    # ── Summary CSV
    def sev_count(series, label):
        return int((series == label).sum())

    summary = (
        df.groupby(["group_id", "artifact_id"])
        .agg(
            total_vulnerabilities=("osv_id",    "count"),
            critical             =("severity",  lambda x: sev_count(x, "CRITICAL")),
            high                 =("severity",  lambda x: sev_count(x, "HIGH")),
            medium               =("severity",  lambda x: sev_count(x, "MEDIUM")),
            low                  =("severity",  lambda x: sev_count(x, "LOW")),
            avg_cvss             =("cvss_score","mean"),
            latest_vuln_date     =("published_date","max"),
            total_affected_versions=("versions", lambda x: len(set(v for vlist in x for v in vlist))),
        )
        .reset_index()
        .rename(columns={"group_id": "publisher", "artifact_id": "product"})
        .sort_values("total_vulnerabilities", ascending=False)
    )
    summary["avg_cvss"] = summary["avg_cvss"].round(1)
    summary.to_csv(f"{out_dir}/csv/vulnerability_summary.csv", index=False)
    log.info("Summary CSV written")

    # ── Heatmap (top 20 packages × year)
    top20 = summary.nlargest(20, "total_vulnerabilities")["product"].tolist()
    heat_df = df[df["artifact_id"].isin(top20)].copy()
    heat_df["year"] = heat_df["published_date"].str[:4]
    heat_df = heat_df[heat_df["year"].str.fullmatch(r"\d{4}", na=False)]

    pivot = heat_df.pivot_table(
        index="artifact_id", columns="year",
        values="osv_id", aggfunc="count", fill_value=0
    )
    pivot = pivot.reindex(
        pivot.sum(axis=1).sort_values(ascending=False).index
    )

    fig, ax = plt.subplots(figsize=(18, 10))
    sns.heatmap(
        pivot, annot=True, fmt="d", cmap="YlOrRd",
        linewidths=0.4, linecolor="#1e293b",
        cbar_kws={"label": "CVE Count", "shrink": 0.6},
        ax=ax,
    )
    ax.set_title(
        "Top 20 Maven Components — CVE Count by Year",
        fontsize=15, fontweight="bold", pad=16,
        color="#1e293b",
    )
    ax.set_xlabel("Year Published", fontsize=11, color="#334155")
    ax.set_ylabel("Component (artifact ID)", fontsize=11, color="#334155")
    ax.tick_params(axis="x", rotation=45)
    ax.tick_params(axis="y", rotation=0)
    plt.tight_layout()
    plt.savefig(f"{out_dir}/images/vulnerability_heatmap.png", dpi=150, bbox_inches="tight")
    plt.close()
    log.info("Heatmap written")

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
    with open(f"{out_dir}/metadata.json", "w") as fh:
        json.dump(metadata, fh, indent=2)
    log.info(f"Metadata: {metadata}")

    return metadata


# ── Stage 4: Upload to S3 ─────────────────────────────────────────────────────

def upload_to_s3(out_dir: str = "/tmp"):
    s3 = boto3.client("s3", region_name=AWS_REGION)
    files = [
        (f"{out_dir}/csv/vulnerability_summary.csv",  "csv/vulnerability_summary.csv",  "text/csv"),
        (f"{out_dir}/csv/vulnerability_detailed.csv", "csv/vulnerability_detailed.csv", "text/csv"),
        (f"{out_dir}/images/vulnerability_heatmap.png", "images/vulnerability_heatmap.png", "image/png"),
        (f"{out_dir}/metadata.json",                  "metadata.json",                  "application/json"),
    ]
    for local, key, content_type in files:
        s3.upload_file(
            local, S3_BUCKET, key,
            ExtraArgs={"ContentType": content_type, "CacheControl": "max-age=3600"},
        )
        log.info(f"  ↑ s3://{S3_BUCKET}/{key}")


def invalidate_cloudfront():
    if not CF_ID:
        return
    cf = boto3.client("cloudfront", region_name="us-east-1")
    cf.create_invalidation(
        DistributionId=CF_ID,
        InvalidationBatch={
            "Paths": {"Quantity": 1, "Items": ["/*"]},
            "CallerReference": str(datetime.now(timezone.utc).timestamp()),
        },
    )
    log.info(f"CloudFront invalidation created for {CF_ID}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    zip_buf  = download_osv()
    df       = parse_osv(zip_buf)
    metadata = generate_outputs(df)
    upload_to_s3()
    invalidate_cloudfront()
    log.info("Pipeline complete ✓")


def handler(event, context):
    """AWS Lambda entry point."""
    main()
    return {"statusCode": 200, "body": "Pipeline complete"}


if __name__ == "__main__":
    main()
