"""
Tests for pipeline.py

Run with:
    pytest tests/test_pipeline.py -v
"""

import io
import json
import os
import zipfile
from unittest.mock import MagicMock, patch

import pandas as pd
import pytest

# S3_BUCKET must be set before importing pipeline
os.environ.setdefault("S3_BUCKET", "test-bucket")

import pipeline  # noqa: E402


# ── extract_cvss ──────────────────────────────────────────────────────────────

class TestExtractCvss:
    def test_database_specific_score(self):
        rec = {"database_specific": {"cvss_score": "7.5"}}
        assert pipeline.extract_cvss(rec) == 7.5

    def test_database_specific_score_numeric(self):
        rec = {"database_specific": {"cvss_score": 9.8}}
        assert pipeline.extract_cvss(rec) == 9.8

    def test_database_specific_score_invalid_falls_through(self):
        rec = {"database_specific": {"cvss_score": "n/a"}, "severity": []}
        assert pipeline.extract_cvss(rec) == 0.0

    def test_severity_label_critical(self):
        rec = {"database_specific": {"severity": "CRITICAL"}}
        assert pipeline.extract_cvss(rec) == 9.5

    def test_severity_label_high(self):
        rec = {"database_specific": {"severity": "HIGH"}}
        assert pipeline.extract_cvss(rec) == 8.0

    def test_severity_label_medium(self):
        rec = {"database_specific": {"severity": "MEDIUM"}}
        assert pipeline.extract_cvss(rec) == 5.5

    def test_severity_label_low(self):
        rec = {"database_specific": {"severity": "LOW"}}
        assert pipeline.extract_cvss(rec) == 2.0

    def test_empty_record_returns_zero(self):
        assert pipeline.extract_cvss({}) == 0.0


# ── score_to_severity ─────────────────────────────────────────────────────────

class TestScoreToSeverity:
    @pytest.mark.parametrize("score,expected", [
        (9.0,  "CRITICAL"),
        (9.8,  "CRITICAL"),
        (7.0,  "HIGH"),
        (8.9,  "HIGH"),
        (4.0,  "MEDIUM"),
        (6.9,  "MEDIUM"),
        (0.1,  "LOW"),
        (3.9,  "LOW"),
        (0.0,  "UNKNOWN"),
    ])
    def test_boundaries(self, score, expected):
        assert pipeline.score_to_severity(score) == expected


# ── extract_cve ───────────────────────────────────────────────────────────────

class TestExtractCve:
    def test_cve_from_aliases(self):
        rec = {"aliases": ["GHSA-xxxx", "CVE-2024-1234"], "id": "GHSA-xxxx"}
        assert pipeline.extract_cve(rec) == "CVE-2024-1234"

    def test_first_cve_alias_wins(self):
        rec = {"aliases": ["CVE-2024-0001", "CVE-2024-0002"], "id": "OSV-1"}
        assert pipeline.extract_cve(rec) == "CVE-2024-0001"

    def test_fallback_to_id(self):
        rec = {"aliases": ["GHSA-xxxx"], "id": "GHSA-xxxx"}
        assert pipeline.extract_cve(rec) == "GHSA-xxxx"

    def test_no_aliases(self):
        rec = {"id": "OSV-1"}
        assert pipeline.extract_cve(rec) == "OSV-1"


# ── download_osv ──────────────────────────────────────────────────────────────

class TestDownloadOsv:
    def test_success_returns_bytesio(self, requests_mock):
        requests_mock.get(pipeline.OSV_URL, content=b"PK\x03\x04fake-zip-data")
        result = pipeline.download_osv()
        assert isinstance(result, io.BytesIO)
        assert result.read() == b"PK\x03\x04fake-zip-data"

    def test_http_error_raises_runtime_error(self, requests_mock):
        requests_mock.get(pipeline.OSV_URL, status_code=503)
        with pytest.raises(RuntimeError, match="HTTP 503"):
            pipeline.download_osv()

    def test_connection_error_raises_runtime_error(self, requests_mock):
        import requests as req
        requests_mock.get(pipeline.OSV_URL, exc=req.exceptions.ConnectionError("refused"))
        with pytest.raises(RuntimeError, match="Network error"):
            pipeline.download_osv()

    def test_timeout_raises_runtime_error(self, requests_mock):
        import requests as req
        requests_mock.get(pipeline.OSV_URL, exc=req.exceptions.Timeout())
        with pytest.raises(RuntimeError, match="Timed out"):
            pipeline.download_osv()


# ── parse_osv ─────────────────────────────────────────────────────────────────

def _make_zip(records: list[dict]) -> io.BytesIO:
    """Build an in-memory ZIP containing one JSON file per record."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i, rec in enumerate(records):
            zf.writestr(f"GHSA-{i:04d}.json", json.dumps(rec))
    buf.seek(0)
    return buf


def _maven_record(osv_id="GHSA-0001", cve="CVE-2024-1234", score=7.5,
                  group="org.example", artifact="lib", versions=None,
                  fixed="2.0.0") -> dict:
    return {
        "id": osv_id,
        "aliases": [cve],
        "published": "2024-01-15T00:00:00Z",
        "summary": "A test vulnerability",
        "database_specific": {"cvss_score": score},
        "affected": [{
            "package": {"ecosystem": "Maven", "name": f"{group}:{artifact}"},
            "versions": versions or ["1.0.0", "1.1.0"],
            "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": fixed}]}],
        }],
        "severity": [],
    }


class TestParseOsv:
    def test_valid_zip_returns_dataframe(self):
        buf = _make_zip([_maven_record()])
        df = pipeline.parse_osv(buf)
        assert len(df) == 1
        assert df.iloc[0]["group_id"] == "org.example"
        assert df.iloc[0]["artifact_id"] == "lib"
        assert df.iloc[0]["cve"] == "CVE-2024-1234"
        assert df.iloc[0]["fixed_version"] == "2.0.0"

    def test_multiple_records_parsed(self):
        records = [
            _maven_record("GHSA-0001", "CVE-2024-0001", group="org.a", artifact="x"),
            _maven_record("GHSA-0002", "CVE-2024-0002", group="org.b", artifact="y"),
        ]
        df = pipeline.parse_osv(_make_zip(records))
        assert len(df) == 2

    def test_non_maven_records_skipped(self):
        non_maven = {
            "id": "GHSA-npm",
            "aliases": [],
            "published": "2024-01-01T00:00:00Z",
            "summary": "npm vuln",
            "database_specific": {},
            "affected": [{"package": {"ecosystem": "npm", "name": "lodash"}, "versions": []}],
            "severity": [],
        }
        buf = _make_zip([non_maven])
        with pytest.raises(RuntimeError, match="No Maven vulnerability records"):
            pipeline.parse_osv(buf)

    def test_invalid_zip_raises_runtime_error(self):
        bad_buf = io.BytesIO(b"this is not a zip")
        with pytest.raises(RuntimeError, match="not a valid ZIP"):
            pipeline.parse_osv(bad_buf)

    def test_corrupt_json_entry_skipped(self):
        good = _maven_record("GHSA-0001", "CVE-2024-0001")
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("bad.json", "not-json{{{{")
            zf.writestr("good.json", json.dumps(good))
        buf.seek(0)
        df = pipeline.parse_osv(buf)
        assert len(df) == 1

    def test_dedup_multiple_affected_entries_same_package(self):
        """Two affected entries for the same package in one record should collapse to one row."""
        rec = {
            "id": "GHSA-multi",
            "aliases": ["CVE-2024-9999"],
            "published": "2024-06-01T00:00:00Z",
            "summary": "Multi-range vuln",
            "database_specific": {"cvss_score": 8.0},
            "affected": [
                {
                    "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                    "versions": ["1.0.0"],
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "1.1.0"}]}],
                },
                {
                    "package": {"ecosystem": "Maven", "name": "org.example:lib"},
                    "versions": ["2.0.0"],
                    "ranges": [{"type": "ECOSYSTEM", "events": [{"fixed": "2.1.0"}]}],
                },
            ],
            "severity": [],
        }
        df = pipeline.parse_osv(_make_zip([rec]))
        assert len(df) == 1
        assert df.iloc[0]["num_affected_versions"] == 2  # 1.0.0 + 2.0.0


# ── generate_outputs ──────────────────────────────────────────────────────────

@pytest.fixture
def sample_df():
    return pd.DataFrame([{
        "osv_id": "GHSA-0001",
        "cve": "CVE-2024-1234",
        "group_id": "org.example",
        "artifact_id": "lib",
        "summary": "Test vuln",
        "cvss_score": 7.5,
        "severity": "HIGH",
        "published_date": "2025-06-01",
        "versions": ["1.0.0", "1.1.0"],
        "num_affected_versions": 2,
        "fixed_version": "2.0.0",
    }])


class TestGenerateOutputs:
    def test_creates_csv_files(self, sample_df, tmp_path):
        pipeline.generate_outputs(sample_df, out_dir=str(tmp_path))
        assert (tmp_path / "csv" / "vulnerability_detailed.csv").exists()
        assert (tmp_path / "csv" / "vulnerability_summary.csv").exists()

    def test_creates_metadata_json(self, sample_df, tmp_path):
        pipeline.generate_outputs(sample_df, out_dir=str(tmp_path))
        meta = json.loads((tmp_path / "metadata.json").read_text())
        assert meta["total_vulnerabilities"] == 1
        assert meta["total_packages"] == 1
        assert meta["high_count"] == 1
        assert meta["critical_count"] == 0

    def test_detailed_csv_columns(self, sample_df, tmp_path):
        pipeline.generate_outputs(sample_df, out_dir=str(tmp_path))
        detail = pd.read_csv(tmp_path / "csv" / "vulnerability_detailed.csv")
        assert "publisher" in detail.columns
        assert "product" in detail.columns
        assert "cve" in detail.columns
        assert "cvss_score" in detail.columns

    def test_summary_csv_has_risk_score(self, sample_df, tmp_path):
        pipeline.generate_outputs(sample_df, out_dir=str(tmp_path))
        summary = pd.read_csv(tmp_path / "csv" / "vulnerability_summary.csv")
        assert "risk_score" in summary.columns
        assert "trend" in summary.columns

    def test_os_error_on_write_raises_runtime_error(self, sample_df, tmp_path):
        with patch("pandas.DataFrame.to_csv", side_effect=OSError("disk full")):
            with pytest.raises(RuntimeError, match="Failed to write"):
                pipeline.generate_outputs(sample_df, out_dir=str(tmp_path))


# ── upload_to_s3 ──────────────────────────────────────────────────────────────

class TestUploadToS3:
    def test_uploads_all_three_files(self, tmp_path):
        # Create dummy output files
        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        (csv_dir / "vulnerability_summary.csv").write_text("a,b\n1,2")
        (csv_dir / "vulnerability_detailed.csv").write_text("a,b\n1,2")
        (tmp_path / "metadata.json").write_text("{}")

        mock_s3 = MagicMock()
        with patch("boto3.client", return_value=mock_s3):
            pipeline.upload_to_s3(out_dir=str(tmp_path))

        assert mock_s3.upload_file.call_count == 3

    def test_no_credentials_raises_runtime_error(self, tmp_path):
        import botocore.exceptions
        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        (csv_dir / "vulnerability_summary.csv").write_text("a,b")
        (csv_dir / "vulnerability_detailed.csv").write_text("a,b")
        (tmp_path / "metadata.json").write_text("{}")

        mock_s3 = MagicMock()
        mock_s3.upload_file.side_effect = botocore.exceptions.NoCredentialsError()
        with patch("boto3.client", return_value=mock_s3):
            with pytest.raises(RuntimeError, match="No AWS credentials"):
                pipeline.upload_to_s3(out_dir=str(tmp_path))

    def test_client_error_raises_runtime_error(self, tmp_path):
        import botocore.exceptions
        csv_dir = tmp_path / "csv"
        csv_dir.mkdir()
        (csv_dir / "vulnerability_summary.csv").write_text("a,b")
        (csv_dir / "vulnerability_detailed.csv").write_text("a,b")
        (tmp_path / "metadata.json").write_text("{}")

        mock_s3 = MagicMock()
        mock_s3.upload_file.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "Access Denied"}}, "PutObject"
        )
        with patch("boto3.client", return_value=mock_s3):
            with pytest.raises(RuntimeError, match="S3 upload failed"):
                pipeline.upload_to_s3(out_dir=str(tmp_path))


# ── invalidate_cloudfront ─────────────────────────────────────────────────────

class TestInvalidateCloudfront:
    def test_skips_when_cf_id_empty(self):
        with patch("pipeline.CF_ID", ""):
            with patch("boto3.client") as mock_boto:
                pipeline.invalidate_cloudfront()
                mock_boto.assert_not_called()

    def test_creates_invalidation(self):
        mock_cf = MagicMock()
        with patch("pipeline.CF_ID", "EXXXXXXXXXXXXX"):
            with patch("boto3.client", return_value=mock_cf):
                pipeline.invalidate_cloudfront()
        mock_cf.create_invalidation.assert_called_once()
        call_kwargs = mock_cf.create_invalidation.call_args[1]
        assert call_kwargs["DistributionId"] == "EXXXXXXXXXXXXX"
        assert call_kwargs["InvalidationBatch"]["Paths"]["Items"] == ["/*"]

    def test_client_error_raises_runtime_error(self):
        import botocore.exceptions
        mock_cf = MagicMock()
        mock_cf.create_invalidation.side_effect = botocore.exceptions.ClientError(
            {"Error": {"Code": "NoSuchDistribution", "Message": "not found"}},
            "CreateInvalidation",
        )
        with patch("pipeline.CF_ID", "EXXXXXXXXXXXXX"):
            with patch("boto3.client", return_value=mock_cf):
                with pytest.raises(RuntimeError, match="CloudFront invalidation failed"):
                    pipeline.invalidate_cloudfront()
