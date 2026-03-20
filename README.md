# VulnDB

A serverless vulnerability dashboard for open-source packages across **Maven (Java)**, **PyPI (Python)**, and **npm (JavaScript)**, powered by the [Google OSV dataset](https://osv.dev). Automatically fetches, processes, and publishes browsable vulnerability databases to a static website via AWS.

## Architecture

```
Google OSV (public bulk exports)
   Maven/all.zip · PyPI/all.zip · npm/all.zip
              │
              ▼
   AWS Lambda (pipeline.py)
   Runs each ecosystem in sequence
   Generates CSVs + metadata.json per ecosystem
              │
              ▼
   Amazon S3 (static hosting)
   maven/ · pypi/ · npm/
              │
              ▼
   Amazon CloudFront (HTTPS + caching)
              │
              ▼
   Static Dashboards
   index.html → maven.html · pypi.html · npm.html
```

The pipeline runs as an AWS Lambda container image, triggered on a schedule or manually via GitHub Actions. The dashboard is a fully static site — no backend, no database.

## Repository Structure

```
├── pipeline.py                        # Lambda handler: fetch → parse → score → upload (all ecosystems)
├── Dockerfile                         # Container image for Lambda
├── requirements.txt                   # Python dependencies
├── pytest.ini                         # Pytest configuration
├── index.html                         # Landing page (links to ecosystem dashboards)
├── maven.html                         # Maven (Java) vulnerability dashboard
├── pypi.html                          # PyPI (Python) vulnerability dashboard
├── npm.html                           # npm (JavaScript) vulnerability dashboard
├── about.html                         # Methodology and data sources
├── tests/
│   └── test_pipeline.py               # Pipeline test suite (pytest)
└── .github/workflows/
    ├── pipeline.yml                   # CI/CD: test, build & deploy Lambda on pipeline changes
    └── deploy.yml                     # CI/CD: deploy HTML files to S3 on dashboard changes
```

## Ecosystems

| Dashboard | Ecosystem | Package format | OSV bulk URL |
|-----------|-----------|----------------|--------------|
| Maven | Java / JVM | `groupId:artifactId` | `osv-vulnerabilities.storage.googleapis.com/Maven/all.zip` |
| PyPI | Python | package name | `osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip` |
| npm | JavaScript / Node.js | package name | `osv-vulnerabilities.storage.googleapis.com/npm/all.zip` |

No API key is required — all OSV bulk downloads are public.

## Deploying Your Own Instance

### Prerequisites

- An AWS account with permissions to create Lambda, ECR, S3, and CloudFront resources
- An S3 bucket configured for static website hosting
- A CloudFront distribution pointing at the S3 bucket
- An ECR repository for the Lambda container image
- An IAM role for the Lambda function with S3 write permissions

### 1. Fork the Repository

Fork this repo to your own GitHub account.

### 2. Configure GitHub Actions Variables

In your repo go to **Settings → Secrets and variables → Actions → Variables** and add:

| Variable | Description | Example |
|----------|-------------|---------|
| `AWS_REGION` | Region for Lambda, ECR, and S3 | `eu-west-2` |
| `S3_BUCKET` | S3 bucket name for the dashboard | `my-vulndb-bucket` |
| `ECR_REPOSITORY` | ECR repository name for the Lambda image | `vulndb-pipeline` |
| `LAMBDA_FUNCTION` | Lambda function name | `vulndb-pipeline` |

### 3. Configure GitHub Actions Secrets

In your repo go to **Settings → Secrets and variables → Actions → Secrets** and add:

| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | IAM access key with deploy permissions |
| `AWS_SECRET_ACCESS_KEY` | IAM secret key |
| `LAMBDA_ROLE_ARN` | Full ARN of the Lambda execution role (e.g. `arn:aws:iam::123456789012:role/vulndb-pipeline-role`) |
| `VULNDB_CF_DISTRIBUTION_ID` | CloudFront distribution ID |

### 4. Deploy

Push any change to `pipeline.py`, `Dockerfile`, or `requirements.txt` to trigger the pipeline workflow, which will run tests, then build and push the Lambda container image and create/update the Lambda function.

Push any change to `index.html`, `maven.html`, `pypi.html`, `npm.html`, or `about.html` to trigger the dashboard deployment to S3.

You can also trigger either workflow manually via **Actions → Run workflow**.

### 5. Schedule the Pipeline

To run the pipeline on a schedule, add a `schedule` trigger to `.github/workflows/pipeline.yml`:

```yaml
on:
  schedule:
    - cron: '0 6 * * 1'   # Every Monday at 06:00 UTC
  workflow_dispatch:
```

## S3 Structure

Each ecosystem's data is stored under its own prefix:

```
s3://your-bucket/
├── index.html
├── maven.html
├── pypi.html
├── npm.html
├── about.html
├── maven/
│   ├── metadata.json
│   └── csv/
│       ├── vulnerability_summary.csv
│       └── vulnerability_detailed.csv
├── pypi/
│   ├── metadata.json
│   └── csv/
│       ├── vulnerability_summary.csv
│       └── vulnerability_detailed.csv
└── npm/
    ├── metadata.json
    └── csv/
        ├── vulnerability_summary.csv
        └── vulnerability_detailed.csv
```

## Risk Score

Each package is assigned a risk score based on recent vulnerability activity:

| Severity | CVSS Range | Weight |
|----------|------------|--------|
| Critical | 9.0 – 10.0 | 4 |
| High | 7.0 – 8.9 | 2 |
| Medium | 4.0 – 6.9 | 1 |
| Low | 0.1 – 3.9 | 0 |

The score is the sum of weights for all vulnerabilities published in the past two years. Packages are ranked by this score on each dashboard.
