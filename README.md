# VulnDB

A serverless vulnerability dashboard for Maven (Java) packages, powered by the [Google OSV dataset](https://osv.dev). Automatically fetches, processes, and publishes a browsable vulnerability database to a static website via AWS.

## Architecture

```
Google OSV API
      │
      ▼
AWS Lambda (pipeline.py)
      │  Generates CSVs + metadata.json
      ▼
Amazon S3 (static hosting)
      │
      ▼
Amazon CloudFront (HTTPS + caching)
      │
      ▼
Static Dashboard (index.html / about.html)
```

The pipeline runs as an AWS Lambda container image, triggered on a schedule or manually via GitHub Actions. The dashboard is a fully static site — no backend, no database.

## Repository Structure

```
├── pipeline.py                        # Lambda handler: fetch → process → upload
├── Dockerfile                         # Container image for Lambda
├── requirements.txt                   # Python dependencies
├── index.html                         # Main dashboard UI
├── about.html                         # Methodology and data sources
└── .github/workflows/
    ├── pipeline.yml                   # CI/CD: build & deploy Lambda on pipeline changes
    └── deploy.yml                     # CI/CD: deploy HTML to S3 on dashboard changes
```

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

Push any change to `pipeline.py`, `Dockerfile`, or `requirements.txt` to trigger the pipeline workflow, which will build and push the Lambda container image and create/update the Lambda function.

Push any change to `index.html` or `about.html` to trigger the dashboard deployment to S3.

You can also trigger either workflow manually via **Actions → Run workflow**.

### 5. Schedule the Pipeline

To run the pipeline on a schedule, add a `schedule` trigger to `.github/workflows/pipeline.yml`:

```yaml
on:
  schedule:
    - cron: '0 3 * * 1'   # Every Monday at 03:00 UTC
  workflow_dispatch:
```

## Data Sources

| Source | Usage |
|--------|-------|
| [Google OSV](https://osv.dev) | Bulk Maven vulnerability dataset (`osv-vulnerabilities.storage.googleapis.com`) |
| [NVD](https://nvd.nist.gov) | CVSS scores (embedded within OSV records) |

No API key is required — the OSV bulk download is public.

## Risk Score

Each package is assigned a risk score based on recent vulnerability activity:

| Severity | Weight |
|----------|--------|
| Critical | 4 |
| High | 2 |
| Medium | 1 |
| Low | 0 |

The score is the sum of weights for all vulnerabilities published in the past two years. Packages are ranked by this score on the dashboard.
