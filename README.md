# ScoutSuite Runner

Reusable Docker-based runner for NCC Group ScoutSuite reports.

This repo is designed for Windows + Docker Desktop + PowerShell.

## What this repo does

* Builds a local pinned ScoutSuite Docker image.
* Keeps AWS credentials out of Git.
* Generates one report folder per client/run.
* Supports full or service-scoped AWS scans.
* Generates draft report artifacts from ScoutSuite results.
* Uses repeatable PowerShell commands.

## Repository structure

```text
scoutsuite-runner/
├─ Dockerfile
├─ README.md
├─ docs/
│  └─ report-template.md
├─ reports/
│  └─ .gitkeep
├─ scripts/
│  ├─ build.ps1
│  ├─ generate-report.ps1
│  ├─ init-aws-creds.ps1
│  ├─ open-latest-report.ps1
│  └─ run-aws.ps1
├─ secrets/
│  └─ aws/
│     ├─ README.md
│     └─ .gitkeep
└─ tools/
   └─ generate_report.py
```

## Security rules

Do not commit:

* `secrets/aws/credentials`
* `secrets/aws/config`
* `reports/`
* Generated ScoutSuite HTML reports
* Generated CSV/Markdown/JSON report outputs

ScoutSuite reports may contain sensitive cloud configuration data, including IAM, networking, storage, public exposure, domains, and resource identifiers.

## First-time setup

Open PowerShell in the repo root.

```powershell
.\scripts\init-aws-creds.ps1
```

Edit the files created in:

```text
secrets/aws/credentials
secrets/aws/config
```

Example `credentials`:

```ini
[scout-audit]
aws_access_key_id = YOUR_ACCESS_KEY_ID
aws_secret_access_key = YOUR_SECRET_ACCESS_KEY
```

Example `config`:

```ini
[profile scout-audit]
region = us-east-1
output = json
```

Then build the local Docker image:

```powershell
.\scripts\build.ps1
```

## Recommended AWS permissions

Use a temporary IAM user or role with audit/read-only permissions.

Recommended starting policy:

* `SecurityAudit`

If ScoutSuite reports missing permissions, consider adding:

* `ViewOnlyAccess`

Use `ReadOnlyAccess` only with explicit approval, because it may allow reading data from services such as S3 or DynamoDB.

Avoid:

* Root credentials
* Administrator access
* Power user access
* Write permissions
* Long-lived credentials

After the assessment, rotate or delete the access key when applicable.

## Run an AWS report

Basic run:

```powershell
.\scripts\run-aws.ps1 -Client "client-name"
```

Optional custom profile:

```powershell
.\scripts\run-aws.ps1 -Client "client-name" -Profile "scout-audit"
```

The report will be generated under:

```text
reports/client-name/YYYYMMDD-HHMMSS/
```

## Run a service-scoped AWS report

For shared AWS accounts, it is often better to scan only the services relevant to the assessment.

Example core AWS services:

```powershell
.\scripts\run-aws.ps1 -Client "client-name" -Services "iam ec2 vpc s3 rds cloudtrail cloudwatch kms lambda elb elbv2 route53 cloudfront acm sns sqs ses"
```

This is useful when some services cause throttling or when the assessment scope is limited.

The script sets AWS retry environment variables to reduce API throttling issues:

```text
AWS_RETRY_MODE=adaptive
AWS_MAX_ATTEMPTS=10
```

## Open the latest HTML report

```powershell
.\scripts\open-latest-report.ps1 -Client "client-name"
```

This opens the latest generated ScoutSuite HTML report for that client.

## Generate draft report artifacts

After running ScoutSuite, generate report artifacts from the latest client run:

```powershell
.\scripts\generate-report.ps1 -Client "client-name"
```

Or generate from a specific run folder:

```powershell
.\scripts\generate-report.ps1 -RunDir "reports\client-name\YYYYMMDD-HHMMSS" -Client "client-name"
```

Optional project/name filter:

```powershell
.\scripts\generate-report.ps1 -Client "client-name" -ProjectFilter "project-name"
```

Use the project filter carefully. It can miss shared resources such as VPCs, security groups, IAM policies, KMS keys, logs, or DNS records that still affect the application.

Generated files are created under:

```text
reports/client-name/YYYYMMDD-HHMMSS/generated/
```

Expected output:

```text
generated/
├─ findings.csv
├─ remediation-tasks.md
├─ report-draft.md
└─ summary.json
```

## Generated files

### `findings.csv`

Spreadsheet-friendly list of parsed ScoutSuite findings.

Useful for:

* Sorting by severity
* Sorting by service
* Filtering affected resources
* Building remediation plans

### `remediation-tasks.md`

Task-oriented Markdown checklist grouped by priority.

Priority mapping:

```text
Critical / High -> P1
Medium          -> P2
Low / Info      -> P3
```

### `report-draft.md`

Draft assessment report.

This is not final by default. It must be manually reviewed before sharing externally.

### `summary.json`

Machine-readable summary for future automation.

This file can later be consumed by n8n, ClickUp, Google Drive, or other reporting workflows.

## Suggested workflow

1. Update local AWS credentials:

```text
secrets/aws/credentials
secrets/aws/config
```

2. Run ScoutSuite:

```powershell
.\scripts\run-aws.ps1 -Client "client-name"
```

Or run only selected services:

```powershell
.\scripts\run-aws.ps1 -Client "client-name" -Services "iam ec2 vpc s3 rds cloudtrail cloudwatch kms lambda elb elbv2 route53 cloudfront acm sns sqs ses"
```

3. Generate draft report artifacts:

```powershell
.\scripts\generate-report.ps1 -Client "client-name"
```

4. Review:

```text
generated/report-draft.md
generated/remediation-tasks.md
generated/findings.csv
```

5. Manually validate scope and findings.

6. Convert the validated draft into the final professional report.

7. Rotate or delete audit credentials when finished.

## Scope guidance

ScoutSuite is primarily account/service-level.

In shared AWS accounts, the final report should not automatically claim that the entire AWS account was assessed for one product.

Recommended language:

```text
ScoutSuite was executed against the AWS account using read-only audit credentials. Because the account may host multiple products, this report focuses only on resources associated with the assessed application and shared infrastructure that directly affects its security posture. Resources belonging exclusively to other products are excluded unless they introduce risk to the assessed application.
```

## Example: Meta data security assessment

For a Meta-related data security assessment, scope the report around systems that store, process, access, transmit, secure, or monitor Meta user data.

Relevant areas usually include:

* IAM users, roles, and policies
* EC2 instances
* Load balancers
* VPCs, subnets, route tables, NACLs, and security groups
* RDS or other databases
* S3 buckets
* KMS keys
* Secrets Manager or SSM parameters
* CloudTrail and CloudWatch
* CloudFront, Route53, and ACM
* Application logs and incident response evidence

The generated report is a starting point. Manual validation is required.
