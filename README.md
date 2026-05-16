# AWS Cloud Security Auditor

Professional AWS security assessment tool with dual operation modes.

## Modes

**Compliance Mode (default)** - CIS AWS Foundations Benchmark v1.5.0 audit  
**Attack Mode** - Offensive security testing (requires authorization)

## Quick Start

```bash
# Install
pip install boto3

# Compliance scan (single region)
python aws_auditor.py --profile readonly --region us-east-2

# Compliance scan (multi-region)
python aws_auditor.py --profile readonly --regions us-east-1,us-west-2,eu-west-1

# Compliance scan (all regions)
python aws_auditor.py --profile readonly --all-regions

# Attack mode (requires authorization)
python aws_auditor.py --mode attack --profile pentest --all-regions
```

## Compliance Mode

**What it checks:**
- CIS Section 1: IAM security (root account, MFA, password policy, access keys)
- CIS Section 2: Storage (S3 encryption, RDS security, EBS encryption)
- CIS Section 3: Logging (CloudTrail, VPC Flow Logs, KMS encryption)
- CIS Section 4: Monitoring (GuardDuty, AWS Config)
- CIS Section 5: Networking (Security groups, default VPC)

**Coverage:** 50+ CIS Benchmark controls

**Output:** JSON compliance report with score

## Attack Mode

****WARNING:** REQUIRES AUTHORIZATION - Authorized security testing only**

**What it tests:**
- IAM privilege escalation paths
- S3 data exfiltration vectors
- EC2 lateral movement opportunities
- RDS database exposure
- IMDSv1 SSRF vulnerabilities
- VPC network reconnaissance gaps
- EKS cluster compromise vectors
- Secrets Manager enumeration

**Output:** JSON attack report with exploitation vectors

## AWS Credentials

```bash
# Option 1: AWS Profile
~/.aws/credentials:
[readonly]
aws_access_key_id = AKIA...
aws_secret_access_key = ...

python aws_auditor.py --profile readonly

# Option 2: Environment Variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...

python aws_auditor.py

# Option 3: IAM Role (EC2/Lambda)
python aws_auditor.py
```

## Required Permissions

**Compliance Mode (Read-only):**
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "iam:Get*",
      "iam:List*",
      "iam:GenerateCredentialReport",
      "s3:GetBucket*",
      "s3:GetPublicAccessBlock",
      "s3:ListAllMyBuckets",
      "ec2:Describe*",
      "rds:Describe*",
      "cloudtrail:Describe*",
      "cloudtrail:GetTrailStatus",
      "cloudtrail:LookupEvents",
      "guardduty:Get*",
      "guardduty:List*",
      "config:Describe*",
      "kms:DescribeKey",
      "kms:GetKeyRotationStatus",
      "kms:ListKeys",
      "lambda:GetPolicy",
      "lambda:ListFunctions",
      "elbv2:Describe*",
      "eks:DescribeCluster",
      "eks:ListClusters",
      "secretsmanager:ListSecrets",
      "accessanalyzer:ListAnalyzers"
    ],
    "Resource": "*"
  }]
}
```

**Attack Mode:** Same as compliance mode (read-only assessment)

## Output Files

```bash
# Compliance mode
aws_compliance_report_YYYYMMDD_HHMMSS.json

# Attack mode
aws_attack_report_YYYYMMDD_HHMMSS.json
```

## Features Comparison

| Feature | Compliance Mode | Attack Mode |
|---------|----------------|-------------|
| **Purpose** | CIS Benchmark audit | Offensive testing |
| **Approach** | Configuration review | Exploitation analysis |
| **Output** | Compliance score | Attack vectors |
| **CIS Mapping** | Yes: Yes | No: No |
| **Risk Assessment** | Policy violations | Exploitation paths |
| **Authorization Required** | Standard pentest | Written authorization |

## Examples

### Multi-region compliance audit
```bash
python aws_auditor.py \
  --mode compliance \
  --profile prod-readonly \
  --regions us-east-1,us-west-2,eu-west-1
```

### Single region attack assessment
```bash
python aws_auditor.py \
  --mode attack \
  --profile pentest-high \
  --region us-east-2
```

### Full account scan (all regions)
```bash
python aws_auditor.py \
  --mode compliance \
  --profile audit \
  --all-regions
```

## Architecture

```
AWSAuditorBase (base class)
├── Shared checks (CIS controls)
├── Session management
└── Finding aggregation

AttackMode (inheritance)
├── IAM privilege escalation
├── Data exfiltration vectors
├── Lateral movement paths
└── SSRF/IMDS attacks

ComplianceMode (inheritance)
├── CIS Section 1: IAM
├── CIS Section 2: Storage
├── CIS Section 3: Logging
├── CIS Section 4: Monitoring
└── CIS Section 5: Networking
```

**Design:** Zero duplicate code, DRY principle, factory pattern for mode selection

## Compliance Score

Compliance mode calculates score based on findings:
- Total CIS checks: ~50 controls
- Compliance Score: (Passed / Total) × 100%
- Severity weighting: CRITICAL > HIGH > MEDIUM > LOW

Example output:
```
Total Findings: 12
  CRITICAL: 2
  HIGH: 4
  MEDIUM: 5
  LOW: 1

CIS Controls Affected: 8
Compliance Score: 76.0%
```

## Security

- Yes: Read-only operations (no modifications)
- Yes: SSL verification disabled for corporate proxies
- Yes: No credentials stored or logged
- Yes: CIS Benchmark aligned
- **WARNING:** Attack mode requires written authorization

## License

MIT

## Disclaimer

**For authorized security assessments only.**  
Unauthorized testing may violate laws and policies.

## Version

2.0 - Unified dual-mode architecture
