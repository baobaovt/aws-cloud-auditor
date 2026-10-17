#!/usr/bin/env python3
"""
AWS Cloud Security Auditor
Dual-mode security assessment tool combining attack and compliance checks

Modes:
  attack      - Offensive security testing (requires authorization)
  compliance  - CIS AWS Foundations Benchmark audit (default)

v2.1 - Performance pass: parallel multi-region scanning, cached credential
       report / bucket / user lookups, full pagination, opt-in TLS bypass.
       Detection logic per check is unchanged from v2.0.
"""

import boto3
import json
import sys
import time
import functools
import warnings
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any
from botocore.exceptions import ClientError, NoCredentialsError
import urllib3

# Suppress warnings (only relevant when --insecure disables TLS verification)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
warnings.filterwarnings('ignore')


# ============================================================================
# Check accounting decorator - drives an honest compliance score
# ============================================================================

def security_check(func):
    """Tally a check's outcome by its return value.

    Convention (unchanged from v2.0): a check returns True when the control
    passes, False when it fails (a finding was raised), and None when it could
    not be evaluated (error / access denied). Only pass+fail form the score
    denominator so missing permissions don't silently deflate the result.
    """
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        result = func(self, *args, **kwargs)
        with self.lock:
            if result is True:
                self.checks_passed += 1
            elif result is False:
                self.checks_failed += 1
            else:
                self.checks_error += 1
        return result
    return wrapper


# ============================================================================
# BASE CLASS - Shared functionality for both modes
# ============================================================================

class AWSAuditorBase:
    """Base class with shared AWS security checks"""

    def __init__(self, profile_name=None, regions=None, all_regions=False,
                 verify_tls=True, max_workers=20, output=None):
        self.profile_name = profile_name
        self.findings = []
        self.start_time = datetime.now()

        # Runtime options
        self.verify = verify_tls          # TLS verification (opt-out via --insecure)
        self.max_workers = max(1, max_workers)
        self.output_file = output

        # Concurrency + caches
        self.lock = threading.Lock()
        self._cred_report = None
        self._buckets = None
        self._users = None
        self._client_cache = {}   # (service, region) -> boto3 client, reused across threads
        self._api_cache = {}      # (service, region, op, args) -> result, dedupes repeated describes

        # Score accounting
        self.checks_passed = 0
        self.checks_failed = 0
        self.checks_error = 0

        # Initialize session FIRST - region resolution (--all-regions) calls AWS
        # and therefore needs self.session to already exist.
        try:
            if profile_name:
                self.session = boto3.Session(profile_name=profile_name)
            else:
                self.session = boto3.Session()

            # Get account info
            sts = self.session.client('sts', verify=self.verify)
            identity = sts.get_caller_identity()
            self.account_id = identity['Account']
            self.user_arn = identity['Arn']

        except NoCredentialsError:
            print("[ERROR] Error: No AWS credentials found")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Error connecting to AWS: {str(e)}")
            sys.exit(1)

        # Setup regions (uses self.session when enumerating all regions)
        if all_regions:
            self.regions = self._get_all_regions()
        elif regions:
            self.regions = regions if isinstance(regions, list) else [regions]
        else:
            self.regions = ['us-east-2']

    def _get_all_regions(self):
        """Get all available AWS regions"""
        ec2 = self.session.client('ec2', region_name='us-east-1', verify=self.verify)
        response = ec2.describe_regions()
        return [region['RegionName'] for region in response['Regions']]

    def get_client(self, service, region=None):
        """Get a cached boto3 client for service in region.

        botocore Sessions are not guaranteed thread-safe for *client creation*,
        so serialize creation under the lock and cache the result. A boto3 client
        is thread-safe for making calls, so the cached client is shared across
        worker threads - this avoids re-creating (and re-loading service models
        for) the same client on every check.
        """
        cache_key = (service, region)
        with self.lock:
            client = self._client_cache.get(cache_key)
            if client is None:
                if region:
                    client = self.session.client(service, region_name=region, verify=self.verify)
                else:
                    client = self.session.client(service, verify=self.verify)
                self._client_cache[cache_key] = client
            return client

    # ------------------------------------------------------------------
    # Concurrency + pagination helpers
    # ------------------------------------------------------------------

    def _parallel(self, fn, items):
        """Map fn over items concurrently, preserving input order."""
        items = list(items)
        if self.max_workers <= 1 or len(items) <= 1:
            return [fn(i) for i in items]
        with ThreadPoolExecutor(max_workers=min(self.max_workers, len(items))) as ex:
            return list(ex.map(fn, items))

    def _for_each_region(self, fn):
        """Run fn(region) across all target regions, concurrently."""
        self._parallel(fn, self.regions)

    def _paginate(self, client, op, key, **kwargs):
        """Collect every page of a list/describe call.

        Fixes the v2.0 truncation bug where only the first page was read, which
        could silently hide findings in large accounts.
        """
        if client.can_paginate(op):
            out = []
            for page in client.get_paginator(op).paginate(**kwargs):
                out.extend(page.get(key, []))
            return out
        resp = getattr(client, op)(**kwargs)
        return resp.get(key, [])

    def _describe_cached(self, service, region, op, key, **kwargs):
        """Paginate a describe/list once per (service, region, op, args) and reuse.

        Several checks read the same resource list (e.g. RDS instances, VPCs, KMS
        keys) in the same region; this memoizes the call so it hits AWS once.
        Results are read-only within a run, so caching is safe.
        """
        cache_key = (service, region, op, tuple(sorted((k, str(v)) for k, v in kwargs.items())))
        with self.lock:
            if cache_key in self._api_cache:
                return self._api_cache[cache_key]
        result = self._paginate(self.get_client(service, region), op, key, **kwargs)
        with self.lock:
            self._api_cache[cache_key] = result
        return result

    def _all_buckets(self):
        """Cached list of S3 buckets (account-global, fetched once)."""
        with self.lock:
            if self._buckets is not None:
                return self._buckets
        s3 = self.get_client('s3')
        buckets = s3.list_buckets().get('Buckets', [])
        with self.lock:
            self._buckets = buckets
        return buckets

    def _all_users(self):
        """Cached, fully-paginated list of IAM users."""
        with self.lock:
            if self._users is not None:
                return self._users
        iam = self.get_client('iam')
        users = self._paginate(iam, 'list_users', 'Users')
        with self.lock:
            self._users = users
        return users

    def _get_cred_report(self):
        """Generate the IAM credential report once, poll until ready, cache it.

        Replaces two separate generate + fixed sleep(5) calls (v2.0) with a
        single generation and a state poll, removing ~10s of dead wait.
        """
        with self.lock:
            if self._cred_report is not None:
                return self._cred_report

        iam = self.get_client('iam')
        state = None
        for _ in range(30):
            try:
                state = iam.generate_credential_report().get('State')
            except ClientError:
                state = None
            if state == 'COMPLETE':
                break
            time.sleep(1)

        report = iam.get_credential_report()
        lines = report['Content'].decode('utf-8').strip().split('\n')
        headers = lines[0].split(',')
        rows = [dict(zip(headers, line.split(','))) for line in lines[1:]]

        with self.lock:
            self._cred_report = rows
        return rows

    def add_finding(self, severity, title, resource, details, cis_control="", cvss=0.0, region="global"):
        """Add security finding (thread-safe)"""
        finding = {
            'severity': severity,
            'title': title,
            'resource': resource,
            'details': details,
            'cis_control': cis_control,
            'cvss_score': cvss,
            'region': region,
            'timestamp': datetime.now().isoformat()
        }
        with self.lock:
            self.findings.append(finding)

    # ========================================================================
    # SHARED CHECKS - Used by both attack and compliance modes
    # ========================================================================

    @security_check
    def check_root_mfa(self):
        """CIS 1.5 - Ensure MFA is enabled for root account"""
        iam = self.get_client('iam')
        try:
            summary = iam.get_account_summary()
            if summary['SummaryMap'].get('AccountMFAEnabled', 0) == 0:
                self.add_finding('CRITICAL', 'Root Account MFA Not Enabled',
                               f'arn:aws:iam::{self.account_id}:root',
                               'Root account without MFA allows account takeover if credentials compromised',
                               'CIS 1.5', 9.1)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking root MFA: {e}")
            return None

    @security_check
    def check_root_access_keys(self):
        """CIS 1.4 - Ensure root account has no access keys"""
        try:
            rows = self._get_cred_report()

            for user_data in rows:
                if user_data['user'] == '<root_account>':
                    if user_data.get('access_key_1_active') == 'true' or user_data.get('access_key_2_active') == 'true':
                        self.add_finding('CRITICAL', 'Root Account Has Access Keys',
                                       '<root_account>',
                                       'Root access keys provide unrestricted access if compromised',
                                       'CIS 1.4', 10.0)
                        return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking root keys: {e}")
            return None

    @security_check
    def check_iam_password_policy(self):
        """CIS 1.8-1.11 - Check IAM password policy"""
        iam = self.get_client('iam')
        try:
            policy = iam.get_account_password_policy()['PasswordPolicy']

            issues = []
            if policy.get('MinimumPasswordLength', 0) < 14:
                issues.append('Min length < 14')
            if not policy.get('RequireUppercaseCharacters'):
                issues.append('No uppercase')
            if not policy.get('RequireLowercaseCharacters'):
                issues.append('No lowercase')
            if not policy.get('RequireNumbers'):
                issues.append('No numbers')
            if not policy.get('RequireSymbols'):
                issues.append('No symbols')
            if not policy.get('MaxPasswordAge', 0) or policy.get('MaxPasswordAge') > 90:
                issues.append('Max age > 90 days or never expires')

            if issues:
                self.add_finding('MEDIUM', 'Weak IAM Password Policy',
                               f'arn:aws:iam::{self.account_id}:account-password-policy',
                               f"Policy weaknesses: {', '.join(issues)}",
                               'CIS 1.8-1.11', 5.0)
                return False
            return True

        except iam.exceptions.NoSuchEntityException:
            self.add_finding('HIGH', 'No IAM Password Policy Configured',
                           f'arn:aws:iam::{self.account_id}:account-password-policy',
                           'No password policy exists for the account',
                           'CIS 1.8', 6.5)
            return False
        except Exception as e:
            print(f"[WARNING]  Error checking password policy: {e}")
            return None

    @security_check
    def check_iam_user_mfa(self):
        """CIS 1.10 - Ensure MFA for IAM users with console access"""
        iam = self.get_client('iam')
        try:
            users = self._all_users()

            def check(user):
                username = user['UserName']
                try:
                    # Check if user has console password
                    iam.get_login_profile(UserName=username)

                    # Check if user has MFA
                    mfa_devices = self._paginate(iam, 'list_mfa_devices', 'MFADevices', UserName=username)
                    if not mfa_devices:
                        return username
                except iam.exceptions.NoSuchEntityException:
                    return None  # User has no console access
                except Exception:
                    return None
                return None

            users_without_mfa = [u for u in self._parallel(check, users) if u]

            if users_without_mfa:
                self.add_finding('HIGH', f'{len(users_without_mfa)} IAM Users Without MFA',
                               f'arn:aws:iam::{self.account_id}:user/*',
                               f"Users: {', '.join(users_without_mfa[:5])}{'...' if len(users_without_mfa) > 5 else ''}",
                               'CIS 1.10', 7.5)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking user MFA: {e}")
            return None

    @security_check
    def check_old_access_keys(self):
        """CIS 1.3 - Ensure credentials unused for 90 days are disabled"""
        iam = self.get_client('iam')
        try:
            users = self._all_users()

            def check(user):
                username = user['UserName']
                found = []
                try:
                    keys = self._paginate(iam, 'list_access_keys', 'AccessKeyMetadata', UserName=username)
                except Exception:
                    return found
                for key in keys:
                    if key['Status'] == 'Active':
                        key_age = (datetime.now(key['CreateDate'].tzinfo) - key['CreateDate']).days
                        if key_age > 90:
                            found.append(f"{username}/{key['AccessKeyId']}")
                return found

            old_keys = [k for sub in self._parallel(check, users) for k in sub]

            if old_keys:
                self.add_finding('MEDIUM', f'{len(old_keys)} Access Keys Older Than 90 Days',
                               f'arn:aws:iam::{self.account_id}:user/*',
                               f"Keys: {', '.join(old_keys[:3])}{'...' if len(old_keys) > 3 else ''}",
                               'CIS 1.3', 5.3)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking access keys: {e}")
            return None

    @security_check
    def check_s3_public_buckets(self):
        """CIS 2.1.5 - Ensure S3 buckets are not publicly accessible"""
        s3 = self.get_client('s3')
        try:
            buckets = self._all_buckets()

            def check(bucket):
                bucket_name = bucket['Name']
                try:
                    pab = s3.get_public_access_block(Bucket=bucket_name)
                    config = pab['PublicAccessBlockConfiguration']

                    if not all([config.get('BlockPublicAcls'), config.get('IgnorePublicAcls'),
                              config.get('BlockPublicPolicy'), config.get('RestrictPublicBuckets')]):
                        return bucket_name
                except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    return bucket_name
                except Exception:
                    return None
                return None

            public_buckets = [b for b in self._parallel(check, buckets) if b]

            if public_buckets:
                self.add_finding('CRITICAL', f'{len(public_buckets)} S3 Buckets Not Fully Protected',
                               f'arn:aws:s3:::*',
                               f"Buckets: {', '.join(public_buckets[:5])}{'...' if len(public_buckets) > 5 else ''}",
                               'CIS 2.1.5', 8.6)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking S3 buckets: {e}")
            return None

    @security_check
    def check_s3_encryption(self):
        """CIS 2.1.1 - Ensure S3 bucket encryption is enabled"""
        s3 = self.get_client('s3')
        try:
            buckets = self._all_buckets()

            def check(bucket):
                bucket_name = bucket['Name']
                try:
                    s3.get_bucket_encryption(Bucket=bucket_name)
                except s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    return bucket_name
                except Exception:
                    return None
                return None

            unencrypted = [b for b in self._parallel(check, buckets) if b]

            if unencrypted:
                self.add_finding('MEDIUM', f'{len(unencrypted)} S3 Buckets Without Encryption',
                               f'arn:aws:s3:::*',
                               f"Buckets: {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}",
                               'CIS 2.1.1', 5.3)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking S3 encryption: {e}")
            return None

    @security_check
    def check_security_groups(self, region):
        """CIS 5.2 - Ensure no security group allows unrestricted ingress"""
        ec2 = self.get_client('ec2', region)
        try:
            security_groups = self._paginate(ec2, 'describe_security_groups', 'SecurityGroups')
            risky_sgs = []

            def _open_to_world(rule):
                # IPv4 anywhere OR IPv6 anywhere
                v4 = any(r.get('CidrIp') == '0.0.0.0/0' for r in rule.get('IpRanges', []))
                v6 = any(r.get('CidrIpv6') == '::/0' for r in rule.get('Ipv6Ranges', []))
                return v4 or v6

            for sg in security_groups:
                sg_id = sg['GroupId']
                sg_name = sg['GroupName']

                for rule in sg.get('IpPermissions', []):
                    if not _open_to_world(rule):
                        continue

                    proto = rule.get('IpProtocol')
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')

                    if proto == '-1':
                        risky_sgs.append(f"{sg_name} (All traffic from anywhere)")
                    elif from_port is not None and to_port is not None:
                        # Flag if the open port range covers SSH or RDP
                        if from_port <= 22 <= to_port:
                            risky_sgs.append(f"{sg_name} (SSH from anywhere)")
                        if from_port <= 3389 <= to_port:
                            risky_sgs.append(f"{sg_name} (RDP from anywhere)")

            if risky_sgs:
                self.add_finding('CRITICAL', f'{len(risky_sgs)} Security Groups Allow Unrestricted Access',
                               f'arn:aws:ec2:{region}:{self.account_id}:security-group/*',
                               f"Issues: {', '.join(risky_sgs[:3])}{'...' if len(risky_sgs) > 3 else ''}",
                               'CIS 5.2', 9.8, region)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking security groups in {region}: {e}")
            return None

    @security_check
    def check_rds_public_access(self, region):
        """CIS 2.3.1 - Ensure RDS instances are not publicly accessible"""
        rds = self.get_client('rds', region)
        try:
            instances = self._describe_cached('rds', region, 'describe_db_instances', 'DBInstances')
            public_dbs = [db['DBInstanceIdentifier'] for db in instances if db.get('PubliclyAccessible')]

            if public_dbs:
                self.add_finding('CRITICAL', f'{len(public_dbs)} RDS Instances Publicly Accessible',
                               f'arn:aws:rds:{region}:{self.account_id}:db:*',
                               f"Databases: {', '.join(public_dbs[:5])}{'...' if len(public_dbs) > 5 else ''}",
                               'CIS 2.3.1', 9.1, region)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking RDS in {region}: {e}")
            return None

    @security_check
    def check_rds_encryption(self, region):
        """CIS 2.3.2 - Ensure RDS encryption at rest is enabled"""
        rds = self.get_client('rds', region)
        try:
            instances = self._describe_cached('rds', region, 'describe_db_instances', 'DBInstances')
            unencrypted = [db['DBInstanceIdentifier'] for db in instances if not db.get('StorageEncrypted')]

            if unencrypted:
                self.add_finding('HIGH', f'{len(unencrypted)} RDS Instances Not Encrypted',
                               f'arn:aws:rds:{region}:{self.account_id}:db:*',
                               f"Databases: {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}",
                               'CIS 2.3.2', 7.5, region)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking RDS encryption in {region}: {e}")
            return None

    @security_check
    def check_cloudtrail_enabled(self, region):
        """CIS 3.1 - Ensure CloudTrail is enabled"""
        cloudtrail = self.get_client('cloudtrail', region)
        try:
            trails = cloudtrail.describe_trails()['trailList']

            if not trails:
                self.add_finding('CRITICAL', 'CloudTrail Not Enabled',
                               f'arn:aws:cloudtrail:{region}:{self.account_id}:trail/*',
                               'No CloudTrail trails configured - audit logging disabled',
                               'CIS 3.1', 8.6, region)
                return False

            # Check if any trail is multi-region and logging
            active_multiregion = False
            for trail in trails:
                if trail.get('IsMultiRegionTrail'):
                    status = cloudtrail.get_trail_status(Name=trail['Name'])
                    if status.get('IsLogging'):
                        active_multiregion = True
                        break

            if not active_multiregion:
                self.add_finding('HIGH', 'CloudTrail Not Multi-Region',
                               f'arn:aws:cloudtrail:{region}:{self.account_id}:trail/*',
                               'No multi-region trail actively logging',
                               'CIS 3.1', 6.5, region)
                return False

            return True
        except Exception as e:
            print(f"[WARNING]  Error checking CloudTrail in {region}: {e}")
            return None

    @security_check
    def check_cloudtrail_log_validation(self, region):
        """CIS 3.2 - Ensure CloudTrail log file validation is enabled"""
        cloudtrail = self.get_client('cloudtrail', region)
        try:
            trails = cloudtrail.describe_trails()['trailList']
            invalid_trails = [t['Name'] for t in trails if not t.get('LogFileValidationEnabled')]

            if invalid_trails:
                self.add_finding('MEDIUM', f'{len(invalid_trails)} CloudTrail Without Log Validation',
                               f'arn:aws:cloudtrail:{region}:{self.account_id}:trail/*',
                               f"Trails: {', '.join(invalid_trails[:3])}{'...' if len(invalid_trails) > 3 else ''}",
                               'CIS 3.2', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"[WARNING]  Error checking log validation in {region}: {e}")
            return None


# ============================================================================
# ATTACK MODE - Offensive security testing
# ============================================================================

class AttackMode(AWSAuditorBase):
    """Offensive security assessment mode"""

    def run(self):
        """Run attack mode checks"""
        print("\n" + "="*70)
        print("[WARNING]  AWS CLOUD SECURITY AUDITOR - ATTACK MODE")
        print("="*70)
        print(f"Account: {self.account_id}")
        print(f"Identity: {self.user_arn}")
        print(f"Regions: {', '.join(self.regions)}")
        print("="*70 + "\n")

        print("[ATTACK] Phase 1: IAM Privilege Escalation Paths")
        self._attack_iam()

        print("\n[ATTACK] Phase 2: S3 Data Exfiltration Vectors")
        self._attack_s3()

        print("\n[ATTACK] Phase 3: EC2 Lateral Movement")
        self._attack_ec2()

        print("\n[ATTACK] Phase 4: RDS Database Exposure")
        self._attack_rds()

        print("\n[ATTACK] Phase 5: EC2 Instance Metadata Attacks")
        self._attack_ec2_instances()

        print("\n[ATTACK] Phase 6: VPC Network Reconnaissance")
        self._attack_vpc()

        print("\n[ATTACK] Phase 7: EKS Cluster Compromise")
        self._attack_eks()

        print("\n[ATTACK] Phase 8: Secrets Manager Enumeration")
        self._attack_secrets()

        self._print_attack_summary()

    def _attack_iam(self):
        """Check IAM for privilege escalation paths"""
        print("  Checking root account compromise vectors...")
        self.check_root_mfa()
        self.check_root_access_keys()

        print("  Checking for weak authentication...")
        self.check_iam_password_policy()
        self.check_iam_user_mfa()

        print("  Checking for credential reuse opportunities...")
        self.check_old_access_keys()

        # Check for overly permissive policies
        print("  Checking for privilege escalation policies...")
        iam = self.get_client('iam')
        try:
            policies = self._paginate(iam, 'list_policies', 'Policies', Scope='Local')
            admin_policies = []

            for policy in policies:
                policy_arn = policy['Arn']
                version = iam.get_policy(PolicyArn=policy_arn)['Policy']['DefaultVersionId']
                policy_doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version)

                document = policy_doc['PolicyVersion']['Document']
                if isinstance(document.get('Statement'), list):
                    for statement in document['Statement']:
                        if statement.get('Effect') == 'Allow':
                            actions = statement.get('Action', [])
                            resources = statement.get('Resource', [])

                            if isinstance(actions, str):
                                actions = [actions]
                            if isinstance(resources, str):
                                resources = [resources]

                            if '*' in actions and '*' in resources:
                                admin_policies.append(policy['PolicyName'])

            if admin_policies:
                self.add_finding('HIGH', f'{len(admin_policies)} Admin Policies Found',
                               'arn:aws:iam::*:policy/*',
                               f"Potential privilege escalation via: {', '.join(admin_policies[:3])}",
                               '', 7.5)
                print(f"    [WARNING]  Found {len(admin_policies)} wildcard admin policies")
        except Exception as e:
            print(f"    [WARNING]  Error: {e}")

    def _attack_s3(self):
        """Check S3 for data exfiltration vectors"""
        print("  Checking for publicly accessible buckets...")
        self.check_s3_public_buckets()

        print("  Checking for unencrypted data stores...")
        self.check_s3_encryption()

        # Check for versioning (potential data recovery)
        print("  Checking for recoverable deleted objects...")
        s3 = self.get_client('s3')
        try:
            buckets = self._all_buckets()

            def check(bucket):
                bucket_name = bucket['Name']
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') == 'Enabled':
                        return bucket_name
                except Exception:
                    return None
                return None

            versioned = [b for b in self._parallel(check, buckets) if b]

            if versioned:
                print(f"    [INFO]  {len(versioned)} buckets with version history (potential data recovery)")
        except Exception as e:
            print(f"    [WARNING]  Error: {e}")

    def _attack_ec2(self):
        """Check EC2 for lateral movement vectors"""
        def scan(region):
            print(f"  Checking {region} for exploitable security groups...")
            self.check_security_groups(region)

            # Check for public AMIs
            print(f"  Checking {region} for public AMIs (information disclosure)...")
            ec2 = self.get_client('ec2', region)
            try:
                amis = ec2.describe_images(Owners=['self'])['Images']
                public_amis = [ami['ImageId'] for ami in amis if ami.get('Public')]

                if public_amis:
                    self.add_finding('HIGH', f'{len(public_amis)} Public AMIs in {region}',
                                   f'arn:aws:ec2:{region}:{self.account_id}:image/*',
                                   'Potential information disclosure via public AMI',
                                   '', 6.5, region)
                    print(f"    [WARNING]  Found {len(public_amis)} public AMIs")
            except Exception as e:
                print(f"    [WARNING]  Error: {e}")

        self._for_each_region(scan)

    def _attack_rds(self):
        """Check RDS for database compromise vectors"""
        def scan(region):
            print(f"  Checking {region} for exposed databases...")
            self.check_rds_public_access(region)
            self.check_rds_encryption(region)

        self._for_each_region(scan)

    def _attack_ec2_instances(self):
        """Check EC2 instances for IMDS attacks"""
        def scan(region):
            print(f"  Checking {region} for IMDSv1 vulnerability (SSRF exploitation)...")
            ec2 = self.get_client('ec2', region)
            try:
                reservations = self._paginate(ec2, 'describe_instances', 'Reservations')
                vulnerable_instances = []

                for reservation in reservations:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] == 'running':
                            metadata_options = instance.get('MetadataOptions', {})
                            if metadata_options.get('HttpTokens') != 'required':
                                vulnerable_instances.append(instance['InstanceId'])

                if vulnerable_instances:
                    self.add_finding('HIGH', f'{len(vulnerable_instances)} EC2 Instances Vulnerable to SSRF',
                                   f'arn:aws:ec2:{region}:{self.account_id}:instance/*',
                                   f"IMDSv1 allows SSRF-based credential theft: {', '.join(vulnerable_instances[:3])}",
                                   '', 7.5, region)
                    print(f"    [WARNING]  {len(vulnerable_instances)} instances vulnerable to SSRF attacks")
            except Exception as e:
                print(f"    [WARNING]  Error: {e}")

        self._for_each_region(scan)

    def _attack_vpc(self):
        """Check VPC for network reconnaissance"""
        def scan(region):
            print(f"  Checking {region} for network monitoring gaps...")
            ec2 = self.get_client('ec2', region)
            try:
                vpcs = self._describe_cached('ec2', region, 'describe_vpcs', 'Vpcs')
                no_flow_logs = []

                for vpc in vpcs:
                    vpc_id = vpc['VpcId']
                    flow_logs = self._paginate(ec2, 'describe_flow_logs', 'FlowLogs',
                                               Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])

                    if not flow_logs:
                        no_flow_logs.append(vpc_id)

                if no_flow_logs:
                    self.add_finding('MEDIUM', f'{len(no_flow_logs)} VPCs Without Flow Logs in {region}',
                                   f'arn:aws:ec2:{region}:{self.account_id}:vpc/*',
                                   'Network attacks undetectable without flow logs',
                                   'CIS 3.9', 6.0, region)
                    print(f"    [WARNING]  {len(no_flow_logs)} VPCs blind to network attacks")
            except Exception as e:
                print(f"    [WARNING]  Error: {e}")

        self._for_each_region(scan)

    def _attack_eks(self):
        """Check EKS for cluster compromise vectors"""
        def scan(region):
            print(f"  Checking {region} for publicly accessible K8s API...")
            eks = self.get_client('eks', region)
            try:
                clusters = self._paginate(eks, 'list_clusters', 'clusters')

                for cluster_name in clusters:
                    cluster = eks.describe_cluster(name=cluster_name)['cluster']
                    endpoint_config = cluster.get('resourcesVpcConfig', {})

                    if endpoint_config.get('endpointPublicAccess'):
                        public_cidrs = endpoint_config.get('publicAccessCidrs', [])
                        if '0.0.0.0/0' in public_cidrs:
                            self.add_finding('CRITICAL', f'EKS Cluster API Publicly Accessible: {cluster_name}',
                                           cluster['arn'],
                                           'Kubernetes API exposed to internet - brute force attacks possible',
                                           '', 8.6, region)
                            print(f"    [WARNING]  {cluster_name} API accessible from internet")
            except Exception as e:
                print(f"    [WARNING]  Error: {e}")

        self._for_each_region(scan)

    def _attack_secrets(self):
        """Check Secrets Manager for enumerable secrets"""
        def scan(region):
            print(f"  Checking {region} for accessible secrets...")
            secrets = self.get_client('secretsmanager', region)
            try:
                secret_list = self._paginate(secrets, 'list_secrets', 'SecretList')

                if secret_list:
                    print(f"    [INFO]  {len(secret_list)} secrets enumerable in region")

                    # Check for secrets without KMS
                    no_kms = [s['Name'] for s in secret_list if not s.get('KmsKeyId')]
                    if no_kms:
                        self.add_finding('MEDIUM', f'{len(no_kms)} Secrets Without KMS Encryption in {region}',
                                       f'arn:aws:secretsmanager:{region}:{self.account_id}:secret:*',
                                       'Secrets encrypted with default key instead of KMS',
                                       '', 5.0, region)
            except Exception as e:
                print(f"    [WARNING]  Error: {e}")

        self._for_each_region(scan)

    def _print_attack_summary(self):
        """Print attack mode summary"""
        print("\n" + "="*70)
        print("ATTACK SUMMARY")
        print("="*70)

        severity_counts = {}
        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print(f"\nFindings: {len(self.findings)} potential attack vectors")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                print(f"  {severity}: {severity_counts[severity]}")

        # Save attack report (honor --output when provided)
        output_file = self.output_file or f'aws_attack_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(output_file, 'w') as f:
            json.dump(self.findings, f, indent=2, default=str)

        print(f"\n[OK] Attack report saved: {output_file}")
        print("="*70 + "\n")


# ============================================================================
# COMPLIANCE MODE - CIS AWS Foundations Benchmark
# ============================================================================

class ComplianceMode(AWSAuditorBase):
    """CIS AWS Foundations Benchmark compliance audit"""

    def run(self):
        """Run compliance mode checks"""
        print("\n" + "="*70)
        print("AWS CLOUD SECURITY AUDITOR - COMPLIANCE MODE")
        print("CIS AWS Foundations Benchmark v1.5.0")
        print("="*70)
        print(f"Account: {self.account_id}")
        print(f"Identity: {self.user_arn}")
        print(f"Regions: {', '.join(self.regions)}")
        print("="*70 + "\n")

        self._cis_section_1_iam()
        self._cis_section_2_storage()
        self._cis_section_3_logging()
        self._cis_section_4_monitoring()
        self._cis_section_5_networking()
        self._additional_compliance_checks()

        self._print_compliance_summary()

    def _cis_section_1_iam(self):
        """CIS Section 1 - Identity and Access Management"""
        print("="*70)
        print("CIS SECTION 1: IDENTITY AND ACCESS MANAGEMENT")
        print("="*70)

        print("\n[CIS 1.4] Root account access keys...")
        self.check_root_access_keys()

        print("[CIS 1.5] Root account MFA...")
        self.check_root_mfa()

        print("[CIS 1.8-1.11] IAM password policy...")
        self.check_iam_password_policy()

        print("[CIS 1.10] IAM user MFA...")
        self.check_iam_user_mfa()

        print("[CIS 1.3] Access key rotation...")
        self.check_old_access_keys()

        # Additional IAM checks
        print("[CIS 1.12] IAM Access Analyzer...")
        self._check_iam_access_analyzer()

        print("[CIS 1.12] Unused credentials...")
        self._check_unused_credentials()

        print("[Best Practice] Unused IAM roles...")
        self._check_unused_roles()

        print("[Best Practice] Role trust policies...")
        self._check_role_trust_policies()

    def _cis_section_2_storage(self):
        """CIS Section 2 - Storage"""
        print("\n" + "="*70)
        print("CIS SECTION 2: STORAGE")
        print("="*70)

        print("\n[CIS 2.1.1] S3 bucket encryption...")
        self.check_s3_encryption()

        print("[CIS 2.1.5] S3 public access...")
        self.check_s3_public_buckets()

        print("[CIS 2.1.3] S3 versioning...")
        self._check_s3_versioning()

        # RDS + EBS checks (per region, run concurrently across regions)
        def scan(region):
            print(f"\n[CIS 2.3.1] RDS public access in {region}...")
            self.check_rds_public_access(region)

            print(f"[CIS 2.3.2] RDS encryption in {region}...")
            self.check_rds_encryption(region)

            print(f"[CIS 2.3.3] RDS backups in {region}...")
            self._check_rds_backups(region)

            print(f"[CIS 2.2.1] EBS encryption in {region}...")
            self._check_ebs_encryption(region)

            print(f"[Best Practice] Unattached EBS volumes in {region}...")
            self._check_unused_ebs_volumes(region)

            print(f"[Best Practice] EBS snapshot encryption in {region}...")
            self._check_ebs_snapshot_encryption(region)

            print(f"[Best Practice] RDS snapshot encryption in {region}...")
            self._check_rds_snapshot_encryption(region)

            print(f"[Best Practice] RDS Multi-AZ in {region}...")
            self._check_rds_multi_az(region)

        self._for_each_region(scan)

    def _cis_section_3_logging(self):
        """CIS Section 3 - Logging"""
        print("\n" + "="*70)
        print("CIS SECTION 3: LOGGING")
        print("="*70)

        def scan(region):
            print(f"\n[CIS 3.1] CloudTrail enabled in {region}...")
            self.check_cloudtrail_enabled(region)

            print(f"[CIS 3.2] CloudTrail log validation in {region}...")
            self.check_cloudtrail_log_validation(region)

            print(f"[CIS 3.7] CloudTrail KMS encryption in {region}...")
            self._check_cloudtrail_kms(region)

            print(f"[CIS 3.9] VPC Flow Logs in {region}...")
            self._check_vpc_flow_logs(region)

            print(f"[Best Practice] Log retention in {region}...")
            self._check_log_retention(region)

        self._for_each_region(scan)

    def _cis_section_4_monitoring(self):
        """CIS Section 4 - Monitoring"""
        print("\n" + "="*70)
        print("CIS SECTION 4: MONITORING")
        print("="*70)

        def scan(region):
            print(f"\n[Best Practice] GuardDuty in {region}...")
            self._check_guardduty(region)

            print(f"[Best Practice] AWS Config in {region}...")
            self._check_aws_config(region)

            print(f"[Best Practice] CloudWatch alarms in {region}...")
            self._check_cloudwatch_alarms(region)

            print(f"[Best Practice] Amazon Inspector in {region}...")
            self._check_inspector(region)

            print(f"[Best Practice] Patch management (SSM) in {region}...")
            self._check_patch_management(region)

        self._for_each_region(scan)

    def _cis_section_5_networking(self):
        """CIS Section 5 - Networking"""
        print("\n" + "="*70)
        print("CIS SECTION 5: NETWORKING")
        print("="*70)

        def scan(region):
            print(f"\n[CIS 5.2] Security groups in {region}...")
            self.check_security_groups(region)

            print(f"[CIS 5.1] Default VPC in {region}...")
            self._check_default_vpc(region)

            print(f"[Best Practice] Network ACLs in {region}...")
            self._check_nacls(region)

            print(f"[Best Practice] VPN connections in {region}...")
            self._check_vpn_connections(region)

        self._for_each_region(scan)

    def _additional_compliance_checks(self):
        """Additional security best practices"""
        print("\n" + "="*70)
        print("ADDITIONAL SECURITY BEST PRACTICES")
        print("="*70)

        def scan(region):
            print(f"\n[Best Practice] Lambda security in {region}...")
            self._check_lambda_security(region)

            print(f"[Best Practice] ELB security in {region}...")
            self._check_elb_security(region)

            print(f"[Best Practice] KMS key rotation in {region}...")
            self._check_kms_rotation(region)

            print(f"[Best Practice] KMS key policy in {region}...")
            self._check_kms_key_policy(region)

            print(f"[Best Practice] ECR image scanning in {region}...")
            self._check_ecr_image_scanning(region)

        self._for_each_region(scan)

    # ========================================================================
    # Additional compliance check implementations
    # ========================================================================

    @security_check
    def _check_iam_access_analyzer(self):
        """Check if IAM Access Analyzer is enabled"""
        missing = []

        def scan(region):
            analyzer = self.get_client('accessanalyzer', region)
            try:
                analyzers = self._paginate(analyzer, 'list_analyzers', 'analyzers')
                active = [a for a in analyzers if a['status'] == 'ACTIVE']

                if not active:
                    self.add_finding('HIGH', 'IAM Access Analyzer Not Enabled',
                                   f'arn:aws:accessanalyzer:{region}:{self.account_id}:analyzer/*',
                                   'External access analysis disabled',
                                   'CIS 1.12', 6.0, region)
                    with self.lock:
                        missing.append(region)
                    print(f"  [ERROR] No active analyzer in {region}")
            except Exception as e:
                print(f"  [WARNING]  Error in {region}: {e}")

        self._for_each_region(scan)
        return len(missing) == 0

    @security_check
    def _check_unused_credentials(self):
        """Check for unused IAM credentials"""
        iam = self.get_client('iam')
        try:
            rows = self._get_cred_report()

            def check(user_data):
                if user_data['user'] != '<root_account>':
                    password_last_used = user_data.get('password_last_used')
                    if password_last_used == 'N/A' or password_last_used == 'no_information':
                        # Check if user has any access keys
                        try:
                            keys = self._paginate(iam, 'list_access_keys', 'AccessKeyMetadata',
                                                  UserName=user_data['user'])
                        except Exception:
                            return None
                        if not keys:
                            return user_data['user']
                return None

            unused = [u for u in self._parallel(check, rows) if u]

            if unused:
                self.add_finding('LOW', f'{len(unused)} Unused IAM Users',
                               f'arn:aws:iam::{self.account_id}:user/*',
                               f"Users with no credentials: {', '.join(unused[:5])}",
                               'CIS 1.12', 3.0)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_s3_versioning(self):
        """Check S3 versioning is enabled"""
        s3 = self.get_client('s3')
        try:
            buckets = self._all_buckets()

            def check(bucket):
                bucket_name = bucket['Name']
                try:
                    versioning = s3.get_bucket_versioning(Bucket=bucket_name)
                    if versioning.get('Status') != 'Enabled':
                        return bucket_name
                except Exception:
                    return None
                return None

            no_versioning = [b for b in self._parallel(check, buckets) if b]

            if no_versioning:
                self.add_finding('LOW', f'{len(no_versioning)} S3 Buckets Without Versioning',
                               'arn:aws:s3:::*',
                               f"Buckets: {', '.join(no_versioning[:5])}",
                               'CIS 2.1.3', 3.0)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_rds_backups(self, region):
        """Check RDS automated backups"""
        rds = self.get_client('rds', region)
        try:
            instances = self._describe_cached('rds', region, 'describe_db_instances', 'DBInstances')
            no_backups = [db['DBInstanceIdentifier'] for db in instances
                         if db.get('BackupRetentionPeriod', 0) < 7]

            if no_backups:
                self.add_finding('MEDIUM', f'{len(no_backups)} RDS Without Adequate Backups',
                               f'arn:aws:rds:{region}:{self.account_id}:db:*',
                               f"Databases: {', '.join(no_backups[:5])}",
                               'CIS 2.3.3', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_ebs_encryption(self, region):
        """Check EBS volume encryption"""
        ec2 = self.get_client('ec2', region)
        try:
            volumes = self._paginate(ec2, 'describe_volumes', 'Volumes')
            unencrypted = [v['VolumeId'] for v in volumes if not v.get('Encrypted')]

            if unencrypted:
                self.add_finding('MEDIUM', f'{len(unencrypted)} Unencrypted EBS Volumes',
                               f'arn:aws:ec2:{region}:{self.account_id}:volume/*',
                               f"Volumes: {', '.join(unencrypted[:5])}",
                               'CIS 2.2.1', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_cloudtrail_kms(self, region):
        """Check CloudTrail KMS encryption"""
        cloudtrail = self.get_client('cloudtrail', region)
        try:
            trails = cloudtrail.describe_trails()['trailList']
            no_kms = [t['Name'] for t in trails if not t.get('KmsKeyId')]

            if no_kms:
                self.add_finding('MEDIUM', f'{len(no_kms)} CloudTrail Without KMS',
                               f'arn:aws:cloudtrail:{region}:{self.account_id}:trail/*',
                               f"Trails: {', '.join(no_kms[:3])}",
                               'CIS 3.7', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_vpc_flow_logs(self, region):
        """Check VPC Flow Logs"""
        ec2 = self.get_client('ec2', region)
        try:
            vpcs = self._describe_cached('ec2', region, 'describe_vpcs', 'Vpcs')
            no_logs = []

            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                flow_logs = self._paginate(ec2, 'describe_flow_logs', 'FlowLogs',
                                           Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}])

                if not flow_logs:
                    no_logs.append(vpc_id)

            if no_logs:
                self.add_finding('MEDIUM', f'{len(no_logs)} VPCs Without Flow Logs',
                               f'arn:aws:ec2:{region}:{self.account_id}:vpc/*',
                               f"VPCs: {', '.join(no_logs[:3])}",
                               'CIS 3.9', 6.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_guardduty(self, region):
        """Check GuardDuty status"""
        guardduty = self.get_client('guardduty', region)
        try:
            detectors = self._paginate(guardduty, 'list_detectors', 'DetectorIds')

            if not detectors:
                self.add_finding('HIGH', 'GuardDuty Not Enabled',
                               f'arn:aws:guardduty:{region}:{self.account_id}:detector/*',
                               'Threat detection disabled',
                               '', 6.5, region)
                return False
            else:
                enabled = True
                for detector_id in detectors:
                    detector = guardduty.get_detector(DetectorId=detector_id)
                    if detector['Status'] != 'ENABLED':
                        self.add_finding('HIGH', 'GuardDuty Detector Not Active',
                                       f'arn:aws:guardduty:{region}:{self.account_id}:detector/{detector_id}',
                                       f"Status: {detector['Status']}",
                                       '', 6.5, region)
                        enabled = False
                return enabled
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_aws_config(self, region):
        """Check AWS Config status"""
        config = self.get_client('config', region)
        try:
            recorders = config.describe_configuration_recorders()['ConfigurationRecorders']

            if not recorders:
                self.add_finding('HIGH', 'AWS Config Not Enabled',
                               f'arn:aws:config:{region}:{self.account_id}:*',
                               'Configuration compliance tracking disabled',
                               '', 6.0, region)
                return False
            else:
                status = config.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
                recording = True
                for recorder in status:
                    if not recorder.get('recording'):
                        self.add_finding('MEDIUM', 'AWS Config Not Recording',
                                       f'arn:aws:config:{region}:{self.account_id}:configuration-recorder/{recorder["name"]}',
                                       'Configuration changes not being recorded',
                                       '', 5.0, region)
                        recording = False
                return recording
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_default_vpc(self, region):
        """Check for default VPC usage"""
        ec2 = self.get_client('ec2', region)
        try:
            vpcs = self._describe_cached('ec2', region, 'describe_vpcs', 'Vpcs')
            default_vpcs = [v['VpcId'] for v in vpcs if v.get('IsDefault')]

            if default_vpcs:
                # Check if resources are actually using it
                reservations = self._paginate(ec2, 'describe_instances', 'Reservations')
                default_vpc_instances = []

                for reservation in reservations:
                    for instance in reservation['Instances']:
                        if instance.get('VpcId') in default_vpcs and instance['State']['Name'] == 'running':
                            default_vpc_instances.append(instance['InstanceId'])

                if default_vpc_instances:
                    self.add_finding('MEDIUM', 'Default VPC In Use',
                                   f'arn:aws:ec2:{region}:{self.account_id}:vpc/*',
                                   f"{len(default_vpc_instances)} resources using default VPC",
                                   'CIS 5.1', 5.0, region)
                    return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_lambda_security(self, region):
        """Check Lambda function security"""
        lambda_client = self.get_client('lambda', region)
        try:
            functions = self._paginate(lambda_client, 'list_functions', 'Functions')

            # Check for public functions
            public = []
            for func in functions:
                try:
                    policy = lambda_client.get_policy(FunctionName=func['FunctionName'])
                    policy_doc = json.loads(policy['Policy'])

                    for statement in policy_doc.get('Statement', []):
                        if statement.get('Effect') == 'Allow' and statement.get('Principal') == '*':
                            if 'Condition' not in statement:
                                public.append(func['FunctionName'])
                except Exception:
                    pass

            if public:
                self.add_finding('CRITICAL', f'{len(public)} Lambda Functions Publicly Accessible',
                               f'arn:aws:lambda:{region}:{self.account_id}:function:*',
                               f"Functions: {', '.join(public[:3])}",
                               '', 8.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_elb_security(self, region):
        """Check ELB/ALB security"""
        elbv2 = self.get_client('elbv2', region)
        try:
            lbs = self._paginate(elbv2, 'describe_load_balancers', 'LoadBalancers')
            insecure = False

            for lb in lbs:
                lb_arn = lb['LoadBalancerArn']

                # Check for HTTP listeners
                listeners = self._paginate(elbv2, 'describe_listeners', 'Listeners', LoadBalancerArn=lb_arn)
                http = [l for l in listeners if l['Protocol'] == 'HTTP']

                if http:
                    self.add_finding('MEDIUM', f'Load Balancer Using HTTP: {lb["LoadBalancerName"]}',
                                   lb_arn,
                                   'Unencrypted traffic on HTTP listener',
                                   '', 5.0, region)
                    insecure = True

            return not insecure
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_kms_rotation(self, region):
        """Check KMS key rotation"""
        kms = self.get_client('kms', region)
        try:
            keys = self._describe_cached('kms', region, 'list_keys', 'Keys')
            no_rotation = []

            for key in keys:
                try:
                    key_metadata = kms.describe_key(KeyId=key['KeyId'])
                    if key_metadata['KeyMetadata']['KeyManager'] == 'CUSTOMER':
                        rotation = kms.get_key_rotation_status(KeyId=key['KeyId'])
                        if not rotation['KeyRotationEnabled']:
                            no_rotation.append(key['KeyId'])
                except Exception:
                    pass

            if no_rotation:
                self.add_finding('MEDIUM', f'{len(no_rotation)} KMS Keys Without Rotation',
                               f'arn:aws:kms:{region}:{self.account_id}:key/*',
                               'Automatic key rotation disabled',
                               '', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_unused_roles(self):
        """Check for IAM roles unused for more than 90 days"""
        iam = self.get_client('iam')
        try:
            roles = self._paginate(iam, 'list_roles', 'Roles')
            stale = []
            for r in roles:
                if r.get('Path', '').startswith('/aws-service-role/'):
                    continue
                last_used = r.get('RoleLastUsed', {}).get('LastUsedDate')
                if last_used is None:
                    stale.append(r['RoleName'])
                elif (datetime.now(last_used.tzinfo) - last_used).days > 90:
                    stale.append(r['RoleName'])

            if stale:
                self.add_finding('LOW', f'{len(stale)} IAM Roles Unused >90 Days',
                               f'arn:aws:iam::{self.account_id}:role/*',
                               f"Roles: {', '.join(stale[:5])}{'...' if len(stale) > 5 else ''}",
                               'CIS 1.12', 3.0)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_role_trust_policies(self):
        """Check for IAM role trust policies assumable by any principal"""
        iam = self.get_client('iam')
        try:
            roles = self._paginate(iam, 'list_roles', 'Roles')
            risky = []
            for r in roles:
                if r.get('Path', '').startswith('/aws-service-role/'):
                    continue
                doc = r.get('AssumeRolePolicyDocument')
                if isinstance(doc, str):
                    from urllib.parse import unquote
                    doc = json.loads(unquote(doc))
                if not isinstance(doc, dict):
                    continue
                statements = doc.get('Statement', [])
                if isinstance(statements, dict):
                    statements = [statements]
                for st in statements:
                    if st.get('Effect') != 'Allow':
                        continue
                    principal = st.get('Principal', {})
                    if principal == '*':
                        values = ['*']
                    else:
                        aws = principal.get('AWS') if isinstance(principal, dict) else None
                        values = [aws] if isinstance(aws, str) else (aws or [])
                    if any(v == '*' for v in values) and 'Condition' not in st:
                        risky.append(r['RoleName'])
                        break

            if risky:
                self.add_finding('HIGH', f'{len(risky)} IAM Roles With Wildcard Trust Policy',
                               f'arn:aws:iam::{self.account_id}:role/*',
                               f"Assumable by any principal without conditions: {', '.join(risky[:5])}",
                               '', 7.5)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_unused_ebs_volumes(self, region):
        """Check for unattached (available) EBS volumes"""
        ec2 = self.get_client('ec2', region)
        try:
            volumes = self._paginate(ec2, 'describe_volumes', 'Volumes',
                                     Filters=[{'Name': 'status', 'Values': ['available']}])
            ids = [v['VolumeId'] for v in volumes]
            if ids:
                self.add_finding('LOW', f'{len(ids)} Unattached EBS Volumes',
                               f'arn:aws:ec2:{region}:{self.account_id}:volume/*',
                               f"Volumes: {', '.join(ids[:5])}{'...' if len(ids) > 5 else ''}",
                               '', 2.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_ebs_snapshot_encryption(self, region):
        """Check owned EBS snapshots are encrypted"""
        ec2 = self.get_client('ec2', region)
        try:
            snaps = self._paginate(ec2, 'describe_snapshots', 'Snapshots', OwnerIds=['self'])
            unencrypted = [s['SnapshotId'] for s in snaps if not s.get('Encrypted')]
            if unencrypted:
                self.add_finding('MEDIUM', f'{len(unencrypted)} Unencrypted EBS Snapshots',
                               f'arn:aws:ec2:{region}:{self.account_id}:snapshot/*',
                               f"Snapshots: {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}",
                               '', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_rds_snapshot_encryption(self, region):
        """Check RDS snapshots are encrypted"""
        rds = self.get_client('rds', region)
        try:
            snaps = self._paginate(rds, 'describe_db_snapshots', 'DBSnapshots')
            unencrypted = [s['DBSnapshotIdentifier'] for s in snaps if not s.get('Encrypted')]
            if unencrypted:
                self.add_finding('MEDIUM', f'{len(unencrypted)} Unencrypted RDS Snapshots',
                               f'arn:aws:rds:{region}:{self.account_id}:snapshot:*',
                               f"Snapshots: {', '.join(unencrypted[:5])}{'...' if len(unencrypted) > 5 else ''}",
                               '', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_rds_multi_az(self, region):
        """Check RDS instances have Multi-AZ high availability"""
        rds = self.get_client('rds', region)
        try:
            instances = self._describe_cached('rds', region, 'describe_db_instances', 'DBInstances')
            single = [db['DBInstanceIdentifier'] for db in instances if not db.get('MultiAZ')]
            if single:
                self.add_finding('LOW', f'{len(single)} RDS Instances Without Multi-AZ',
                               f'arn:aws:rds:{region}:{self.account_id}:db:*',
                               f"No failover across AZs: {', '.join(single[:5])}{'...' if len(single) > 5 else ''}",
                               '', 3.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_log_retention(self, region):
        """Check CloudWatch log groups have a retention policy"""
        logs = self.get_client('logs', region)
        try:
            groups = self._paginate(logs, 'describe_log_groups', 'logGroups')
            no_retention = [g['logGroupName'] for g in groups if not g.get('retentionInDays')]
            if no_retention:
                self.add_finding('LOW', f'{len(no_retention)} Log Groups Without Retention',
                               f'arn:aws:logs:{region}:{self.account_id}:log-group:*',
                               f"Never-expiring: {', '.join(no_retention[:5])}{'...' if len(no_retention) > 5 else ''}",
                               '', 2.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_cloudwatch_alarms(self, region):
        """Check that CloudWatch alarms exist for alerting on critical events"""
        cw = self.get_client('cloudwatch', region)
        try:
            alarms = self._paginate(cw, 'describe_alarms', 'MetricAlarms')
            if not alarms:
                self.add_finding('LOW', 'No CloudWatch Alarms Configured',
                               f'arn:aws:cloudwatch:{region}:{self.account_id}:alarm:*',
                               'No metric alarms to alert on critical events',
                               '', 3.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_inspector(self, region):
        """Check Amazon Inspector vulnerability scanning is enabled"""
        inspector = self.get_client('inspector2', region)
        try:
            resp = inspector.batch_get_account_status(accountIds=[self.account_id])
            disabled = []
            for acct in resp.get('accounts', []):
                state = acct.get('resourceState', {})
                for res in ('ec2', 'ecr', 'lambda'):
                    status = state.get(res, {}).get('status')
                    if status and status != 'ENABLED':
                        disabled.append(res)
            if disabled:
                self.add_finding('MEDIUM', 'Amazon Inspector Not Fully Enabled',
                               f'arn:aws:inspector2:{region}:{self.account_id}:*',
                               f"Vulnerability scanning disabled for: {', '.join(sorted(set(disabled)))}",
                               '', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_patch_management(self, region):
        """Check running EC2 instances are managed by SSM (patchable)"""
        ec2 = self.get_client('ec2', region)
        ssm = self.get_client('ssm', region)
        try:
            reservations = self._paginate(ec2, 'describe_instances', 'Reservations',
                                          Filters=[{'Name': 'instance-state-name', 'Values': ['running']}])
            running = [i['InstanceId'] for r in reservations for i in r['Instances']]
            if not running:
                return True
            managed = {m.get('InstanceId') for m in
                       self._paginate(ssm, 'describe_instance_information', 'InstanceInformationList')}
            unmanaged = [i for i in running if i not in managed]
            if unmanaged:
                self.add_finding('MEDIUM', f'{len(unmanaged)} EC2 Instances Not Managed by SSM',
                               f'arn:aws:ec2:{region}:{self.account_id}:instance/*',
                               f"Patch state unverifiable (no SSM agent): {', '.join(unmanaged[:5])}{'...' if len(unmanaged) > 5 else ''}",
                               '', 4.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_nacls(self, region):
        """Check non-default Network ACLs do not allow all inbound from anywhere"""
        ec2 = self.get_client('ec2', region)
        try:
            nacls = self._paginate(ec2, 'describe_network_acls', 'NetworkAcls')
            risky = []
            for n in nacls:
                if n.get('IsDefault'):
                    continue
                for entry in n.get('Entries', []):
                    if entry.get('Egress'):
                        continue
                    if (entry.get('RuleAction') == 'allow'
                            and entry.get('CidrBlock') == '0.0.0.0/0'
                            and entry.get('Protocol') == '-1'):
                        risky.append(n['NetworkAclId'])
                        break
            if risky:
                self.add_finding('MEDIUM', f'{len(risky)} Network ACLs Allow All Inbound',
                               f'arn:aws:ec2:{region}:{self.account_id}:network-acl/*',
                               f"NACLs: {', '.join(risky[:5])}",
                               '', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_vpn_connections(self, region):
        """Check Site-to-Site VPN connections have both tunnels up"""
        ec2 = self.get_client('ec2', region)
        try:
            conns = ec2.describe_vpn_connections().get('VpnConnections', [])
            down = []
            for c in conns:
                if c.get('State') == 'deleted':
                    continue
                if any(t.get('Status') != 'UP' for t in c.get('VgwTelemetry', [])):
                    down.append(c['VpnConnectionId'])
            if down:
                self.add_finding('MEDIUM', f'{len(down)} VPN Connections With Tunnel Down',
                               f'arn:aws:ec2:{region}:{self.account_id}:vpn-connection/*',
                               f"VPNs: {', '.join(down[:5])}",
                               '', 4.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_kms_key_policy(self, region):
        """Check customer KMS key policies do not grant access to any principal"""
        kms = self.get_client('kms', region)
        try:
            keys = self._describe_cached('kms', region, 'list_keys', 'Keys')
            risky = []
            for key in keys:
                try:
                    meta = kms.describe_key(KeyId=key['KeyId'])['KeyMetadata']
                    if meta.get('KeyManager') != 'CUSTOMER':
                        continue
                    policy = json.loads(kms.get_key_policy(KeyId=key['KeyId'], PolicyName='default')['Policy'])
                    for st in policy.get('Statement', []):
                        if st.get('Effect') != 'Allow':
                            continue
                        principal = st.get('Principal', {})
                        aws = principal.get('AWS') if isinstance(principal, dict) else principal
                        values = [aws] if isinstance(aws, str) else (aws or [])
                        if any(v == '*' for v in values) and 'Condition' not in st:
                            risky.append(key['KeyId'])
                            break
                except Exception:
                    pass
            if risky:
                self.add_finding('HIGH', f'{len(risky)} KMS Keys With Wildcard Policy',
                               f'arn:aws:kms:{region}:{self.account_id}:key/*',
                               f"Usable by any principal without conditions: {', '.join(risky[:5])}",
                               '', 7.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    @security_check
    def _check_ecr_image_scanning(self, region):
        """Check ECR repositories have scan-on-push enabled"""
        ecr = self.get_client('ecr', region)
        try:
            repos = self._paginate(ecr, 'describe_repositories', 'repositories')
            no_scan = [r['repositoryName'] for r in repos
                       if not r.get('imageScanningConfiguration', {}).get('scanOnPush')]
            if no_scan:
                self.add_finding('MEDIUM', f'{len(no_scan)} ECR Repos Without Scan-on-Push',
                               f'arn:aws:ecr:{region}:{self.account_id}:repository/*',
                               f"Images not scanned for vulnerabilities: {', '.join(no_scan[:5])}{'...' if len(no_scan) > 5 else ''}",
                               '', 5.0, region)
                return False
            return True
        except Exception as e:
            print(f"  [WARNING]  Error: {e}")
            return None

    def _print_compliance_summary(self):
        """Print compliance summary"""
        print("\n" + "="*70)
        print("COMPLIANCE SUMMARY")
        print("="*70)

        # Count by severity
        severity_counts = {}
        cis_controls = set()

        for finding in self.findings:
            severity = finding['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

            if finding.get('cis_control'):
                cis_controls.add(finding['cis_control'])

        print(f"\nTotal Findings: {len(self.findings)}")
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                print(f"  {severity}: {severity_counts[severity]}")

        print(f"\nCIS Controls Affected: {len(cis_controls)}")

        # Calculate compliance score from actual checks executed
        # (passed vs failed; checks that errored out are excluded from the ratio)
        evaluated = self.checks_passed + self.checks_failed
        compliance_score = (self.checks_passed / evaluated * 100) if evaluated else 100.0

        print(f"\nChecks Passed:  {self.checks_passed}")
        print(f"Checks Failed:  {self.checks_failed}")
        if self.checks_error:
            print(f"Checks Errored: {self.checks_error} (excluded from score)")
        print(f"\nCompliance Score: {compliance_score:.1f}%")

        # Save compliance report (honor --output when provided)
        output_file = self.output_file or f'aws_compliance_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
        with open(output_file, 'w') as f:
            json.dump({
                'account_id': self.account_id,
                'scan_date': datetime.now().isoformat(),
                'compliance_score': compliance_score,
                'checks_passed': self.checks_passed,
                'checks_failed': self.checks_failed,
                'checks_errored': self.checks_error,
                'findings': self.findings
            }, f, indent=2, default=str)

        print(f"\n[OK] Compliance report saved: {output_file}")
        print("="*70 + "\n")


# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='AWS Cloud Security Auditor - Dual-mode security assessment',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Compliance mode (default) - CIS Benchmark audit
  python aws_auditor.py --mode compliance --profile readonly --region us-east-2

  # Attack mode - Offensive security testing (requires authorization)
  python aws_auditor.py --mode attack --profile pentest --all-regions

  # Multi-region compliance scan
  python aws_auditor.py --regions us-east-1,us-west-2,eu-west-1

  # All regions scan
  python aws_auditor.py --all-regions

  # Behind an intercepting TLS proxy (disables cert verification)
  python aws_auditor.py --all-regions --insecure

[WARNING]  ATTACK MODE WARNING:
  Only use attack mode with proper written authorization.
  Unauthorized security testing may violate laws and policies.
        """
    )

    parser.add_argument('--mode', choices=['attack', 'compliance'], default='compliance',
                       help='Scan mode: attack (offensive) or compliance (CIS audit)')
    parser.add_argument('--profile', help='AWS profile name')
    parser.add_argument('--region', help='Single AWS region (default: us-east-2)')
    parser.add_argument('--regions', help='Comma-separated list of regions')
    parser.add_argument('--all-regions', action='store_true', help='Scan all AWS regions')
    parser.add_argument('--output', help='Output file path')
    parser.add_argument('--workers', type=int, default=20,
                       help='Parallel workers for multi-region/multi-resource scans (default: 20)')
    parser.add_argument('--insecure', action='store_true',
                       help='Disable TLS verification (only for corporate/intercepting proxies)')

    args = parser.parse_args()

    # Parse regions
    regions = None
    if args.regions:
        regions = [r.strip() for r in args.regions.split(',')]
    elif args.region:
        regions = [args.region]

    common_kwargs = dict(
        profile_name=args.profile,
        regions=regions,
        all_regions=args.all_regions,
        verify_tls=not args.insecure,
        max_workers=args.workers,
        output=args.output,
    )

    # Attack mode confirmation
    if args.mode == 'attack':
        print("\n" + "="*70)
        print("[WARNING]  ATTACK MODE WARNING")
        print("="*70)
        print("You are about to run OFFENSIVE security tests.")
        print("This mode performs active exploitation testing including:")
        print("  • Privilege escalation path identification")
        print("  • Data exfiltration vector analysis")
        print("  • Lateral movement opportunity enumeration")
        print("  • SSRF and IMDS exploitation checks")
        print("\n[WARNING]  USE ONLY WITH WRITTEN AUTHORIZATION")
        print("="*70 + "\n")

        confirm = input("Type 'YES' to confirm authorization: ")
        if confirm != 'YES':
            print("Attack mode cancelled.")
            sys.exit(0)

        auditor = AttackMode(**common_kwargs)
        auditor.run()

    else:  # Compliance mode
        auditor = ComplianceMode(**common_kwargs)
        auditor.run()


if __name__ == '__main__':
    main()
