import json
import os
import time
from datetime import datetime, timedelta, timezone
import boto3

# Cache S3 config to avoid repeated API calls
config_cache = None
config_last_modified = None

# AWS clients
s3 = boto3.client("s3")
sts = boto3.client("sts")
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

# Load environment variables
BUCKET_NAME = os.environ["BUCKET_NAME"]
CONFIG_KEY = os.environ["CONFIG_KEY"]
DYNAMODB_TABLE_NAME = os.environ["DYNAMODB_TABLE_NAME"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

# Load S3 config
def load_config():
    global config_cache, config_last_modified
    try:
        response = s3.head_object(Bucket=BUCKET_NAME, Key=CONFIG_KEY)
        last_modified = response["LastModified"]

        if config_cache is None or last_modified != config_last_modified:
            print("Fetching config from S3...")
            obj = s3.get_object(Bucket=BUCKET_NAME, Key=CONFIG_KEY)
            config_cache = json.loads(obj["Body"].read())
            config_last_modified = last_modified
        return config_cache
    except Exception as e:
        print("Unable to load config from S3")
        print(f"Reason: {str(e)}")
        raise


# Load previous DB snapshot
def get_previous_snapshot_from_db(ipset_id):
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        response = table.get_item(Key={"ipset_id": ipset_id})

        if "Item" in response:
            return set(response["Item"].get("managed_ips", []))
        return set()
    except Exception as e:
        print("DB read failed, defaulting to empty history")
        print(f"Reason: {str(e)}")
        return set()


# Update new DB snapshot
def update_db_snapshot(ipset_id, current_ips_list, username):
    try:
        table = dynamodb.Table(DYNAMODB_TABLE_NAME)
        ist_time = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S IST")

        table.put_item(
            Item={
                "ipset_id": ipset_id,
                "managed_ips": current_ips_list,
                "last_updated_by": username,
                "last_updated_time": ist_time,
            }
        )
        print(f"DynamoDB record for {ipset_id} updated successfully")
    except Exception as e:
        print("Unable to update DynamoDB record")
        print(f"Reason: {str(e)}")
        raise


# Lambda function handler
def lambda_handler(event, context):
    try:
        print("Lambda execution started")

        detail = event.get("detail")
        request_params = detail.get("requestParameters") if detail else None

        if not detail or not request_params or "addresses" not in request_params:
            print("Invalid event detected, skipping execution")
            return

        current_ipset_id = request_params.get("id")
        current_ipset_name = request_params.get("name", "Unknown-IPSet")

        # DynamoDB partition key
        ipset_id = f"{current_ipset_name}_{current_ipset_id}"

        # Raw list from event payload
        source_ips_list = request_params.get("addresses", [])

        # Tracking skipped IPs by identifying duplicate entries in payload
        non_skipped_ips = set()
        skipped_ips = set()
        for ip in source_ips_list:
            if ip in non_skipped_ips:
                skipped_ips.add(ip)
            else:
                non_skipped_ips.add(ip)

        # IP addresses de-duplication
        source_ips_set = set(source_ips_list)

        # Initializing S3 config & Previous DB snapshot
        config = load_config()
        previous_source_ips_set = get_previous_snapshot_from_db(ipset_id)

        # Track new IPs to append and explicitly deleted IPs from console
        attempted_ips = source_ips_set - previous_source_ips_set
        removed_ips = previous_source_ips_set - source_ips_set

        # Active IPs targeted for sync evaluation
        all_active_ips = attempted_ips.union(
            source_ips_set.intersection(previous_source_ips_set)
        )

        print(f"Skipped IPs: {sorted(list(skipped_ips)) if skipped_ips else 'None'}")
        print(f"New IPs: {sorted(list(attempted_ips)) if attempted_ips else 'None'}")
        print(f"Removed IPs: {sorted(list(removed_ips)) if removed_ips else 'None'}")

        # Cross account assumption
        print("Assuming cross-account roles across target accounts for IP set synchronization...")
        synced_accounts, skipped_accounts, failed_accounts = [], [], []

        for account in config["accounts"]:
            account_id = account["account_id"]
            account_name = account.get("account_name", "unknown")
            role_arn = account["role_arn"]
            target_ipset_id = account["ipset_id"]
            target_ipset_name = account["ipset_name"]
            region = account["region"]

            try:
                assumed = sts.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName="WAFSyncSession",
                    DurationSeconds=900,
                )
                creds = assumed["Credentials"]

                waf = boto3.client(
                    "wafv2",
                    region_name=region,
                    aws_access_key_id=creds["AccessKeyId"],
                    aws_secret_access_key=creds["SecretAccessKey"],
                    aws_session_token=creds["SessionToken"],
                )

                # WAF Locktoken Retry logic
                max_retries = 3
                for attempt in range(1, max_retries + 1):
                    try:
                        ipset = waf.get_ip_set(
                            Name=target_ipset_name, Scope="REGIONAL", Id=target_ipset_id
                        )
                        target_ips_set = set(ipset["IPSet"]["Addresses"])

                        # Desired target state calculation
                        desired_target_set = target_ips_set.union(all_active_ips) - removed_ips

                        # Evaluate if target is already in sync
                        if target_ips_set == desired_target_set:
                            print(f"{account_name} ({account_id}): SKIPPED")
                            print("Reason: IPs already exist in the target account")
                            skipped_accounts.append(f"{account_name} ({account_id})")
                            break

                        # Update target IP set to match perfectly with desired state
                        waf.update_ip_set(
                            Name=target_ipset_name,
                            Scope="REGIONAL",
                            Id=target_ipset_id,
                            Addresses=list(desired_target_set),
                            LockToken=ipset["LockToken"],
                        )
                        print(f"{account_name} ({account_id}): SYNCED")
                        synced_accounts.append(f"{account_name} ({account_id})")
                        break

                    except waf.exceptions.WAFOptimisticLockException:
                        if attempt < max_retries:
                            time.sleep(1)
                        else:
                            raise RuntimeError(
                                "IP set update failed due to repeated WAF locktoken conflicts after multiple retries"
                            )

            except Exception as e:
                print(f"{account_name} ({account_id}): FAILED")
                print(f"Reason: {str(e)}")
                failed_accounts.append(f"{account_name} ({account_id})")

            time.sleep(0.2)

        # Extracted user identity metadata cleanly before DB updates
        user_identity = event.get("detail", {}).get("userIdentity", {})
        username = (
            user_identity.get("arn", "").split("/")[-1]
            if "/" in user_identity.get("arn", "")
            else "Unknown"
        )

        if source_ips_set != previous_source_ips_set:
            update_db_snapshot(ipset_id, sorted(list(source_ips_set)), username)
        else:
            print("Skipping DB update as DynamoDB record is perfectly in sync")

        # SNS Mail notification
        ist_time = (datetime.now(timezone.utc) + timedelta(hours=5, minutes=30)).strftime("%Y-%m-%d %H:%M:%S IST")

        num_failed, num_synced, num_skipped = (
            len(failed_accounts),
            len(synced_accounts),
            len(skipped_accounts),
        )

        # Update global report execution status
        if num_failed > 0:
            status = "🚨 FAILED"
        elif num_skipped > 0 and num_synced == 0:
            status = "⚠️ SKIPPED"
        else:
            status = "✅ SYNCED"

        # Format layout tracking details dynamically into stacked blocks for clean emails
        ips_reporting_blocks = []
        if attempted_ips:
            ips_reporting_blocks.append("New IPs:\n" + "\n".join(sorted(list(attempted_ips))))
        if removed_ips:
            ips_reporting_blocks.append("Removed IPs:\n" + "\n".join(sorted(list(removed_ips))))
        if skipped_ips:
            ips_reporting_blocks.append("Existing IPs:\n" + "\n".join(sorted(list(skipped_ips))))

        if ips_reporting_blocks:
            ips_to_show = "\n\n".join(ips_reporting_blocks)
        else:
            ips_to_show = "No IPs are found in this execution"

        message = f"""
The WAF IP Set Synchronizer Lambda function was executed by {username} at {ist_time} from the source account.

Updated IP set: {ipset_id}

IPs attempted in this execution:

{ips_to_show}

Execution Summary:
Total accounts processed: {len(config['accounts'])}

Number of synced accounts: {num_synced}
{chr(10).join(synced_accounts) if synced_accounts else 'None'}

Number of skipped accounts: {num_skipped}
{chr(10).join(skipped_accounts) if skipped_accounts else 'None'}

Number of failed accounts: {num_failed}
{chr(10).join(failed_accounts) if failed_accounts else 'None'}
"""

        # Publish message to SNS topic
        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject=f"{status} - WAF IP Set Synchronization Report",
            Message=message,
        )
        print("Lambda execution stopped")

    except Exception as e:
        print("Lambda execution failed")
        print(f"Reason: {str(e)}")
        raise
