import os
import json
import sys
import re
import getpass
import time
import uuid
from datetime import datetime
import boto3
from botocore.exceptions import ClientError


# Global Production Constants
SOURCE_LAMBDA_ROLE_NAME = "my-lambda-execution-role"
SOURCE_LAMBDA_POLICY_NAME = "my-lambda-execution-role-policy"
CONFIG_BUCKET = "my-waf-ip-set-config-bucket"
CONFIG_FILE = "config/config.json"

SCRIPT_PASSWORD = "CHANGE_ME_PASSWORD"
SNS_TOPIC_ARN = "arn:aws:sns:REGION:111122223333:my-sns-alerts-topic"
LOG_GROUP_NAME = "/aws/cloudshell/waf-account-onboarding-logs"


# Initialize local AWS clients 
sts = boto3.client('sts')
s3 = boto3.client('s3')
iam = boto3.client('iam')
logs = boto3.client('logs')
sns = boto3.client('sns')

current_operator = "Unknown"
log_stream_name = f"/aws/cloudshell/waf-account-onboarding-logs/{uuid.uuid4().hex}"


# Write logs to CloudWatch Logs
def log_message(text):
    print(text)
    try:
        clean_text = str(text).strip()
        logs.put_log_events(
            logGroupName=LOG_GROUP_NAME,
            logStreamName=log_stream_name,
            logEvents=[{'timestamp': int(time.time() * 1000), 'message': clean_text}]
        )
    except ClientError:
        pass


# CloudWatch Log Group & Log Stream Initialization
def initialize_cloudwatch_logging():
    global log_stream_name
    try:
        try:
            logs.create_log_group(logGroupName=LOG_GROUP_NAME)
        except logs.exceptions.ResourceAlreadyExistsException:
            pass
        logs.create_log_stream(logGroupName=LOG_GROUP_NAME, logStreamName=log_stream_name)
    except ClientError as e:
        print(f"CloudWatch log group initialization failed: {e}")
 

# Password authentication 
def verify_password():
    user_input = getpass.getpass("\nEnter password: ").strip()
    if user_input == SCRIPT_PASSWORD:
        print("Access granted!")
        return True
    print("Incorrect password!")
    return False
 

# Send execution status alerts via SNS
def send_sns_notification(action, status, account_id="N/A", account_name="N/A", region="N/A", ipset="N/A", role_name="N/A", error_reason=""):
    if not SNS_TOPIC_ARN:
        log_message("Notification skipped, SNS Topic ARN is not configured")
        return

    if action == "ONBOARD":
        subject_prefix = "✅ ONBOARDED" if status == "SUCCESS" else "🚨 ONBOARD_FAILED"
    else:
        subject_prefix = "✅ OFFBOARDED" if status == "SUCCESS" else "🚨 OFFBOARD_FAILED"

    # Dynamically alternate the subject prefix based on the specified operation
    report_type = "Onboarding" if action == "ONBOARD" else "Offboarding"
    subject = f"{subject_prefix} - Enterprise WAF Account {report_type} Report"

    message_body = (
        f"Please find the execution details of the WAF Account {report_type} script that was ran from the CloudShell Console.\n\n"
        f"Action Performed: {action}\n\n"
        f"IP Set name: {ipset if ipset != 'N/A' else 'None'}\n\n"
        f"\nEXECUTION SUMMARY:\n"
        f"\n - Status: {status}\n"
        f"\n - Executed By: {current_operator}"
    )

    if status == "FAILED" and error_reason:
        message_body += f"\nReason: {error_reason}\n"

    message_body += (
        f"\n\n"
        f"\n - AWS Account ID: {account_id}\n"
        f"\n - AWS Account Name: {account_name}\n"
        f"\n - AWS Region: {region}\n"
        f"\n - Target IAM Role Name: {role_name}\n"
    )

    try:
        sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=message_body)
        log_message("\nSNS Email notification sent successfully")
    except ClientError as e:
        log_message(f"\nSNS Email notification failed: {e}")


# IAM resource string transformation
def sanitize_for_iam(name):
    sanitized = re.sub(r'[\s_]+', '-', name.strip())
    sanitized = re.sub(r'[^a-zA-Z0-9\-+=.,]', '', sanitized)
    return sanitized.lower()


# Paginated search for target regional WAFv2 IP Set ARNs
def fetch_target_ipset_arn(target_waf_client, ipset_name):
    next_marker = None
    while True:
        list_params = {'Scope': 'REGIONAL', 'Limit': 100}
        if next_marker:
            list_params['NextMarker'] = next_marker

        response = target_waf_client.list_ip_sets(**list_params)
        ip_sets = response.get('IPSets', [])

        matched_set = next((s for s in ip_sets if s['Name'] == ipset_name), None)
        if matched_set:
            return matched_set['ARN']

        next_marker = response.get('NextMarker')
        if not next_marker:
            break
    return None


# Main Function
def main():
    global current_operator
    initialize_cloudwatch_logging()

    try:
        caller_identity = sts.get_caller_identity()
        current_operator = caller_identity['Arn'].split('/')[-1]
    except ClientError:
        current_operator = "Unknown User"

    print("1. ONBOARD a target account")
    print("2. OFFBOARD a target account")

    choice = input("Select operation (1 or 2): ").strip()
    if choice not in ['1', '2']:
        print("Invalid choice, skipping execution")
        return

    action = "ONBOARD" if choice == '1' else "OFFBOARD"

    if not verify_password():
        return

    target_account_id = "N/A"
    target_region = "N/A"
    account_name = "N/A"
    ipset_name = "N/A"
    target_sync_role_name = "N/A"

    try:
        # =================================== #
        # STEP 1: COLLECT INPUT PARAMETERS    #
        # =================================== #
        target_account_id = input("\nEnter AWS Account ID: ").strip()
        account_name = input("Enter AWS Account Name: ").strip()
        target_region = input("Enter AWS Region Code: ").strip().lower()
        ipset_name = input("Enter Blacklist IP Set Name: ").strip()

        if account_name:
            safe_account_string = sanitize_for_iam(account_name)
            target_sync_role_name = f"{safe_account_string}-waf-ip-set-synchronizer-role"
            target_sync_policy_name = f"{target_sync_role_name}-policy"

        if len(target_account_id) != 12 or not target_account_id.isdigit():
            err = "Invalid AWS Account ID, standard 12-digit numeric structure required"
            log_message(err)
            send_sns_notification(action, "FAILED", target_account_id, account_name, target_region, ipset_name, target_sync_role_name, err)
            return

        if not all([account_name, ipset_name, target_region]):
            err = "Execution parameters are empty, all input fields required"
            log_message(err)
            send_sns_notification(action, "FAILED", target_account_id, account_name, target_region, ipset_name, target_sync_role_name, err)
            return

        # ======================================= #
        # STEP 2: NESTED ROLE CHAINING EXECUTION  #
        # ======================================= #
        log_message(f"\nExecuting Role chaining...")
        log_message(f"Role chain executed successfully.\n")

        # Assume Local Central Operator Role 
        operator_role_arn = "arn:aws:iam::111122223333:role/waf-account-onboarding-operator-role"
        log_message(f"Assuming operator role...")
        
        try:
            operator_session_data = sts.assume_role(
                RoleArn=operator_role_arn,
                RoleSessionName="OnboardOperatorSession",
                DurationSeconds=900
            )['Credentials']
            log_message(f"Operator role assumed successfully.\n")
        except ClientError as e:
            err = f"Failed to assume operator role. Reason: {e.response['Error']['Message']}"
            log_message(err)
            send_sns_notification(action, "FAILED", target_account_id, account_name, target_region, ipset_name, target_sync_role_name, err)
            return

        # Bind temporary STS credentials to a scoped client
        operator_sts_client = boto3.client(
            'sts',
            aws_access_key_id=operator_session_data['AccessKeyId'],
            aws_secret_access_key=operator_session_data['SecretAccessKey'],
            aws_session_token=operator_session_data['SessionToken']
        )

        # Assume Target Execution Role
        target_execution_role_arn = f"arn:aws:iam::{target_account_id}:role/waf-account-onboarding-execution-role"
        target_sync_role_arn = f"arn:aws:iam::{target_account_id}:role/{target_sync_role_name}"
        log_message(f"Initializing cross-account assumption to {account_name}...")

        try:
            cross_account_data = operator_sts_client.assume_role(
                RoleArn=target_execution_role_arn,
                RoleSessionName="SecureTargetOnboardSession",
                DurationSeconds=900
            )['Credentials']
            log_message(f"Cross-account role assumption to {account_name} executed successfully.")
        except ClientError as e:
            err = f"Failed cross-account assumption to {account_name}. Reason: {e.response['Error']['Message']}"
            log_message(err)
            send_sns_notification(action, "FAILED", target_account_id, account_name, target_region, ipset_name, target_sync_role_name, err)
            return

        # Instantiate target session bounded to assumed target execution credentials
        target_session = boto3.Session(
            aws_access_key_id=cross_account_data['AccessKeyId'],
            aws_secret_access_key=cross_account_data['SecretAccessKey'],
            aws_session_token=cross_account_data['SessionToken']
        )

        # Instantiate global and regional service clients
        target_iam = target_session.client('iam')
        target_waf = target_session.client('wafv2', region_name=target_region)

        if action == "ONBOARD":
            # =================================== # 
            # STEP 3: VALIDATE TARGET WAF IPSET   # 
            # =================================== #
            log_message(f"\nScanning {ipset_name} in '{target_region}'...")
            target_ipset_arn = fetch_target_ipset_arn(target_waf, ipset_name)

            if not target_ipset_arn:
                err = f"Target IP Set {ipset_name} not found in '{target_region}'"
                log_message(err)
                send_sns_notification(action, "FAILED", target_account_id, account_name, target_region, ipset_name, target_sync_role_name, err)
                return

            log_message(f"WAF IP set ID identified: {target_ipset_arn.split('/')[-1]}")

            # ================================== #
            # STEP 4a: PROVISION TARGET IAM ROLE #
            # ================================== #
            log_message(f"\nProvisioning target account IAM role...")

            target_trust_document = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": {
                        "AWS": f"arn:aws:iam::{sts.get_caller_identity()['Account']}:role/{SOURCE_LAMBDA_ROLE_NAME}"
                    },
                    "Action": "sts:AssumeRole"
                }]
            }

            is_new_role = True
            try:
                target_iam.create_role(RoleName=target_sync_role_name, AssumeRolePolicyDocument=json.dumps(target_trust_document))
                log_message(f"Target account IAM role ({target_sync_role_name}) successfully provisioned")
                # Cooldown to ensure target IAM consistency model propagates globally
                time.sleep(5) 
            except target_iam.exceptions.EntityAlreadyExistsException:
                is_new_role = False
                log_message(f"Target account IAM role ({target_sync_role_name}) already exists, skipping creation")

            # ======================================= #
            # STEP 5: ATTACH TARGET WAF PERMISSIONS   # 
            # ======================================= #
            if is_new_role:
                target_permissions = {
                    "Version": "2012-10-17",
                    "Statement": [{
                        "Effect": "Allow",
                        "Action": ["wafv2:GetIPSet", "wafv2:UpdateIPSet"],
                        "Resource": target_ipset_arn
                    }]
                }
                target_iam.put_role_policy(RoleName=target_sync_role_name, PolicyName=target_sync_policy_name, PolicyDocument=json.dumps(target_permissions))
                log_message(f"Target account WAF resource permissions ({target_sync_policy_name}) attached successfully")
            else:
                log_message(f"Target account WAF resource permissions already attached to role ({target_sync_role_name}), skipping policy creation")

        else:
            # ======================================= #
            # Step 4b: DEPROVISION TARGET IAM ROLE    # 
            # ======================================= #
            log_message(f"\nCleaning up target account IAM role policies...")
            try:
                target_iam.delete_role_policy(RoleName=target_sync_role_name, PolicyName=target_sync_policy_name)
                log_message(f"Target account WAF resource permissions ({target_sync_policy_name}) removed successfully")
            except target_iam.exceptions.NoSuchEntityException:
                log_message(f"Target account WAF resoure permissions ({target_sync_policy_name}) already absent, skipping deletion.")

            try:
                target_iam.delete_role(RoleName=target_sync_role_name)
                log_message(f"Target IAM role ({target_sync_role_name}) successfully deleted")
            except target_iam.exceptions.NoSuchEntityException:
                log_message(f"Target IAM role ({target_sync_role_name}) already absent, skipping deletion")

        # ==================================== # 
        # STEP 6: UPDATE SOURCE IAM POLICY     # 
        # ==================================== #
        log_message(f"\nModifying Source account Lambda role policy...")

        response = iam.get_role_policy(RoleName=SOURCE_LAMBDA_ROLE_NAME, PolicyName=SOURCE_LAMBDA_POLICY_NAME)
        policy_doc = response['PolicyDocument']
        policy_updated = False
        api_write_required = False

        for statement in policy_doc.get('Statement', []):
            if statement.get('Action') == 'sts:AssumeRole':
                resources = statement.get('Resource', [])
                if isinstance(resources, str):
                    resources = [resources]

                if action == "ONBOARD":
                    if target_sync_role_arn not in resources:
                        resources.append(target_sync_role_arn)
                        api_write_required = True
                else:
                    if target_sync_role_arn in resources:
                        resources.remove(target_sync_role_arn)
                        api_write_required = True
                    if not resources:
                        resources = ["arn:aws:iam::111122223333:role/placeholder-role"]

                statement['Resource'] = resources
                policy_updated = True
                break

        if not policy_updated:
            err = "Unable to locate 'sts:AssumeRole' block in source account IAM policy schema"
            log_message(err)
            send_sns_notification(action, "FAILED", target_account_id, account_name, target_region, ipset_name, target_sync_role_name, err)
            return

        if api_write_required:
            iam.put_role_policy(RoleName=SOURCE_LAMBDA_ROLE_NAME, PolicyName=SOURCE_LAMBDA_POLICY_NAME, PolicyDocument=json.dumps(policy_doc, indent=2))
            log_suffix = "appended successfully" if action == "ONBOARD" else "removed successfully"
            log_message(f"Source account Lambda assume-role resource path {log_suffix}")
        else:
            log_message(f"Source account Lambda policy ({SOURCE_LAMBDA_POLICY_NAME}) already up-to-date, skipping update")


        # =========================== # 
        # STEP 7: UPDATE S3 CONFIG    # 
        # =========================== #
        log_message(f"\nSynchronizing target account metadata to S3...")

        s3_obj = s3.get_object(Bucket=CONFIG_BUCKET, Key=CONFIG_FILE)
        config_data = json.loads(s3_obj['Body'].read().decode('utf-8'))

        account_index = -1
        for idx, acc in enumerate(config_data.get('accounts', [])):
            if acc.get('account_id') == target_account_id:
                account_index = idx
                break

        s3_write_required = True
        if action == "ONBOARD":
            try:
                target_ipset_arn = fetch_target_ipset_arn(target_waf, ipset_name)
                ipset_id_payload = target_ipset_arn.split('/')[-1] if target_ipset_arn else "N/A"
            except Exception:
                ipset_id_payload = "N/A"

            new_account_payload = {
                "account_id": target_account_id,
                "account_name": account_name,
                "role_arn": target_sync_role_arn,
                "ipset_id": ipset_id_payload,
                "ipset_name": ipset_name,
                "region": target_region
            }

            if account_index != -1:
                config_data['accounts'][account_index] = new_account_payload
                s3_log_message = "S3 config updated: Existing target account metadata overwritten successfully"
            else:
                config_data['accounts'].append(new_account_payload)
                s3_log_message = "S3 config updated: New target account metadata added successfully"
        else:
            if account_index != -1:
                config_data['accounts'].pop(account_index)
                s3_log_message = "S3 config updated: Specified target account metadata entry removed successfully"
            else:
                s3_log_message = "No existing metadata found inside S3 config, skipping file update"
                s3_write_required = False

        if s3_write_required:
            s3.put_object(Bucket=CONFIG_BUCKET, Key=CONFIG_FILE, Body=json.dumps(config_data, indent=2), ContentType='application/json')
            log_message(s3_log_message)
        else:
            log_message(s3_log_message)

        log_message(f"\nAccount {account_name} ({target_account_id}) successfully processed via {action} workflow")
        send_sns_notification(action, "SUCCESS", target_account_id, account_name, target_region, ipset_name, target_sync_role_name)

    except Exception as e:
        err_msg = str(e)
        log_message(err_msg)
        send_sns_notification(action, "FAILED", target_account_id, account_name, target_region, ipset_name, target_sync_role_name, err_msg)


if __name__ == "__main__":
    main()
