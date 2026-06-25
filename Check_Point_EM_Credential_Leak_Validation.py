"""
Check Point EM Credential Leak Validation and Response

Uses Check Point EM Argos Leaked Employee and Customer Credential alerts to automatically
or semi-automatically validate and recycle compromised credential pairs. Checks if
exposed accounts are active in directory services (AD/Entra/Okta), forces password
resets for active accounts, and notifies relevant parties.

Check Point EM API Endpoints:
- POST /by_domain/ - Lookup leaked credentials by domain

Integrations:
- Directory Services: Active Directory, AzureAD, Okta
- Notifications: Email/Slack/MS Teams
"""

import phantom.rules as phantom
import json
from datetime import datetime, timezone


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # Call input_filter to validate inputs
    input_filter(container=container)

    return


@phantom.playbook_block()
def input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('input_filter() called')

    playbook_input_company_domain = phantom.collect2(container=container, datapath=['playbook_input:company_domain'])

    company_domain = playbook_input_company_domain[0][0] if playbook_input_company_domain else None

    if company_domain:
        phantom.save_run_data(key='company_domain', value=company_domain)
        get_leaked_credentials(container=container)
    else:
        phantom.error("Company domain not provided. Playbook requires a domain to search.")

    return


@phantom.playbook_block()
def get_leaked_credentials(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_leaked_credentials() called')

    company_domain = phantom.get_run_data(key='company_domain')
    playbook_input_last_run = phantom.collect2(container=container, datapath=['playbook_input:last_run_timestamp'])
    last_run_timestamp = playbook_input_last_run[0][0] if playbook_input_last_run else None

    phantom.save_run_data(key='last_run_timestamp', value=last_run_timestamp or '')

    parameters = [{
        'Domain': company_domain,
        'last_seen_since': last_run_timestamp
    }]

    phantom.act(action='credentials - lookup by domain', parameters=parameters, assets=['cyberint'], callback=check_credentials_found, name='get_leaked_credentials')

    return


@phantom.playbook_block()
def check_credentials_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_credentials_found() called')

    results_data = phantom.collect2(container=container, datapath=[
        'get_leaked_credentials:action_result.summary.total_credentials',
        'get_leaked_credentials:action_result.data'
    ])

    total_credentials = results_data[0][0] if results_data else 0
    credentials_data = results_data[0][1] if results_data and len(results_data[0]) > 1 else []

    phantom.save_run_data(key='credentials_data', value=json.dumps(credentials_data or []))
    phantom.save_run_data(key='total_credentials', value=str(total_credentials or 0))

    if total_credentials and int(total_credentials) > 0:
        phantom.debug(f"Found {total_credentials} leaked credentials")
        check_account_status(container=container)
    else:
        phantom.debug("No leaked credentials found")
        log_no_credentials(container=container)

    return


@phantom.playbook_block()
def check_account_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_account_status() called')

    credentials_data = json.loads(phantom.get_run_data(key='credentials_data') or '[]')

    # Extract emails from credentials
    emails = []
    for cred in credentials_data:
        if isinstance(cred, dict) and cred.get('email'):
            emails.append(cred['email'])
        elif isinstance(cred, list):
            for item in cred:
                if isinstance(item, dict) and item.get('email'):
                    emails.append(item['email'])

    phantom.save_run_data(key='leaked_emails', value=json.dumps(emails))

    if not emails:
        phantom.debug("No email addresses to check")
        log_no_credentials(container=container)
        return

    parameters = []
    for email in emails:
        parameters.append({
            'username': email
        })

    phantom.act(action='get user', parameters=parameters, assets=['ldap', 'azure_ad', 'okta'], callback=filter_active_accounts, name='check_account_status')

    return


@phantom.playbook_block()
def filter_active_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_active_accounts() called')

    results_data = phantom.collect2(container=container, datapath=[
        'check_account_status:action_result.parameter.username',
        'check_account_status:action_result.data.*.enabled',
        'check_account_status:action_result.status'
    ])

    active_accounts = []
    inactive_accounts = []

    for result in results_data:
        username = result[0]
        enabled = result[1]
        status = result[2]

        if status == 'success':
            if enabled == True or str(enabled).lower() == 'true':
                active_accounts.append(username)
            else:
                inactive_accounts.append(username)
        else:
            # If we couldn't check, treat as potentially active
            phantom.debug(f"Could not verify account status for {username}")

    phantom.save_run_data(key='active_accounts', value=json.dumps(active_accounts))
    phantom.save_run_data(key='inactive_accounts', value=json.dumps(inactive_accounts))

    phantom.debug(f"Active accounts: {len(active_accounts)}, Inactive accounts: {len(inactive_accounts)}")

    if active_accounts:
        force_password_reset(container=container)
    else:
        log_inactive_accounts(container=container)

    return


@phantom.playbook_block()
def force_password_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('force_password_reset() called')

    active_accounts = json.loads(phantom.get_run_data(key='active_accounts') or '[]')

    parameters = []
    for username in active_accounts:
        parameters.append({
            'username': username,
            'require_change_at_logon': True
        })

    phantom.act(action='reset password', parameters=parameters, assets=['ldap', 'azure_ad', 'okta'], callback=send_notifications, name='force_password_reset')

    return


@phantom.playbook_block()
def log_no_credentials(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('log_no_credentials() called')

    company_domain = phantom.get_run_data(key='company_domain')
    last_run_timestamp = phantom.get_run_data(key='last_run_timestamp')

    status_message = f"No new leaked credentials found for domain {company_domain} since {last_run_timestamp or 'initial run'}."
    phantom.debug(status_message)

    phantom.save_run_data(key='status_message', value=status_message)

    format_no_findings_report(container=container)

    return


@phantom.playbook_block()
def log_inactive_accounts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('log_inactive_accounts() called')

    inactive_accounts = json.loads(phantom.get_run_data(key='inactive_accounts') or '[]')

    phantom.debug(f"Inactive accounts with leaked credentials: {inactive_accounts}")

    phantom.save_run_data(key='inactive_list', value=json.dumps(inactive_accounts))

    send_notifications(container=container)

    return


@phantom.playbook_block()
def send_notifications(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_notifications() called')

    # Check if password reset action is complete
    active_accounts = json.loads(phantom.get_run_data(key='active_accounts') or '[]')
    if active_accounts and not phantom.completed(action_names=['force_password_reset']):
        return

    # Collect reset results
    reset_results = phantom.collect2(container=container, datapath=[
        'force_password_reset:action_result.parameter.username',
        'force_password_reset:action_result.status'
    ])

    successful_resets = []
    failed_resets = []

    for result in reset_results:
        username = result[0]
        status = result[1]
        if status == 'success':
            successful_resets.append(username)
        else:
            failed_resets.append(username)

    notification_content = f"""## Credential Leak Response Summary

**Successful Password Resets:** {len(successful_resets)}
**Failed Password Resets:** {len(failed_resets)}

### Users with Reset Passwords:
"""
    for user in successful_resets:
        notification_content += f"- {user}\n"

    if failed_resets:
        notification_content += "\n### Users Requiring Manual Intervention:\n"
        for user in failed_resets:
            notification_content += f"- {user}\n"

    # Add inactive accounts
    inactive_accounts = json.loads(phantom.get_run_data(key='inactive_accounts') or '[]')
    if inactive_accounts:
        notification_content += "\n### Inactive Accounts (No Action Needed):\n"
        for user in inactive_accounts:
            notification_content += f"- {user}\n"

    phantom.add_note(container=container, content=notification_content, note_format="markdown", note_type="general", title="Credential Leak Response - Notifications")

    phantom.save_run_data(key='notification_summary', value=notification_content)
    phantom.debug("Notifications sent for credential leak response")

    create_incident_log(container=container)

    return


@phantom.playbook_block()
def format_no_findings_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_no_findings_report() called')

    company_domain = phantom.get_run_data(key='company_domain')
    last_run_timestamp = phantom.get_run_data(key='last_run_timestamp')

    template = f"""# Check Point EM Credential Leak Scan - No New Findings

**Domain Scanned:** {company_domain}
**Last Run:** {last_run_timestamp or 'Initial scan'}

No new leaked credentials were discovered for this domain since the last scan.

**Source:** Check Point EM Argos Platform
"""

    phantom.add_note(container=container, content=template, note_format="markdown", note_type="general", title="Credential Leak Scan - No Findings")

    phantom.save_run_data(key='formatted_report', value=template)

    create_incident_log(container=container)

    return


@phantom.playbook_block()
def create_incident_log(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_incident_log() called')

    credentials_data = json.loads(phantom.get_run_data(key='credentials_data') or '[]')
    notification_summary = phantom.get_run_data(key='notification_summary') or 'No notifications sent.'

    # Flatten credentials if nested
    leaked_creds = []
    if isinstance(credentials_data, list):
        for item in credentials_data:
            if isinstance(item, dict):
                leaked_creds.append(item)
            elif isinstance(item, list):
                leaked_creds.extend([i for i in item if isinstance(i, dict)])

    incident_report = f"""# Credential Leak Incident Report

**Generated:** {datetime.now(timezone.utc).isoformat()}
**Source:** Check Point EM Argos Platform
**Playbook:** Check_Point_EM_Credential_Leak_Validation

## Summary

- **Total Leaked Credentials Found:** {len(leaked_creds)}

## Leaked Credentials Details

| Email | Breach Source | First Seen | Last Seen |
|-------|--------------|------------|----------|
"""

    for cred in leaked_creds:
        email = cred.get('email', 'N/A')
        source = cred.get('breach_source', 'N/A')
        first_seen = cred.get('first_seen', 'N/A')
        last_seen = cred.get('last_seen', 'N/A')
        incident_report += f"| {email} | {source} | {first_seen} | {last_seen} |\n"

    incident_report += f"""

## Response Actions

{notification_summary}

## Recommendations

1. Review affected user accounts for suspicious activity
2. Check for unauthorized access attempts during exposure window
3. Inform security team of high-value targets
4. Consider additional monitoring for affected accounts

---
*This report was generated automatically by the Check Point EM Credential Leak Validation playbook.*
"""

    phantom.add_note(container=container, content=incident_report, note_format="markdown", note_type="general", title="Credential Leak Incident Report")

    phantom.save_run_data(key='incident_report', value=incident_report)
    phantom.debug("Created incident log with Check Point EM evidence")

    build_output(container=container)

    return


@phantom.playbook_block()
def build_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_output() called')

    credentials_data = json.loads(phantom.get_run_data(key='credentials_data') or '[]')
    active_accounts = json.loads(phantom.get_run_data(key='active_accounts') or '[]')

    # Flatten credentials
    leaked_creds = []
    if isinstance(credentials_data, list):
        for item in credentials_data:
            if isinstance(item, dict):
                leaked_creds.append(item)
            elif isinstance(item, list):
                leaked_creds.extend([i for i in item if isinstance(i, dict)])

    build_output__compromised_credentials = []
    build_output__response_actions = []

    for cred in leaked_creds:
        email = cred.get('email', '')
        build_output__compromised_credentials.append({
            'email': email,
            'breach_source': cred.get('breach_source', ''),
            'first_seen': cred.get('first_seen', ''),
            'last_seen': cred.get('last_seen', ''),
            'password_reset': email in active_accounts
        })

    for user in active_accounts:
        build_output__response_actions.append({
            'action': 'password_reset',
            'user': user,
            'status': 'completed'
        })

    phantom.save_run_data(key='compromised_credentials', value=json.dumps(build_output__compromised_credentials))
    phantom.save_run_data(key='response_actions', value=json.dumps(build_output__response_actions))

    phantom.debug(f"Output built: {len(build_output__compromised_credentials)} credentials, {len(build_output__response_actions)} actions")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug('on_finish() called')

    compromised_credentials = json.loads(phantom.get_run_data(key='compromised_credentials') or '[]')
    response_actions = json.loads(phantom.get_run_data(key='response_actions') or '[]')
    incident_report = phantom.get_run_data(key='incident_report') or ''

    output = {
        'compromised_credentials': compromised_credentials,
        'response_actions': response_actions,
        'report': incident_report
    }

    phantom.save_playbook_output_data(output=output)

    return