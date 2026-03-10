"""
Check Point EM Automated/Semi-Automated Takedown for High-Confidence Phishing Websites

Automates or semi-automates the takedown process for high-confidence phishing websites
detected by Check Point EM. Extracts phishing alert details, enriches with website data and
screenshots, evaluates confidence/severity thresholds, initiates takedown requests,
and continuously monitors takedown status until resolution.

Check Point EM API Endpoints:
- POST /api/v1/alerts - Get phishing alert details
- POST /api/v1/submit - Submit takedown request
- POST /api/v1/submit (filter by alert_id) - Poll takedown status
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # Call input filter
    alert_input_filter(container=container)

    return


def alert_input_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('alert_input_filter() called')

    playbook_input_alert_id = phantom.collect2(container=container, datapath=['playbook_input:alert_id'])
    playbook_input_confidence = phantom.collect2(container=container, datapath=['playbook_input:confidence_threshold'])
    playbook_input_auto = phantom.collect2(container=container, datapath=['playbook_input:auto_takedown'])

    alert_id = playbook_input_alert_id[0][0] if playbook_input_alert_id else None
    confidence_threshold = float(playbook_input_confidence[0][0] or 80) if playbook_input_confidence else 80
    auto_takedown = str(playbook_input_auto[0][0]).lower() == 'true' if playbook_input_auto else False

    phantom.save_run_data(key='alert_id', value=alert_id or '')
    phantom.save_run_data(key='confidence_threshold', value=str(confidence_threshold))
    phantom.save_run_data(key='auto_takedown', value=str(auto_takedown))

    if alert_id:
        get_phishing_alert_details(container=container)
    else:
        phantom.error("Alert ID not provided. Playbook requires a Check Point EM alert ID.")

    return


def get_phishing_alert_details(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_phishing_alert_details() called')

    alert_id = phantom.get_run_data(key='alert_id')

    parameters = [{}]

    phantom.act(action='get enriched alerts', parameters=parameters, assets=['cyberint'], callback=enrich_phishing_data, name='get_phishing_alert_details')

    return


def enrich_phishing_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('enrich_phishing_data() called')

    results_data = phantom.collect2(container=container, datapath=[
        'get_phishing_alert_details:action_result.data'
    ])

    enrich_phishing_data__phishing_details = {}
    enrich_phishing_data__phishing_url = ''
    enrich_phishing_data__confidence_score = 0
    enrich_phishing_data__severity_score = 0
    enrich_phishing_data__detection_reasons = []

    alert_data = results_data[0][0] if results_data else None

    if alert_data:
        # Handle list response
        if isinstance(alert_data, list):
            alert_data = alert_data[0] if alert_data else {}

        alert_details = alert_data.get('alertData', alert_data)

        enrich_phishing_data__phishing_details = {
            'url': alert_details.get('url', ''),
            'title': alert_details.get('title', ''),
            'a_record': alert_details.get('a_record', ''),
            'copyright': alert_details.get('copyright', ''),
            'registrar': alert_details.get('registrar', ''),
            'mx_records': alert_details.get('mx_records', []),
            'nameservers': alert_details.get('nameservers', []),
            'redirect_chain': alert_details.get('redirect_chain', []),
            'detection_reasons': alert_details.get('detection_reasons', []),
            'has_password_field': alert_details.get('has_password_field', False),
            'whois_created_date': alert_details.get('whois_created_date', ''),
            'has_ssl_certificate': alert_details.get('has_ssl_certificate', False),
            'page_source_matches': alert_details.get('page_source_matches', []),
            'page_copyright_matches': alert_details.get('page_copyright_matches', []),
            'screenshot_url': alert_details.get('screenshot_url', '')
        }

        enrich_phishing_data__phishing_url = enrich_phishing_data__phishing_details['url']
        enrich_phishing_data__confidence_score = alert_data.get('confidence', 0)
        enrich_phishing_data__severity_score = alert_data.get('severity', 0)
        enrich_phishing_data__detection_reasons = enrich_phishing_data__phishing_details['detection_reasons']

    phantom.save_run_data(key='phishing_details', value=json.dumps(enrich_phishing_data__phishing_details))
    phantom.save_run_data(key='phishing_url', value=enrich_phishing_data__phishing_url)
    phantom.save_run_data(key='confidence_score', value=str(enrich_phishing_data__confidence_score))
    phantom.save_run_data(key='severity_score', value=str(enrich_phishing_data__severity_score))
    phantom.save_run_data(key='detection_reasons', value=json.dumps(enrich_phishing_data__detection_reasons))

    phantom.debug(f"Enriched phishing data for URL: {enrich_phishing_data__phishing_url}")
    phantom.debug(f"Confidence: {enrich_phishing_data__confidence_score}, Severity: {enrich_phishing_data__severity_score}")

    # Add enrichment note
    enrichment_note = f"""## Phishing Website Analysis

**URL:** {enrich_phishing_data__phishing_url}
**Confidence Score:** {enrich_phishing_data__confidence_score}
**Severity Score:** {enrich_phishing_data__severity_score}

### Detection Reasons
"""
    for reason in enrich_phishing_data__detection_reasons:
        enrichment_note += f"- {reason}\n"

    enrichment_note += f"""
### Technical Details
- **Has Password Field:** {enrich_phishing_data__phishing_details.get('has_password_field', 'Unknown')}
- **Has SSL Certificate:** {enrich_phishing_data__phishing_details.get('has_ssl_certificate', 'Unknown')}
- **Registrar:** {enrich_phishing_data__phishing_details.get('registrar', 'Unknown')}
- **A Record:** {enrich_phishing_data__phishing_details.get('a_record', 'Unknown')}
- **WHOIS Created:** {enrich_phishing_data__phishing_details.get('whois_created_date', 'Unknown')}
"""

    phantom.add_note(container=container, content=enrichment_note, note_format="markdown", note_type="general", title="Phishing Website Analysis")

    evaluate_takedown_threshold(container=container)

    return


def evaluate_takedown_threshold(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('evaluate_takedown_threshold() called')

    confidence_score = float(phantom.get_run_data(key='confidence_score') or 0)
    confidence_threshold = float(phantom.get_run_data(key='confidence_threshold') or 80)
    auto_takedown = phantom.get_run_data(key='auto_takedown') == 'True'

    phantom.debug(f"Confidence: {confidence_score}, Threshold: {confidence_threshold}, Auto: {auto_takedown}")

    if confidence_score >= confidence_threshold and auto_takedown:
        # Auto-initiate takedown
        auto_initiate_takedown(container=container)
    elif confidence_score >= confidence_threshold:
        # High confidence but manual approval required
        analyst_review_prompt(container=container)
    else:
        # Below threshold, require manual review
        analyst_review_prompt(container=container)

    return


def auto_initiate_takedown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('auto_initiate_takedown() called')

    phishing_url = phantom.get_run_data(key='phishing_url')
    detection_reasons = json.loads(phantom.get_run_data(key='detection_reasons') or '[]')
    alert_id = phantom.get_run_data(key='alert_id')

    reason_text = ', '.join(detection_reasons) if detection_reasons else 'Phishing website detected'

    parameters = [{
        'URL': phishing_url,
        'Reason': reason_text,
        'Note': 'Auto-initiated takedown via SOAR playbook based on high confidence score',
        'Alert_ID': int(alert_id) if alert_id else None,
        'Customer_ID': '',
        'Brand': ''
    }]

    phantom.act(action='alerts - submit takedown', parameters=parameters, assets=['cyberint'], callback=check_takedown_initiated, name='auto_initiate_takedown')

    return


def analyst_review_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('analyst_review_prompt() called')

    phishing_details = json.loads(phantom.get_run_data(key='phishing_details') or '{}')
    confidence = phantom.get_run_data(key='confidence_score')
    severity = phantom.get_run_data(key='severity_score')

    message = f"""## Phishing Website Takedown Review Required

**URL:** {phishing_details.get('url', 'N/A')}
**Confidence:** {confidence}
**Severity:** {severity}

**Detection Reasons:**
"""
    for reason in phishing_details.get('detection_reasons', []):
        message += f"- {reason}\n"

    message += f"""

**Additional Details:**
- Has Password Field: {phishing_details.get('has_password_field', 'Unknown')}
- Has SSL Certificate: {phishing_details.get('has_ssl_certificate', 'Unknown')}
- Registrar: {phishing_details.get('registrar', 'Unknown')}

Please review and decide whether to initiate a takedown request.
"""

    response_types = [
        {
            "prompt": "Do you want to initiate a takedown request for this phishing website?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes, initiate takedown",
                    "No, do not takedown",
                    "Need more investigation"
                ]
            }
        }
    ]

    phantom.prompt2(container=container, user="Administrator", message=message, respond_in_mins=60, name="analyst_review_prompt", response_types=response_types, callback=process_analyst_decision)

    return


def process_analyst_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('process_analyst_decision() called')

    results_data = phantom.collect2(container=container, datapath=[
        'analyst_review_prompt:action_result.summary.responses'
    ])

    response = results_data[0][0][0] if results_data and results_data[0][0] else 'No, do not takedown'

    phantom.debug(f"Analyst decision: {response}")

    if response == "Yes, initiate takedown":
        manual_initiate_takedown(container=container)
    else:
        log_no_takedown(container=container)

    return


def manual_initiate_takedown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('manual_initiate_takedown() called')

    phishing_url = phantom.get_run_data(key='phishing_url')
    detection_reasons = json.loads(phantom.get_run_data(key='detection_reasons') or '[]')
    alert_id = phantom.get_run_data(key='alert_id')

    reason_text = ', '.join(detection_reasons) if detection_reasons else 'Phishing website detected'

    parameters = [{
        'URL': phishing_url,
        'Reason': reason_text,
        'Note': 'Semi-automated takedown initiated via SOAR playbook after analyst approval',
        'Alert_ID': int(alert_id) if alert_id else None,
        'Customer_ID': '',
        'Brand': ''
    }]

    phantom.act(action='alerts - submit takedown', parameters=parameters, assets=['cyberint'], callback=check_takedown_initiated, name='manual_initiate_takedown')

    return


def check_takedown_initiated(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_takedown_initiated() called')

    # Check both auto and manual takedown actions
    auto_results = phantom.collect2(container=container, datapath=[
        'auto_initiate_takedown:action_result.status',
        'auto_initiate_takedown:action_result.data'
    ])

    manual_results = phantom.collect2(container=container, datapath=[
        'manual_initiate_takedown:action_result.status',
        'manual_initiate_takedown:action_result.data'
    ])

    takedown_initiated = False
    takedown_data = {}

    if auto_results and auto_results[0][0] == 'success':
        takedown_initiated = True
        takedown_data = auto_results[0][1]
    elif manual_results and manual_results[0][0] == 'success':
        takedown_initiated = True
        takedown_data = manual_results[0][1]

    phantom.save_run_data(key='takedown_initiated', value=str(takedown_initiated))
    phantom.save_run_data(key='takedown_data', value=json.dumps(takedown_data or {}))

    if takedown_initiated:
        phishing_url = phantom.get_run_data(key='phishing_url')
        phantom.add_note(container=container, content=f"Takedown request successfully submitted for: {phishing_url}", note_format="markdown", note_type="general", title="Takedown Initiated")
        poll_takedown_status(container=container)
    else:
        log_no_takedown(container=container)

    return


def poll_takedown_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('poll_takedown_status() called')

    alert_id = phantom.get_run_data(key='alert_id')

    parameters = [{
        'Customer_ID': ''
    }]

    phantom.act(action='alerts - retrieve takedowns', parameters=parameters, assets=['cyberint'], callback=check_status_change, name='poll_takedown_status')

    return


def check_status_change(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_status_change() called')

    results_data = phantom.collect2(container=container, datapath=[
        'poll_takedown_status:action_result.data.*.status'
    ])

    current_status = results_data[0][0] if results_data else 'unknown'

    phantom.debug(f"Current takedown status: {current_status}")

    # Check if status has changed from pending states
    pending_states = ['pending', 'request_sent']

    if current_status and current_status not in pending_states:
        # Status has changed
        process_status_change(container=container)
    else:
        # Status still pending - continue polling (handled by loop in action)
        phantom.debug("Status still pending, continuing to monitor...")
        # The action loop will handle re-polling

    return


def process_status_change(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('process_status_change() called')

    results_data = phantom.collect2(container=container, datapath=[
        'poll_takedown_status:action_result.data'
    ])

    phishing_url = phantom.get_run_data(key='phishing_url')

    process_status_change__status_update = ''
    process_status_change__requires_action = False

    status_data = results_data[0][0] if results_data else {}

    if status_data:
        if isinstance(status_data, list):
            status_data = status_data[0] if status_data else {}

        current_status = status_data.get('status', 'unknown')
        pending_details = status_data.get('pending_details', '')
        resolution_date = status_data.get('resolution_date', '')

        status_note = f"""## Phishing Takedown Status Update

**URL:** {phishing_url}
**Current Status:** {current_status}
**Resolution Date:** {resolution_date or 'Pending'}

"""

        if current_status == 'completed' or current_status == 'taken_down':
            status_note += """### SUCCESS: Website has been taken down!

The phishing website has been successfully removed by the hosting provider/registrar.
"""
            phantom.set_severity(container=container, severity="low")

        elif current_status == 'pending_details':
            status_note += f"""### ACTION REQUIRED: Additional Information Needed

**Details Required:** {pending_details}

Please provide the requested information to proceed with the takedown.
"""
            process_status_change__requires_action = True
            phantom.set_severity(container=container, severity="high")

        elif current_status == 'rejected':
            status_note += """### REJECTED: Takedown request was rejected

The takedown request was rejected. Manual intervention may be required.
"""
            phantom.set_severity(container=container, severity="medium")

        else:
            status_note += f"""### Status: {current_status}

Continue monitoring for further updates.
"""

        phantom.add_note(container=container, content=status_note, note_format="markdown", note_type="general", title=f"Takedown Status: {current_status.upper()}")

        process_status_change__status_update = status_note

    phantom.save_run_data(key='status_update', value=process_status_change__status_update)
    phantom.save_run_data(key='requires_action', value=str(process_status_change__requires_action))

    phantom.debug(f"Processed status change: requires_action={process_status_change__requires_action}")

    build_observable_output(container=container)

    return


def log_no_takedown(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('log_no_takedown() called')

    phishing_url = phantom.get_run_data(key='phishing_url')
    confidence_score = phantom.get_run_data(key='confidence_score')

    log_no_takedown__no_takedown_note = f"""## Phishing Alert - No Takedown Initiated

**URL:** {phishing_url}
**Confidence Score:** {confidence_score}

Takedown was not initiated for this phishing alert. This may be due to:
- Analyst decision to decline takedown
- Confidence score below threshold
- Technical error submitting takedown request

Please review manually if needed.
"""

    phantom.add_note(container=container, content=log_no_takedown__no_takedown_note, note_format="markdown", note_type="general", title="Phishing Alert - No Takedown")

    phantom.save_run_data(key='no_takedown_note', value=log_no_takedown__no_takedown_note)
    phantom.debug("Logged: takedown not initiated")

    build_observable_output(container=container)

    return


def build_observable_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_observable_output() called')

    phishing_details = json.loads(phantom.get_run_data(key='phishing_details') or '{}')
    takedown_data = json.loads(phantom.get_run_data(key='takedown_data') or '{}')

    if isinstance(takedown_data, list):
        takedown_data = takedown_data[0] if takedown_data else {}

    build_observable_output__observable_array = []

    observable = {
        "value": phishing_details.get('url', ''),
        "type": "url",
        "classification": "phishing",
        "details": {
            "title": phishing_details.get('title', ''),
            "registrar": phishing_details.get('registrar', ''),
            "a_record": phishing_details.get('a_record', ''),
            "has_password_field": phishing_details.get('has_password_field', False),
            "has_ssl_certificate": phishing_details.get('has_ssl_certificate', False),
            "detection_reasons": phishing_details.get('detection_reasons', [])
        },
        "takedown": {
            "status": takedown_data.get('status', 'not_initiated'),
            "initiated": bool(takedown_data),
            "resolution_date": takedown_data.get('resolution_date', '')
        },
        "source": "Check Point EM"
    }

    build_observable_output__observable_array.append(observable)

    phantom.save_run_data(key='observable_array', value=json.dumps(build_observable_output__observable_array))
    phantom.debug(f"Built observable for phishing URL: {observable['value']}")

    format_final_report(container=container)

    return


def format_final_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_final_report() called')

    phishing_details = json.loads(phantom.get_run_data(key='phishing_details') or '{}')
    takedown_initiated = phantom.get_run_data(key='takedown_initiated') == 'True'

    template = f"""# Check Point EM Phishing Takedown Report

**Phishing URL:** {phishing_details.get('url', 'N/A')}
**Takedown Initiated:** {'Yes' if takedown_initiated else 'No'}

This playbook processed a phishing website alert and initiated takedown procedures.

**API Endpoints Used:**
- `POST /api/v1/alerts` - Retrieve phishing alert details
- `POST /api/v1/submit` - Submit takedown request
- `POST /api/v1/submit` - Poll takedown status

## Key Benefits

- Streamlines takedown request process for high-confidence phishing
- Reduces effort for monitoring takedown request status
- Improves verbosity of phishing ticket information
- Enables status tracking for SLA purposes

**Source:** Check Point EM Threat Intelligence Platform
"""

    phantom.save_run_data(key='final_report', value=template)

    return


def on_finish(container, summary):
    phantom.debug('on_finish() called')

    observable_array = json.loads(phantom.get_run_data(key='observable_array') or '[]')
    report = phantom.get_run_data(key='final_report') or ''

    output = {
        'observable': observable_array,
        'report': report
    }

    phantom.save_playbook_output_data(output=output)

    return
