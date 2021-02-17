"""
Originally written as an example playbook for BlackHat 2017, this playbook investigates a potential phishing email with a suspicious attachment. Execution starts when a suspicious email with an attachment is forwarded to an inbox which Phantom is polling. McAfee Advanced Threat Defense is used to do static and dynamic analysis on any attachments to the email. If the attachment(s) appear malicious, any IP addresses identified during the ATD detonation are used to do geolocation and IP address reputation, further enriching the data in the original container. The ATD detonation also records the hashes of files that are created or touched. McAfee Active Response is used to search within the enterprise for those hashes, and if there are any matches they are shared on the OpenDXL message fabric.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

"""
Only proceed with the playbook if the ingested email has an artifact with a vaultId, which will be present if the email has one or more file attachments.
"""
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.vaultId", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        atd_detonate_file(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Enrich the container with the geolocation of any IP addresses found in the detonation to inform any further analysis.
"""
def geolocate_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('geolocate_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'geolocate_ip' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:atd_detonate_file:action_result.data.*.Summary.Ips.*.Ipv4", "filtered-data:filter_1:condition_1:atd_detonate_file:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'geolocate_ip' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'ip': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="geolocate ip", parameters=parameters, assets=['maxmind'], name="geolocate_ip")

    return

"""
Only proceed with investigation if the final severity verdict returned by ATD is greater than or equal to 3, indicating the file is probably malicious.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["atd_detonate_file:action_result.data.*.Summary.Verdict.Severity", ">=", 3],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        geolocate_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        opendxl_push_ip(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        mar_lookup_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Investigate further for any hashes that were identified in the MAR lookup.
"""
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["mar_lookup_hash:action_result.data.*.items.*.count", ">", 0],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        opendxl_push_hash(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_ticket_and_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Create a new ticket with a summary of the information needed to start remediation.
"""
def create_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_ticket_and_email')

    parameters = []
    
    # build parameters list for 'create_ticket_2' call
    for container_item in container_data:
        parameters.append({
            'table': "incident",
            'fields': "",
            'vault_id': container_item[0],
            'description': formatted_data_1,
            'short_description': "phishing attachment present on endpoints",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], name="create_ticket_2")

    return

"""
Email an analyst with a summary of the information needed to start remediation.
"""
def send_email_to_analyst(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_to_analyst() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_to_analyst' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])
    formatted_data_1 = phantom.get_format_data(name='format_ticket_and_email')

    parameters = []
    
    # build parameters list for 'send_email_to_analyst' call
    for container_item in container_data:
        parameters.append({
            'cc': "",
            'to': "analyst@mcafee-ebc.com",
            'bcc': "",
            'body': formatted_data_1,
            'from': "phantom@mcafee-ebc.com",
            'headers': "",
            'subject': "phishing attachment present on endpoints",
            'attachments': container_item[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_to_analyst")

    return

"""
Submit the file(s) to ATD for both static and dynamic analysis. The combined analysis will provide a security verdict about how dangerous the file looks as well as one or more hashes from different stages of its execution and one or more IP addresses hard-coded within it (static analysis) or detected during execution (dynamic analysis).
"""
def atd_detonate_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('atd_detonate_file() called')

    # collect data for 'atd_detonate_file' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'atd_detonate_file' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'vault_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="detonate file", parameters=parameters, assets=['mcafee_atd'], callback=atd_detonate_file_callback, name="atd_detonate_file")

    return

def atd_detonate_file_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('atd_detonate_file_callback() called')
    
    send_email_to_admin(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    filter_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Push any IP addresses identified in the ATD detonation to the OpenDXL message fabric. These can be received by any number of other tools listening on OpenDXL.
"""
def opendxl_push_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('opendxl_push_ip() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'opendxl_push_ip' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:atd_detonate_file:action_result.data.*.Summary.Ips.*.Ipv4", "filtered-data:filter_1:condition_1:atd_detonate_file:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'opendxl_push_ip' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'dxl_ip': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="post ip", parameters=parameters, assets=['mcafee_opendxl'], callback=ip_reputation_1, name="opendxl_push_ip")

    return

"""
Enrich the container with the reputation of any IP addresses found in the detonation to inform any further analysis.
"""
def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['opendxl_push_ip:action_result.parameter.dxl_ip', 'opendxl_push_ip:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                'ph': "",
                'to': "",
                'from': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['passivetotal'], name="ip_reputation_1", parent_action=action)

    return

"""
Use OpenDXL to connect to McAfee Active Response, querying for the existence of the detected hashes on any endpoints within the enterprise. MAR searches for the hash on disk, in netflow, or in processes and registry keys.
"""
def mar_lookup_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('mar_lookup_hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'mar_lookup_hash' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:atd_detonate_file:action_result.data.*.Summary.Files.*.Md5", "filtered-data:filter_1:condition_1:atd_detonate_file:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'mar_lookup_hash' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'mar_md5': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="lookup hash", parameters=parameters, assets=['mcafee_opendxl'], callback=filter_2, name="mar_lookup_hash")

    return

"""
Always send the high-level ATD verdict description to the admin to keep them in the loop.
"""
def send_email_to_admin(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_to_admin() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_to_admin' call
    results_data_1 = phantom.collect2(container=container, datapath=['atd_detonate_file:action_result.data.*.Summary.Verdict.Description', 'atd_detonate_file:action_result.summary.verdict', 'atd_detonate_file:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'send_email_to_admin' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'cc': "",
                'to': "admin@mcafee-ebc.com",
                'bcc': "",
                'body': results_item_1[0],
                'from': "phantom@mcafee-ebc.com",
                'headers': "",
                'subject': results_item_1[1],
                'attachments': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_to_admin", parent_action=action)

    return

"""
Push out the identified hashes for use by McAfee Threat Intelligence Exchange (TIE). From there the hash can be blocked depending on the reputation threshold configured in TIE policy and whether or not files with that hash are signed by a trusted source.
"""
def opendxl_push_hash(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('opendxl_push_hash() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'opendxl_push_hash' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:mar_lookup_hash:action_result.data.*.items.*.output.Files|md5", "filtered-data:filter_2:condition_1:mar_lookup_hash:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'opendxl_push_hash' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'dxl_rep': "KNOWN_MALICIOUS",
                'tie_md5': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="post hash", parameters=parameters, assets=['mcafee_opendxl'], name="opendxl_push_hash")

    return

"""
Summarize the key findings from the investigation to populate a new ticket and an email to an analyst.
"""
def format_ticket_and_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_and_email() called')
    
    template = """Phantom received a potential phishing email from {0} with source_id {1}

Since the email contained an attachment, Phantom used McAfee ATD to detonate the file. The detonation returned a severity verdict of {2}

Phantom proceeded to use McAfee Active Response to hunt internally for endpoints associated with any of the hashes identified during ATD detonation. The following internal hostnames were identified:

{3}

Please continue to investigate these endpoints as soon as possible."""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.fromEmail",
        "container:source_data_identifier",
        "atd_detonate_file:action_result.data.*.Summary.Verdict.Severity",
        "filtered-data:filter_2:condition_1:mar_lookup_hash:action_result.data.*.items.*.output.HostInfo|hostname",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_and_email")

    create_ticket_2(container=container)
    send_email_to_analyst(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return