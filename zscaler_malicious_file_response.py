"""
Respond to a malicious file alert from the zScaler web proxy by gathering more information about the file, querying Splunk and Carbon Black internally to find more about the user and the endpoints where the file exists, and protecting against further malicious behavior by blocking executions of the file and quarantining affected devices from the network.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

"""
Copy the file back to the Phantom Vault.
"""
def get_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_file_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_file_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.parameter.hash', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_file_1' call
    for results_item_1 in results_data_1:
        parameters.append({
            'hash': results_item_1[0],
            'ph_0': "",
            'offset': "",
            'get_count': "",
            'sensor_id': "",
            'file_source': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="get file", parameters=parameters, assets=['carbonblack'], callback=join_format_short_description, name="get_file_1", parent_action=action)

    return

"""
Gather general system information about affected endpoints.
"""
def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.binary.results.*.endpoint', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_system_info_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            for endpoint in results_item_1[0]:
                if endpoint:
                    parameters.append({
                        'sensor_id': "",
                        'ip_hostname': endpoint.split('|')[0],
                        # context (artifact id) is added to associate results with the artifact
                        'context': {'artifact_id': results_item_1[1]},
                    })

    phantom.act("get system info", parameters=parameters, assets=['carbonblack'], name="get_system_info_1", parent_action=action)

    return

"""
Quarantine affected endpoints from the network.
"""
def quarantine_device_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('quarantine_device_2() called')

    # collect data for 'quarantine_device_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:action_result.data.*.binary.results.*.endpoint', 'hunt_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'quarantine_device_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            for endpoint in results_item_1[0]:
                if endpoint:
                    parameters.append({
                        'ip_hostname': endpoint.split('|')[0],
                        # context (artifact id) is added to associate results with the artifact
                        'context': {'artifact_id': results_item_1[1]},
                    })

    phantom.act("quarantine device", parameters=parameters, assets=['carbonblack'], name="quarantine_device_2", parent_action=action)

    return

"""
Make the summary for the ServiceNow ticket.
"""
def format_short_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_short_description() called')
    
    template = """Malicious MD5 Found on Endpoint(s) - {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.fileHashMd5",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_short_description")

    format_long_description(container=container)

    return

def join_format_short_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_short_description() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['quarantine_device_2', 'get_system_info_1', 'get_file_1', 'get_user_attributes_1', 'file_reputation_1', 'block_hash_1']):
        
        # call connected block "format_short_description"
        format_short_description(container=container, handle=handle)
    
    return

"""
Make the body of the ServiceNow ticket description.
"""
def format_long_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_long_description() called')
    
    template = """Zscaler sent a Patient 0 Alert to Phantom, which executed the Playbook called \"zscaler_malicious_file_response\" to take the following actions:

1. gathered file reputation information from Virustotal
2. queried Splunk for additional information in the Zscaler logs including the affected user and the policy action taken by Zscaler
3. blocked further execution using the MD5 file hash of the file with Carbon Black Response
4. quarantined endpoints on which the file was detected using Carbon Black Response

MD5 File Hash - {0}

VirusTotal Positives: {1}

Affected Endpoints: {2}

Additional details can be found within Phantom Mission Control:
{3}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.fileHashMd5",
        "file_reputation_1:action_result.summary.positives",
        "hunt_file_1:action_result.data.*.binary.results.*.endpoint",
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_long_description")

    create_ticket_3(container=container)

    return

"""
Create a ServiceNow ticket.
"""
def create_ticket_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_3' call
    formatted_data_1 = phantom.get_format_data(name='format_long_description')
    formatted_data_2 = phantom.get_format_data(name='format_short_description')

    parameters = []
    
    # build parameters list for 'create_ticket_3' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': formatted_data_2,
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], name="create_ticket_3")

    return

"""
Build a Splunk query to determine the affected user during the malicious file alert.
"""
def format_proxy_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_proxy_query() called')
    
    template = """host=\"zscalertwo-phantom\" index=\"proxy_logs_zscaler\" sourcetype=\"csv\"  MD5=\"{0}\" | rename \"Client IP\" as client_ip \"Policy Action\" as policy_action | fields client_ip, policy_action, MD5, User"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.fileHashMd5",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_proxy_query")

    run_query_2(container=container)

    return

"""
Look up any known reputation information about the detected file on VirusTotal.
"""
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashMd5', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=join_format_short_description, name="file_reputation_1")

    return

"""
Block future executions of files with the detected hash.
"""
def block_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_hash_1() called')

    # collect data for 'block_hash_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashMd5', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'block_hash_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                'comment': "Patient zero alert from zScaler validate in Virus Total",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="block hash", parameters=parameters, assets=['carbonblack'], callback=join_format_short_description, name="block_hash_1")

    return

"""
Find endpoints where the detected file is on disk.
"""
def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('hunt_file_1() called')

    # collect data for 'hunt_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHashMd5', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_file_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                'type': "",
                'range': "0-10",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="hunt file", parameters=parameters, assets=['carbonblack'], callback=hunt_file_1_callback, name="hunt_file_1")

    return

def hunt_file_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('hunt_file_1_callback() called')
    
    quarantine_device_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    get_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Query Active Directory for information about the affected user such as failed logins or the department in the organization.
"""
def get_user_attributes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attributes_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_user_attributes_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['run_query_2:action_result.data.*.User', 'run_query_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_user_attributes_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'fields': "",
                'username': results_item_1[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, app={ "name": 'LDAP' }, callback=join_format_short_description, name="get_user_attributes_1", parent_action=action)

    return

"""
Run a Splunk query to determine the affected user during the malicious file alert.
"""
def run_query_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_query_2() called')

    # collect data for 'run_query_2' call
    formatted_data_1 = phantom.get_format_data(name='format_proxy_query')

    parameters = []
    
    # build parameters list for 'run_query_2' call
    parameters.append({
        'query': formatted_data_1,
        'command': "",
        'display': "client_ip, policy_action, MD5, User",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk_es'], callback=get_user_attributes_1, name="run_query_2")

    return

"""
Only operate on artifacts such as that created by the community playbook "zscaler_patient_0_parse_email", which parses emails from zScaler Patient 0 alerts.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.name", "==", "zScaler Alert Artifact"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_proxy_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        block_hash_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        hunt_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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