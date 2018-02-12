"""
This playbook uses ProtectWise and other tools to investigate several aspects of a security alert containing a file hash and a destination IP address. If the investigation finds malicious hashes or IP addresses they will be blocked using Carbon Black Response and/or Palo Alto Networks Firewall, respectively. This playbook was constructed for the Phantom Tech Session held on 02/10/2017 with ProtectWise.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    # call 'filter_2' block
    filter_2(container=container)

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">=", 10],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_hash_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def whois_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('whois_ip_1() called')

    # collect data for 'whois_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("whois ip", parameters=parameters, assets=['whois'], name="whois_ip_1")

    return

def get_pcap_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('get_pcap_1() called')

    # collect data for 'get_pcap_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.sensorId', 'filtered-data:filter_2:condition_1:artifact:*.cef.observationId', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_pcap_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[1]:
            parameters.append({
                'sensorid': filtered_artifacts_item_1[0],
                'type': "Observation",
                'id': filtered_artifacts_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[2]},
            })

    phantom.act("get pcap", parameters=parameters, assets=['protectwise'], name="get_pcap_1")

    return

def geolocate_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('geolocate_ip_1() called')

    # collect data for 'geolocate_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("geolocate ip", parameters=parameters, assets=['maxmind'], name="geolocate_ip_1")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.destinationAddress", "!=", ""],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        hunt_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        ip_reputation_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        geolocate_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        whois_ip_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        get_pcap_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Beacon", "in", "hunt_ip_1:action_result.data.*.threat.observations.top.*._state.killChainStage"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        block_ip_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def block_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_hash_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_hash_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['file_reputation_1:action_result.parameter.hash', 'file_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_hash_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'comment': "",
                'hash': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("block hash", parameters=parameters, assets=['carbonblack'], callback=severity_high, name="block_hash_1")

    return

def hunt_ip_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('hunt_ip_1() called')

    # collect data for 'hunt_ip_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_ip_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                'ph': "",
                'start_time': "",
                'end_time': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("hunt ip", parameters=parameters, assets=['protectwise'], callback=filter_4, name="hunt_ip_1")

    return

def severity_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('severity_high() called')

    phantom.set_severity(container, "high")
    resolve(container=container)

    return

def resolve(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('resolve() called')

    phantom.set_status(container, "closed")
    format_3(container=container)

    return

def block_ip_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_ip_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_ip_2' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_4:condition_1:hunt_ip_1:action_result.parameter.ip", "filtered-data:filter_4:condition_1:hunt_ip_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'block_ip_2' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'is_source_address': "",
                'ip': filtered_results_item_1[0],
                'vsys': "vsys1",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act("block ip", parameters=parameters, assets=['pan'], callback=block_ip_2_callback, name="block_ip_2")

    return

def block_ip_2_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('block_ip_2_callback() called')
    
    format_2(action=action, success=success, container=container, results=results, handle=handle)
    format_1(action=action, success=success, container=container, results=results, handle=handle)

    return

def create_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_ticket_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_2' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'create_ticket_2' call
    parameters.append({
        'description': "",
        'fields': "",
        'project_key': "AP",
        'summary': formatted_data_1,
        'priority': "",
        'assignee': "",
        'vault_id': "",
        'issue_type': "",
    })

    phantom.act("create ticket", parameters=parameters, assets=['jira'], name="create_ticket_2")

    return

def join_create_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_create_ticket_2() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'block_ip_2' ]):
        
        # call connected block "create_ticket_2"
        create_ticket_2(container=container, handle=handle)
    
    return

def ip_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('ip_reputation_1() called')

    # collect data for 'ip_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_1:artifact:*.cef.destinationAddress', 'filtered-data:filter_2:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['virustotal'], name="ip_reputation_1")

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('file_reputation_1() called')

    # collect data for 'file_reputation_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_1:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_1:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'hash': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal'], callback=filter_3, name="file_reputation_1")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """Follow-up will be required for the block rules on the following IP addresses:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "block_ip_2:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    join_create_ticket_2(container=container)

    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """Deployed Block IP: {0}"""

    # parameter list for template variable replacement
    parameters = [
        "block_ip_2:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    join_create_ticket_2(container=container)

    return

def notify_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('notify_status() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'notify_status' call
    formatted_data_1 = phantom.get_format_data(name='format_3')

    parameters = []
    
    # build parameters list for 'notify_status' call
    parameters.append({
        'body': "The container has been closed.",
        'to': "demo.phantom@gmail.com",
        'from': "local@localhost",
        'attachments': "",
        'subject': formatted_data_1,
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], name="notify_status")

    return

def format_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_3() called')
    
    template = """Phantom Notification - Deploying Block Hash for container ID:  {0}"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_3")

    notify_status(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return