"""
This playbook executes investigative actions to detect a rootkit infection on an endpoint.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    return

def playbook_platinum_rootkit_remediate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    # call playbook "platinum/rootkit_remediate", returns the playbook_run_id
    playbook_run_id = phantom.playbook("platinum/rootkit_remediate", container)

    return

def Close(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    phantom.act("set status", parameters=parameters, name="Close", parent_action=action)    
    
    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", 0],
            ["artifact:*.cef.fileHash", "==", "file_reputation_1:action_result.parameter.hash"],
        ],
        logical_operator='and')

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        get_system_info_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", "==", 0],
            ["artifact:*.cef.fileHash", "==", "file_reputation_1:action_result.parameter.hash"],
        ],
        logical_operator='and')

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        get_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_1:action_result.data.*.threat.score", ">", 0],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        get_system_info_2(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_1:action_result.data.*.threat.score", "==", 0],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        Send_Email_false_positive(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def Send_Email_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Send_Email_malicious' call

    parameters = []
    
    # build parameters list for 'Send_Email_malicious' call
    parameters.append({
        'body': "A rootkit was detected and verified, a promt will now be created to approve remediation.  See Phantom for more info.",
        'to': "test@phantom.us",
        'from': "admin@phantom.us",
        'attachments': "",
        'subject': "Malicious rootkit detected",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=prompt_1, name="Send_Email_malicious", parent_action=action)    
    
    return

def get_system_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_2' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.sourceAddress', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'get_system_info_2' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'ip_hostname': filtered_container_item[0],
            })

    phantom.act("get system info", parameters=parameters, assets=['vmwarevsphere'], callback=filter_4, name="get_system_info_2")    
    
    return

def join_get_system_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation_1', 'detonate_file_1' ]):
        
        # call connected block "get_system_info_2"
        get_system_info_2(container=container, handle=handle)
    
    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("file reputation", parameters=parameters, assets=['virustotal_private'], callback=filter_6, name="file_reputation_1")    
    
    return

def get_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_file_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("get file", parameters=parameters, assets=['carbonblack'], callback=detonate_file_1, name="get_file_1")    
    
    return

def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_1' call

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    parameters.append({
        'file_name': "",
        'force_analysis': "",
        'vault_id': "",
        'vm': "",
        'private': "",
    })

    phantom.act("detonate file", parameters=parameters, assets=['threatgrid'], callback=filter_5, name="detonate_file_1", parent_action=action)    
    
    return

def Send_Email_false_positive(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Send_Email_false_positive' call

    parameters = []
    
    # build parameters list for 'Send_Email_false_positive' call
    parameters.append({
        'body': "There was a reported rootkit that was identified as a false positive.  See Phantom for more info.",
        'to': "test@phantom.us",
        'from': "admin@phantom.us",
        'attachments': "",
        'subject': "False positive rootkit identified",
    })

    phantom.act("send email", parameters=parameters, assets=['smtp'], callback=Close, name="Send_Email_false_positive")    
    
    return

def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_1' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.sourceAddress', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'get_system_info_1' call
    for filtered_container_item in filtered_container_data:
        parameters.append({
            'ip_hostname': filtered_container_item[0],
        })

    phantom.act("get system info", parameters=parameters, assets=['carbonblack'], callback=Send_Email_malicious, name="get_system_info_1")    
    
    return

def join_get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation_1', 'detonate_file_1' ]):
        
        # call connected block "get_system_info_1"
        get_system_info_1(container=container, handle=handle)
    
    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    # set user and message variables for phantom.prompt call
    user = "Incident Commander"
    message = """Remediate the rootkit?"""

    # parameter list for template variable replacement
    parameters = [
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
        "undefined",
    ]

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, callback=playbook_platinum_rootkit_remediate)

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_system_info_2:action_result.data.*.state", "==", "running"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        snapshot_vm_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def snapshot_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'snapshot_vm_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["get_system_info_2:filtered-action_result.data.*.vmx_path", "get_system_info_2:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'snapshot_vm_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'download': "",
                'vmx_path': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act("snapshot vm", parameters=parameters, assets=['vmwarevsphere'], name="snapshot_vm_1")    
    
    return

def on_finish(container, summary):

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