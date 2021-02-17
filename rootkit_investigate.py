"""
This playbook executes investigative actions to detect a rootkit infection on an endpoint.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "Incident Commander"
    message = """Remediate the rootkit?"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", response_types=response_types, callback=playbook_community_rootkit_remediate_1)

    return

def set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_2() called')

    phantom.set_status(container=container, status="closed")

    return

def snapshot_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('snapshot_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'snapshot_vm_1' call
    passed_filtered_results_data_1 = phantom.collect2(container=container, datapath=["get_system_info_2:filtered-action_result.data.*.vmx_path", "get_system_info_2:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'snapshot_vm_1' call
    for passed_filtered_results_item_1 in passed_filtered_results_data_1:
        if passed_filtered_results_item_1[0]:
            parameters.append({
                'download': "",
                'vmx_path': passed_filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': passed_filtered_results_item_1[1]},
            })

    phantom.act(action="snapshot vm", parameters=parameters, assets=['vmwarevsphere'], name="snapshot_vm_1")

    return

def get_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_file_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_file_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_8:condition_1:artifact:*.cef.fileHash', 'filtered-data:filter_8:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_file_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        parameters.append({
            'hash': filtered_artifacts_item_1[0],
            'ph_0': "",
            'offset': "",
            'get_count': "",
            'sensor_id': "",
            'file_source': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': filtered_artifacts_item_1[1]},
        })

    phantom.act(action="get file", parameters=parameters, assets=['carbonblack'], callback=detonate_file_1, name="get_file_1")

    return

def filter_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_4() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_system_info_2:action_result.data.*.state", "==", "running"],
        ],
        name="filter_4:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        snapshot_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.parameter.hash", "==", "artifact:*.cef.fileHash"],
        ],
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_get_system_info_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_1' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.sourceAddress', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)
    phantom.save_data(filtered_container_data, key="rkitdata")
    parameters = []
    
    # build parameters list for 'get_system_info_1' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'ip_hostname': filtered_container_item[0],
            })

    if parameters:
        phantom.act("get system info", parameters=parameters, assets=['carbonblack'], callback=Send_Email_malicious, name="get_system_info_1")    
    else:
        phantom.error("'get_system_info_1' will not be executed due to lack of parameters")
    
    return

def join_get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_get_system_info_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_get_system_info_1_called'):
        return

    # no callbacks to check, call connected block "get_system_info_1"
    phantom.save_run_data(key='join_get_system_info_1_called', value='get_system_info_1', auto=True)

    get_system_info_1(container=container, handle=handle)
    
    return

def Send_Email_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Send_Email_malicious() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Send_Email_malicious' call

    parameters = []
    
    # build parameters list for 'Send_Email_malicious' call
    parameters.append({
        'cc': "",
        'to': "test@phantom.us",
        'bcc': "",
        'body': "A rootkit was detected and verified, a promt will now be created to approve remediation.  See Phantom for more info.",
        'from': "admin@phantom.us",
        'headers': "",
        'subject': "Malicious rootkit detected",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=prompt_1, name="Send_Email_malicious", parent_action=action)

    return

def get_system_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_2' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_5:condition_1:artifact:*.cef.sourceAddress', 'filtered-data:filter_5:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_system_info_2' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'ip_hostname': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="get system info", parameters=parameters, assets=['vmwarevsphere'], callback=filter_4, name="get_system_info_2")

    return

def join_get_system_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_get_system_info_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_get_system_info_2_called'):
        return

    # no callbacks to check, call connected block "get_system_info_2"
    phantom.save_run_data(key='join_get_system_info_2_called', value='get_system_info_2', auto=True)

    get_system_info_2(container=container, handle=handle)
    
    return

def set_severity_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_1() called')

    phantom.set_severity(container=container, severity="low")
    set_status_2(container=container)

    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')

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

    phantom.act(action="file reputation", parameters=parameters, assets=['reversinglabs'], callback=filter_6, name="file_reputation_1")

    return

def send_fp_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_fp_email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_fp_email' call

    parameters = []
    
    # build parameters list for 'send_fp_email' call
    parameters.append({
        'cc': "",
        'to': "test@phantom.us",
        'bcc': "",
        'body': "There was a reported rootkit that was identified as a false positive.  See Phantom for more info.",
        'from': "admin@phantom.us",
        'headers': "",
        'subject': "False positive rootkit identified",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], callback=set_severity_1, name="send_fp_email")

    return

def filter_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_6() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">", 0],
        ],
        name="filter_6:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_7(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", "==", 0],
        ],
        name="filter_6:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        filter_8(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def filter_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_8() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_6:condition_2:file_reputation_1:action_result.parameter.hash", "==", "artifact:*.cef.fileHash"],
        ],
        name="filter_8:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_file_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def filter_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_5() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_1:action_result.data.*.threat.score", ">", 0],
            ["artifact:*.cef.fileHash", "==", "get_file_1:artifact:*.cef.fileHash"],
        ],
        logical_operator='and',
        name="filter_5:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        join_get_system_info_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        join_get_system_info_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["detonate_file_1:action_result.data.*.threat.score", "==", 0],
        ],
        name="filter_5:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        send_fp_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('detonate_file_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_1' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_8:condition_1:artifact:*.cef.vaultId', 'filtered-data:filter_8:condition_1:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'vm': "",
                'private': "",
                'playbook': "",
                'vault_id': filtered_artifacts_item_1[0],
                'file_name': "",
                'force_analysis': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act(action="detonate file", parameters=parameters, assets=['threatgrid'], callback=filter_5, name="detonate_file_1", parent_action=action)

    return

def playbook_community_rootkit_remediate_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('playbook_community_rootkit_remediate_1() called')
    
    # call playbook "community/rootkit_remediate", returns the playbook_run_id
    playbook_run_id = phantom.playbook(playbook="community/rootkit_remediate", container=container)

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