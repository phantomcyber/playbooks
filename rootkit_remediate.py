"""
This playbook executes remediation actions to clear a rootkit infection on an endpoint
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'quarantine_device_1' block
    quarantine_device_1(container=container)

    return

def quarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):

    # collect data for 'quarantine_device_1' call
    container_data = phantom.get_data("rkitdata", clear_data=True)

    parameters = []
    
    # build parameters list for 'quarantine_device_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip_hostname': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("quarantine device", parameters=parameters, assets=['carbonblack'], callback=get_system_info_1, name="quarantine_device_1")    
    else:
        phantom.error("'quarantine_device_1' will not be executed due to lack of parameters")
    
    return

def get_system_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['quarantine_device_1:artifact:*.cef.sourceAddress', 'quarantine_device_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_system_info_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'ip_hostname': inputs_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="get system info", parameters=parameters, assets=['vmwarevsphere'], callback=filter_1, name="get_system_info_1", parent_action=action)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_system_info_1:action_result.data.*.state", "==", "running"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        revert_vm_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_system_info_1:action_result.data.*.state", "!=", "running"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        terminate_process_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)
        get_system_info_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def get_system_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_system_info_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_system_info_2' call
    passed_filtered_results_data_1 = phantom.collect2(container=container, datapath=["get_system_info_1:filtered-action_result.data.*.ip", "get_system_info_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'get_system_info_2' call
    for passed_filtered_results_item_1 in passed_filtered_results_data_1:
        if passed_filtered_results_item_1[0]:
            parameters.append({
                'namespace': "",
                'ip_hostname': passed_filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': passed_filtered_results_item_1[1]},
            })

    phantom.act(action="get system info", parameters=parameters, assets=['domainctrl1'], callback=disable_user_1, name="get_system_info_2")

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'fields': "",
        'summary': "Machine was identified with a rootkit.",
        'assignee': "",
        'priority': "High",
        'vault_id': "",
        'issue_type': "",
        'description': "Machine was discovered by phantom to have a rootkit.  See Phantom for more information.",
        'project_key': "REIMAGE",
        'assignee_account_id': "",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['jira'], callback=send_email_2, name="create_ticket_1")

    return

def join_create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_create_ticket_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['disable_user_1', 'terminate_process_1']):
        
        # call connected block "create_ticket_1"
        create_ticket_1(container=container, handle=handle)
    
    return

def terminate_process_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('terminate_process_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'terminate_process_1' call
    passed_filtered_results_data_1 = phantom.collect2(container=container, datapath=["get_system_info_1:filtered-action_result.data.*.vm_hostname", "get_system_info_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'terminate_process_1' call
    for passed_filtered_results_item_1 in passed_filtered_results_data_1:
        parameters.append({
            'pid': "",
            'sensor_id': "",
            'ip_hostname': passed_filtered_results_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': passed_filtered_results_item_1[1]},
        })

    phantom.act(action="terminate process", parameters=parameters, assets=['carbonblack'], callback=join_create_ticket_1, name="terminate_process_1")

    return

def disable_user_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('disable_user_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'disable_user_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_system_info_2:action_result.data.*.system_details.PrimaryOwnerName', 'get_system_info_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'disable_user_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'username': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="disable user", parameters=parameters, assets=['domainctrl1'], callback=join_create_ticket_1, name="disable_user_1", parent_action=action)

    return

def unquarantine_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unquarantine_device_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'unquarantine_device_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['revert_vm_1:artifact:*.cef.sourceAddress', 'revert_vm_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'unquarantine_device_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'ip_hostname': inputs_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    phantom.act(action="unquarantine device", parameters=parameters, assets=['carbonblack'], callback=send_email_reverted, name="unquarantine_device_1", parent_action=action)

    return

def send_email_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_2' call

    parameters = []
    
    # build parameters list for 'send_email_2' call
    parameters.append({
        'cc': "",
        'to': "",
        'bcc': "",
        'body': "",
        'from': "",
        'headers': "",
        'subject': "",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_2", parent_action=action)

    return

def send_email_reverted(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_email_reverted() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_email_reverted' call

    parameters = []
    
    # build parameters list for 'send_email_reverted' call
    parameters.append({
        'cc': "",
        'to': "test@phantom.us",
        'bcc': "",
        'body': "A rootkit was discovered on a device, which was then reverted to an earlier VM snapshot.  See Phantom for more details.",
        'from': "admin@phantom.us",
        'headers': "",
        'subject': "Rootkit was remediated",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['smtp'], name="send_email_reverted", parent_action=action)

    return

def revert_vm_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('revert_vm_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'revert_vm_1' call
    passed_filtered_results_data_1 = phantom.collect2(container=container, datapath=["get_system_info_1:filtered-action_result.data.*.vmx_path", "get_system_info_1:filtered-action_result.parameter.context.artifact_id"], action_results=filtered_results)

    parameters = []
    
    # build parameters list for 'revert_vm_1' call
    for passed_filtered_results_item_1 in passed_filtered_results_data_1:
        if passed_filtered_results_item_1[0]:
            parameters.append({
                'snapshot': "",
                'vmx_path': passed_filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': passed_filtered_results_item_1[1]},
            })

    phantom.act(action="revert vm", parameters=parameters, assets=['vmwarevsphere'], callback=unquarantine_device_1, name="revert_vm_1")

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