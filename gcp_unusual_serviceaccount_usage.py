"""
Investigate and respond to an unusual service account usage alert in Google Cloud Platform. Gather information about the service account keys associated with the service account in question, as well as the compute instance involved in the activity, if applicable. According to a prompt response from an analyst, optionally delete the service account keys and/or stop the compute instance.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block




# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'artifact_check' block
    artifact_check(container=container)

    return

"""
Leave a comment and stop playbook execution.
"""
def add_comment_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_comment_1() called')

    phantom.comment(container=container, comment="An unusual serviceaccount alert was triggered but no serviceaccount name was found in the sourceUserId field of the alert, so manual investigation is needed.")

    return

"""
Show the keys that belong to the service account in question.
"""
def list_serviceaccountkey_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_serviceaccountkey_1() called')

    # collect data for 'list_serviceaccountkey_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_serviceaccountkey_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'account': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="list serviceaccountkey", parameters=parameters, assets=['gcp_iam'], callback=format_key_info_1, name="list_serviceaccountkey_1")

    return

"""
Format information about each service account key so it can be used in a prompt.
"""
def format_key_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_key_info_1() called')
    
    template = """%%
Key Name: {0}
Key Type: {1}
Key Origin: {2}
Key Algorithm: {3}
Valid After Time: {4}
Valid Before Time: {5}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "list_serviceaccountkey_1:action_result.data.0.keys.*.name",
        "list_serviceaccountkey_1:action_result.data.0.keys.*.keyType",
        "list_serviceaccountkey_1:action_result.data.0.keys.*.keyOrigin",
        "list_serviceaccountkey_1:action_result.data.0.keys.*.keyAlgorithm",
        "list_serviceaccountkey_1:action_result.data.0.keys.*.validAfterTime",
        "list_serviceaccountkey_1:action_result.data.0.keys.*.validBeforeTime",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_key_info_1", separator=", ")

    join_gcp_unusual_usage_keys_and_vm(container=container)

    return

"""
Use the formatted messages to prompt the analyst.
"""
def gcp_unusual_usage_keys_and_vm(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('gcp_unusual_usage_keys_and_vm() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Unusual Google Cloud Compute Engine activity was detected. The service account in use has the following service account keys:
{0}

The following Compute Engine VM instance was associated with the activity:
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "format_key_info_1:formatted_data",
        "format_vm_info:formatted_data",
    ]

    #responses:
    response_types = [
        {
            "prompt": "Should the associated service account keys be deleted to disable further access?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
        {
            "prompt": "Should the associated virtual machine be stopped?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="gcp_unusual_usage_keys_and_vm", separator=", ", parameters=parameters, response_types=response_types, callback=gcp_unusual_usage_keys_and_vm_callback)

    return

def gcp_unusual_usage_keys_and_vm_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('gcp_unusual_usage_keys_and_vm_callback() called')
    
    decision_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    decision_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def join_gcp_unusual_usage_keys_and_vm(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_gcp_unusual_usage_keys_and_vm() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['list_serviceaccountkey_1', 'describe_instance_1']):
        
        # call connected block "gcp_unusual_usage_keys_and_vm"
        gcp_unusual_usage_keys_and_vm(container=container, handle=handle)
    
    return

"""
Delete each of the offending service account keys.
"""
def delete_keys_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_keys_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delete_keys_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['list_serviceaccountkey_1:action_result.data.0.keys.*.name', 'list_serviceaccountkey_1:action_result.parameter.account', 'list_serviceaccountkey_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'delete_keys_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and results_item_1[1]:
            parameters.append({
                'key': results_item_1[0],
                'account': results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="delete serviceaccountkey", parameters=parameters, assets=['gcp_iam'], name="delete_keys_1")

    return

"""
Gather metadata about the compute instance referenced in the event.
"""
def describe_instance_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('describe_instance_1() called')

    # collect data for 'describe_instance_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.data_resource_labels_zone', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'describe_instance_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'id': "",
                'zone': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="describe instance", parameters=parameters, assets=['gcp_compute'], callback=format_vm_info, name="describe_instance_1")

    return

"""
Check the event for the service account ID and compute instance ID needed to run the actions. This splits into one of three paths:

1. events without a service account ID
2. events with a service account ID but no compute instance ID
3. events with both a service account ID and a compute instance ID
"""
def artifact_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('artifact_check() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceUserId", "!=", ""],
            ["artifact:*.cef.data_resource_labels_instance_id", "!=", ""],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        list_serviceaccountkey_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        describe_instance_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceUserId", "!=", ""],
            ["artifact:*.cef.data_resource_labels_instance_id", "==", ""],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        list_serviceaccountkey_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    add_comment_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Show the keys that belong to the service account in question.
"""
def list_serviceaccountkey_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_serviceaccountkey_2() called')

    # collect data for 'list_serviceaccountkey_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_serviceaccountkey_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'account': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="list serviceaccountkey", parameters=parameters, assets=['gcp_iam'], callback=format_key_info_2, name="list_serviceaccountkey_2")

    return

"""
Format key fields from the compute instance metadata so they can be displayed in a prompt.
"""
def format_vm_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_vm_info() called')
    
    template = """Instance ID: {0}
Instance Name: {1}
Machine Type: {2}
Instance IP: {3}"""

    # parameter list for template variable replacement
    parameters = [
        "describe_instance_1:action_result.summary.id",
        "describe_instance_1:action_result.summary.name",
        "describe_instance_1:action_result.summary.machineType",
        "describe_instance_1:action_result.data.0.networkInterfaces.*.networkIP",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_vm_info", separator=", ")

    join_gcp_unusual_usage_keys_and_vm(container=container)

    return

"""
Format information about each service account key so it can be used in a prompt.
"""
def format_key_info_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_key_info_2() called')
    
    template = """%%
Key Name: {0}
Key Type: {1}
Key Origin: {2}
Key Algorithm: {3}
Valid After Time: {4}
Valid Before Time: {5}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "list_serviceaccountkey_2:action_result.data.0.keys.*.name",
        "list_serviceaccountkey_2:action_result.data.0.keys.*.keyType",
        "list_serviceaccountkey_2:action_result.data.0.keys.*.keyOrigin",
        "list_serviceaccountkey_2:action_result.data.0.keys.*.keyAlgorithm",
        "list_serviceaccountkey_2:action_result.data.0.keys.*.validAfterTime",
        "list_serviceaccountkey_2:action_result.data.0.keys.*.validBeforeTime",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_key_info_2", separator=", ")

    gcp_unusual_usage_keys(container=container)

    return

"""
Check the prompt response.
"""
def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["gcp_unusual_usage_keys_and_vm:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        delete_keys_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Check the prompt response.
"""
def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["gcp_unusual_usage_keys_and_vm:action_result.summary.responses.1", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        stop_instance_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Stop the compute instance referenced in the event.
"""
def stop_instance_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('stop_instance_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'stop_instance_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['describe_instance_1:action_result.parameter.zone', 'describe_instance_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'stop_instance_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': "",
                'zone': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="stop instance", parameters=parameters, assets=['gcp_compute'], name="stop_instance_1")

    return

"""
Use the formatted messages to prompt the analyst.
"""
def gcp_unusual_usage_keys(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('gcp_unusual_usage_keys() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """Unusual Google Cloud Compute Engine activity was detected. The service account in use has the following service account keys:
{0}

Should the associated service account keys be deleted to disable further access?"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="gcp_unusual_usage_keys", separator=", ", response_types=response_types, callback=decision_5)

    return

"""
Check the prompt response.
"""
def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["gcp_unusual_usage_keys:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        delete_keys_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

"""
Delete each of the offending service account keys.
"""
def delete_keys_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_keys_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delete_keys_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['list_serviceaccountkey_2:action_result.data.0.keys.*.name', 'list_serviceaccountkey_2:action_result.parameter.account', 'list_serviceaccountkey_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'delete_keys_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and results_item_1[1]:
            parameters.append({
                'key': results_item_1[0],
                'account': results_item_1[1],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="delete serviceaccountkey", parameters=parameters, assets=['gcp_iam'], name="delete_keys_2")

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