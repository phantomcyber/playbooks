"""
This playbook de-escalates the severity level of a particular event based upon whether it's cef.sourceAddress is found in the custom list "test_machine_ips."  If the source address is not found within "test machine ips", and is not found in the custom list "non_test_machine_ips", a role is prompted as to whether the source address is a test machine.  If it is, it is added to the "test_machine_ips" custom list, and the severity of the event is set to LOW with a sensitivity of TLP:WHITE.  Otherwise, the source address is added to "non_test_machine_ips", and the playbook completes.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "custom_list:test_machine_ips"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        join_deescalate_alert(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    decision_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:non_test_machine_ips"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def Add_to_test_machine_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_to_test_machine_list() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_to_test_machine_list' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Add_to_test_machine_list' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'list': "custom_list:test_machine_ips",
                'create': True,
                'new_row': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="add listitem", parameters=parameters, assets=['helper'], callback=join_deescalate_alert, name="Add_to_test_machine_list")

    return

def Add_to_non_test_machine_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_to_non_test_machine_list() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Add_to_non_test_machine_list' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Add_to_non_test_machine_list' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'list': "custom_list:non_test_machine_ips",
                'create': True,
                'new_row': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="add listitem", parameters=parameters, assets=['helper'], name="Add_to_non_test_machine_list")

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "!=", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Add_to_test_machine_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Add_to_non_test_machine_list(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def deescalate_alert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deescalate_alert() called')

    phantom.set_sensitivity(container=container, sensitivity="white")

    phantom.set_severity(container=container, severity="low")

    return

def join_deescalate_alert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_deescalate_alert() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Add_to_test_machine_list']):
        
        # call connected block "deescalate_alert"
        deescalate_alert(container=container, handle=handle)
    
    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "Automation Engineer"
    message = """sourceAddress \"{0}\" has been compromised - is this a test machine?"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_4)

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