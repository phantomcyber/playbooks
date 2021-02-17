"""
This playbook demonstrates an automated response when a mobile device is lost or stolen.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'list_mobile_devices' block
    list_mobile_devices(container=container)

    return

def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_1() called')

    phantom.set_status(container=container, status="closed")

    return

def join_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_status_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['create_ticket_3', 'create_ticket_2', 'create_ticket_1']):
        
        # call connected block "set_status_1"
        set_status_1(container=container, handle=handle)
    
    return

def reset_password_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_password_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'reset_password_2' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_2:get_user_attributes_1:action_result.parameter.username", "filtered-data:filter_3:condition_2:get_user_attributes_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'reset_password_2' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'username': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="reset password", parameters=parameters, assets=['domainctrl1'], callback=executive_reset, name="reset_password_2")

    return

def list_mobile_devices(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('list_mobile_devices() called')

    # collect data for 'list_mobile_devices' call

    parameters = []
    
    # build parameters list for 'list_mobile_devices' call
    parameters.append({
        'limit': 500000,
        'start_index': 1,
    })

    phantom.act(action="list devices", parameters=parameters, assets=['mobileiron'], callback=filter_1, name="list_mobile_devices")

    return

def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attributes_1:action_result.parameter.username", "not in", "custom_list:executives"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        reset_password_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["get_user_attributes_1:action_result.parameter.username", "in", "custom_list:executives"],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def lock_device_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lock_device_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'lock_device_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:list_mobile_devices:action_result.data.*.uuid", "filtered-data:filter_1:condition_1:list_mobile_devices:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'lock_device_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'uuid': filtered_results_item_1[0],
                'reason': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="lock device", parameters=parameters, assets=['mobileiron'], callback=get_user_attributes_1, name="lock_device_1")

    return

def reset_password_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_password_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'reset_password_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_3:condition_1:get_user_attributes_1:action_result.parameter.username", "filtered-data:filter_3:condition_1:get_user_attributes_1:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'reset_password_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'username': filtered_results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="reset password", parameters=parameters, assets=['domainctrl1'], callback=non_executive_reset, name="reset_password_1")

    return

def create_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_2' call
    formatted_data_1 = phantom.get_format_data(name='executive_reset')

    parameters = []
    
    # build parameters list for 'create_ticket_2' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Lost/Stolen Mobile Device",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=join_set_status_1, name="create_ticket_2")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", 1],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        reset_password_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", 2],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        not_reset(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The following user has lost his/her device: 

{0}

This user is part of the executive team.  Do you wish to: 
1. Reset the user password and file ticket
2. Take no immediate action and file ticket

Please response with a 1 or 2."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_2:get_user_attributes_1:action_result.parameter.username",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "range",
                "min": 1,
                "max": 100,
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_mobile_devices:action_result.data.*.uuid", "==", "artifact:*.cef.deviceExternalId"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        lock_device_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def create_ticket_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_3' call
    formatted_data_1 = phantom.get_format_data(name='non_executive_reset')

    parameters = []
    
    # build parameters list for 'create_ticket_3' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Lost/Stolen Mobile Device",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=join_set_status_1, name="create_ticket_3")

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='not_reset')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Lost/Stolen Mobile Device",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=join_set_status_1, name="create_ticket_1")

    return

def get_user_attributes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attributes_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_user_attributes_1' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:list_mobile_devices:action_result.data.*.userId", "filtered-data:filter_1:condition_1:list_mobile_devices:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'get_user_attributes_1' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'fields': "",
                'username': filtered_results_item_1[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, assets=['domainctrl1'], callback=filter_3, name="get_user_attributes_1", parent_action=action)

    return

"""
Format text and data in preparation for filing a ticket.
"""
def non_executive_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('non_executive_reset() called')
    
    template = """The following user has reported a lost or stolen device and their password has been reset:
{0}

The UUID of the device lost or stolen is: 
{1}

This user is not part of the executive team."""

    # parameter list for template variable replacement
    parameters = [
        "reset_password_1:action_result.parameter.username",
        "filtered-data:filter_1:condition_1:list_mobile_devices:action_result.data.*.uuid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="non_executive_reset")

    create_ticket_3(container=container)

    return

"""
Format text and data in preparation for filing a ticket.
"""
def executive_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('executive_reset() called')
    
    template = """The following user has reported a lost or stolen device and their password has been reset:
{0}

The UUID of the device lost or stolen is: 
{1}

This user is a member of the executive team.
{1}"""

    # parameter list for template variable replacement
    parameters = [
        "reset_password_2:action_result.parameter.username",
        "filtered-data:filter_1:condition_1:list_mobile_devices:action_result.data.*.uuid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="executive_reset")

    create_ticket_2(container=container)

    return

"""
Format text and data for ticket when the password is not reset.
"""
def not_reset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_reset() called')
    
    template = """The following user has reported a lost or stolen device and it was decided to not reset their password:
{0}

The UUID of the device lost or stolen is: 
{1}

This user is a member of the executive team.  Further action must be taken as the password for the user has not be reset."""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_2:get_user_attributes_1:action_result.parameter.username",
        "filtered-data:filter_1:condition_1:list_mobile_devices:action_result.data.*.uuid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="not_reset")

    create_ticket_1(container=container)

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