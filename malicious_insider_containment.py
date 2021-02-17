"""
This playbook demonstrates an automated response plan to handling malicious insiders within the environment.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_user_attributes_1' block
    get_user_attributes_1(container=container)

    # call 'task_1' block
    task_1(container=container)

    return

def get_user_attributes_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_user_attributes_1() called')

    # collect data for 'get_user_attributes_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_user_attributes_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'fields': "",
                'username': container_item[0],
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get user attributes", parameters=parameters, assets=['domainctrl1'], callback=format_ticket_description, name="get_user_attributes_1")

    return

def reset_password_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reset_password_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'reset_password_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['disable_user_1:action_result.parameter.username', 'disable_user_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'reset_password_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'username': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="reset password", parameters=parameters, assets=['domainctrl1'], callback=create_ticket_2, name="reset_password_1", parent_action=action)

    return

def create_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_2' call
    formatted_data_1 = phantom.get_format_data(name='format_ticket_description')

    parameters = []
    
    # build parameters list for 'create_ticket_2' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Malicious Insider Flagged - User Disabled and Password Reset",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=join_set_status_1, name="create_ticket_2", parent_action=action)

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_ticket_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_ticket_description')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'table': "incident",
        'fields': "",
        'vault_id': "",
        'description': formatted_data_1,
        'short_description': "Malicious Insider Identified - No Action Taken",
    })

    phantom.act(action="create ticket", parameters=parameters, assets=['servicenow'], callback=join_set_status_1, name="create_ticket_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        disable_user_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    create_ticket_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "admin"
    message = """The following user has been flagged as a malicious insider:
{0}

Do you want to proceed with disabling the user and resetting their password? 

Response should be: Yes/No"""

    # parameter list for template variable replacement
    parameters = [
        "get_user_attributes_1:action_result.parameter.username",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_1)

    return

def task_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('task_1() called')
    
    # set user and message variables for phantom.task call
    user = "admin"
    message = """Please notify the HR department of this malicious insider event."""

    phantom.task(user=user, message=message, respond_in_mins=30, name="task_1")

    return

def set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_status_1() called')

    phantom.set_status(container=container, status="closed")

    return

def join_set_status_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_set_status_1() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_set_status_1_called'):
        return

    # no callbacks to check, call connected block "set_status_1"
    phantom.save_run_data(key='join_set_status_1_called', value='set_status_1', auto=True)

    set_status_1(container=container, handle=handle)
    
    return

def disable_user_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('disable_user_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'disable_user_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_user_attributes_1:action_result.parameter.username', 'get_user_attributes_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'disable_user_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'username': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="disable user", parameters=parameters, assets=['domainctrl1'], callback=reset_password_1, name="disable_user_1")

    return

"""
Prepare the action results from the user lookup for the ticketing system.
"""
def format_ticket_description(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ticket_description() called')
    
    template = """The following is a dump of the attributes associated with the malicious user: 
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_user_attributes_1:action_result",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ticket_description")

    prompt_1(container=container)

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