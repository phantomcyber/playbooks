"""
This playbook will operate on infected sourceAddress CEF values and determine if it is a new infection or a repeat by checking the sourceAddress against the infected_endpoint custom list, prompting users within a particular role as to whether to contain the infection or not.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def create_infected_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_infected_ticket() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_infected_ticket' call
    formatted_data_1 = phantom.get_format_data(name='initial_endpoint_infection')

    parameters = []
    
    # build parameters list for 'create_infected_ticket' call
    parameters.append({
        'parent_group': "",
        'name': formatted_data_1,
    })

    phantom.act("create ticket", parameters=parameters, assets=['arcsight_esm'], callback=format_list_item, name="create_infected_ticket")

    return

def add_list_item(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_list_item() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_list_item' call
    formatted_data_1 = phantom.get_format_data(name='format_list_item')

    parameters = []
    
    # build parameters list for 'add_list_item' call
    parameters.append({
        'list': "infected_endpoints",
        'create': True,
        'new_row': formatted_data_1,
    })

    phantom.act("add listitem", parameters=parameters, assets=['helper'], callback=join_set_status_2, name="add_list_item", parent_action=action)

    return

def initial_endpoint_infection(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('initial_endpoint_infection() called')
    
    template = """Contain Endpoint At {0}"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="initial_endpoint_infection")

    create_infected_ticket(container=container)

    return

def reinfected_endpoint(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('reinfected_endpoint() called')
    
    template = """Contain Reinfected Endpoint At {0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_2:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reinfected_endpoint")

    create_reinfected_ticket(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        endpoint_infection_ticket_approval(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_set_status_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('set_status_2() called')

    phantom.set_status(container, "closed")

    return

def join_set_status_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_set_status_2() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'endpoint_infection_ticket_approval', 'add_list_item', 'create_reinfected_ticket' ]):
        
        # call connected block "set_status_2"
        set_status_2(container=container, handle=handle)
    
    return

def endpoint_infection_ticket_approval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('endpoint_infection_ticket_approval() called')
    
    # set user and message variables for phantom.prompt call
    user = "Incident Commander"
    message = """Endpoint at {0} has been deemed infected.  Would you like to create a ticket to contain this infection?"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.sourceAddress",
    ]

    # response options
    options = {
        "type": "list",
        "choices": [
            "Yes",
            "No",
        ]
    }

    phantom.prompt(container=container, user=user, message=message, respond_in_mins=60, name="endpoint_infection_ticket_approval", parameters=parameters, options=options, callback=decision_2)

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["endpoint_infection_ticket_approval:action_result.summary.response", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_set_status_2(action=action, success=success, container=container, results=results, handle=handle)

    return

def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:infected_endpoints"],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        initial_endpoint_infection(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "custom_list:infected_endpoints"],
        ],
        name="filter_1:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        reinfected_endpoint(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

def create_reinfected_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_reinfected_ticket() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_reinfected_ticket' call
    formatted_data_1 = phantom.get_format_data(name='reinfected_endpoint')

    parameters = []
    
    # build parameters list for 'create_reinfected_ticket' call
    parameters.append({
        'parent_group': "All Cases/All Cases",
        'name': formatted_data_1,
    })

    phantom.act("create ticket", parameters=parameters, assets=['arcsight_esm'], callback=join_set_status_2, name="create_reinfected_ticket")

    return

def format_list_item(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_list_item() called')
    
    template = """[\"{0}\"]"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_1:condition_1:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_list_item")

    add_list_item(container=container)

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