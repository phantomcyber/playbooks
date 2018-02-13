"""
This playbook will operate on infected sourceAddress CEF values and determine if it is a new infection or repeat by checking the sourceAddress against the infected_endpoint custom list.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def add_endpoint_to_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('add_endpoint_to_list() called')

    # collect data for 'add_endpoint_to_list' call
    filtered_artifacts_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_2:condition_2:artifact:*.cef.sourceAddress', 'filtered-data:filter_2:condition_2:artifact:*.id'])

    parameters = []
    
    # build parameters list for 'add_endpoint_to_list' call
    for filtered_artifacts_item_1 in filtered_artifacts_data_1:
        if filtered_artifacts_item_1[0]:
            parameters.append({
                'list': "infected_endpoints",
                'create': "",
                'new_row': filtered_artifacts_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_artifacts_item_1[1]},
            })

    phantom.act("add listitem", parameters=parameters, assets=['helper'], callback=format_2, name="add_endpoint_to_list")

    return

def format_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_2() called')
    
    template = """The following infected endpoints are new infection instances and have been added to the infected_endpoints custom list:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_2:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_2")

    create_ticket_2(container=container)

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
        filter_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2
    join_close_container(action=action, success=success, container=container, results=results, handle=handle)

    return

def close_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('close_container() called')

    phantom.set_status(container, "closed")

    return

def join_close_container(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('join_close_container() called')

    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'create_ticket_2', 'create_ticket_1' ]):
        
        # call connected block "close_container"
        close_container(container=container, handle=handle)
    
    return

def format_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('format_1() called')
    
    template = """The following infected endpoints are repeat offenders who have matched on the infected_endpoints custom list:
{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_2:condition_1:artifact:*.cef.sourceAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_1")

    create_ticket_1(container=container)

    return

def create_ticket_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_ticket_1() called')

    # collect data for 'create_ticket_1' call
    formatted_data_1 = phantom.get_format_data(name='format_1')

    parameters = []
    
    # build parameters list for 'create_ticket_1' call
    parameters.append({
        'short_description': "Reinfected Endpoint Instance",
        'table': "",
        'vault_id': "",
        'description': formatted_data_1,
        'fields': "",
    })

    phantom.act("create ticket", parameters=parameters, assets=['servicenow'], callback=join_close_container, name="create_ticket_1")

    return

def create_ticket_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('create_ticket_2() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_ticket_2' call
    formatted_data_1 = phantom.get_format_data(name='format_2')

    parameters = []
    
    # build parameters list for 'create_ticket_2' call
    parameters.append({
        'short_description': "New Infected Endpoints",
        'table': "",
        'vault_id': "",
        'description': formatted_data_1,
        'fields': "",
    })

    phantom.act("create ticket", parameters=parameters, assets=['servicenow'], callback=join_close_container, name="create_ticket_2")

    return

def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('filter_2() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "in", "custom_list:infected_endpoints"],
        ],
        name="filter_2:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.sourceAddress", "not in", "custom_list:infected_endpoints"],
        ],
        name="filter_2:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        add_endpoint_to_list(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

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