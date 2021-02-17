"""
This Playbook utilizes DomainTools to generate the risk level of a domain, and, if a high enough score, blocks the domain on OpenDNS Umbrella for 60 minutes, after approval via user prompt of a role.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'domain_reputation_1' block
    domain_reputation_1(container=container)

    return

def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')

    # collect data for 'domain_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                'use_risk_api': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="domain reputation", parameters=parameters, assets=['domaintools'], callback=decision_2, name="domain_reputation_1")

    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation_1:action_result.data.*.risk_score", ">=", 80],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def prompt_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_1() called')
    
    # set user and message variables for phantom.prompt call
    user = "Automation Engineer"
    message = """The risk score of {0} has been evaluated by DomainTools Domain Reputation as {1}, which exceeds the Playbook's defined threshold.  Would you like to block this domain?"""

    # parameter list for template variable replacement
    parameters = [
        "domain_reputation_1:action_result.parameter.domain",
        "domain_reputation_1:action_result.data.*.risk_score",
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

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=60, name="prompt_1", parameters=parameters, response_types=response_types, callback=decision_3)

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["prompt_1:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        block_domain_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def unblock_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unblock_domain_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'unblock_domain_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['block_domain_1:action_result.parameter.domain', 'block_domain_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'unblock_domain_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'domain': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })
    # calculate start time using delay of 60 minutes
    start_time = datetime.now() + timedelta(minutes=60)

    phantom.act(action="unblock domain", parameters=parameters, assets=['opendns_umbrella'], start_time=start_time, name="unblock_domain_1", parent_action=action)

    return

def block_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('block_domain_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'block_domain_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['domain_reputation_1:action_result.parameter.domain', 'domain_reputation_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'block_domain_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'domain': results_item_1[0],
                'disable_safeguards': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="block domain", parameters=parameters, assets=['opendns_umbrella'], callback=unblock_domain_1, name="block_domain_1")

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