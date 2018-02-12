"""
This playbook automatically escalates an event's severity and sensitivity based upon the cef.suser found in the artifact.  This cef.suser is then used to list groups that the user belongs to using the LDAP app; if one of those groups is the "Executive" group, then the event is escalated to Severity "High" with TLP:RED as the sensitivity.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def escalate_alert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('escalate_alert() called')

    phantom.set_sensitivity(container, "red")

    phantom.set_severity(container, "high")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.suser", "!=", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        list_user_groups_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["list_user_groups_1:action_result.summary.total_groups", ">", 0],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        decision_4(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["CN=Executive", "in", "list_user_groups_1:action_result.data.*.group"],
        ])

    # call connected blocks if condition 1 matched
    if matched_artifacts_1 or matched_results_1:
        escalate_alert(action=action, success=success, container=container, results=results, handle=handle)
        return

    # call connected blocks for 'else' condition 2

    return

def list_user_groups_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    phantom.debug('list_user_groups_1() called')

    # collect data for 'list_user_groups_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.suser', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'list_user_groups_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'username': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act("list user groups", parameters=parameters, assets=['domainctrl1'], callback=decision_3, name="list_user_groups_1")

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