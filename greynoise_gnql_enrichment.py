"""
Runs a GNQL query of classification:malicious metadata.rdns:*.gov*, which returns all compromised devices that include .gov in their reverse DNS records. If an IP in that response matches the event IP, it is promoted to a case and set to high severity. If it is not, the event severity is set to low.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'gnql_query_1' block
    gnql_query_1(container=container)

    return

def gnql_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('gnql_query_1() called')

    # collect data for 'gnql_query_1' call

    parameters = []
    
    # build parameters list for 'gnql_query_1' call
    parameters.append({
        'size': 100,
        'query': "classification:malicious metadata.rdns:*.gov*",
    })

    phantom.act(action="gnql query", parameters=parameters, assets=['greynoise'], callback=decision_1, name="gnql_query_1")

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["gnql_query_1:action_result.data.*.ip", "==", "artifact:*.cef.sourceAddress"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        promote_to_case(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        set_severity_high(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    set_severity_low(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def promote_to_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('promote_to_case() called')

    phantom.promote(container=container, template="Network Indicator Enrichment")

    return

def set_severity_high(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_high() called')

    phantom.set_severity(container=container, severity="High")

    return

def set_severity_low(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_severity_low() called')

    phantom.set_severity(container=container, severity="Low")

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