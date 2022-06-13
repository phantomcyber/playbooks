"""
Gather intelligence about one or more URLs, tag the URL indicators with priority scores, and return a verdict that can be used in other playbooks or analyst actions.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'indicator_reputation_1' block
    indicator_reputation_1(container=container)

    return

def indicator_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_reputation_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Gather intelligence about the URL from Splunk Intelligence Management (formerly 
    # known as TruSTAR).
    ################################################################################

    playbook_input_url = phantom.collect2(container=container, datapath=["playbook_input:url"])

    parameters = []

    # build parameters list for 'indicator_reputation_1' call
    for playbook_input_url_item in playbook_input_url:
        if playbook_input_url_item[0] is not None:
            parameters.append({
                "limit": 10000,
                "indicator_value": playbook_input_url_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("indicator reputation", parameters=parameters, name="indicator_reputation_1", assets=["trustar"], callback=indicator_reputation_1_callback)

    return


def indicator_reputation_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_reputation_1_callback() called")

    
    tag_with_priority_score(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    filter_medium_or_higher(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def tag_with_priority_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_with_priority_score() called")

    indicator_reputation_1_result_data = phantom.collect2(container=container, datapath=["indicator_reputation_1:action_result.data.*.priorityScore","indicator_reputation_1:action_result.parameter.indicator_value","indicator_reputation_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'tag_with_priority_score' call
    for indicator_reputation_1_result_item in indicator_reputation_1_result_data:
        parameters.append({
            "tags": indicator_reputation_1_result_item[0],
            "indicator": indicator_reputation_1_result_item[1],
            "overwrite": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_tag", parameters=parameters, name="tag_with_priority_score")

    return


def format_verdict(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_verdict() called")

    ################################################################################
    # Create a formatted text block to return as a verdict, including each URL with 
    # a priority score of MEDIUM or higher.
    ################################################################################

    template = """%%\n| {0} :: {1} |\n%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_medium_or_higher:condition_1:indicator_reputation_1:action_result.parameter.indicator_value",
        "filtered-data:filter_medium_or_higher:condition_1:indicator_reputation_1:action_result.data.*.priorityScore"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_verdict")

    return


def filter_medium_or_higher(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("filter_medium_or_higher() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["indicator_reputation_1:action_result.data.*.priorityScore", "==", "MEDIUM"],
            ["indicator_reputation_1:action_result.data.*.priorityScore", "==", "HIGH"],
            ["indicator_reputation_1:action_result.data.*.priorityScore", "==", "CRITICAL"]
        ],
        name="filter_medium_or_higher:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_verdict(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_verdict = phantom.get_format_data(name="format_verdict")

    output = {
        "verdict": format_verdict,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return