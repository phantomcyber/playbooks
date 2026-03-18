"""
This playbook classifies and labels email artifacts within a phishing report container by determining which email is the reporter&#39;s submission versus the suspicious forwarded email.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_email_artifacts_0' block
    filter_email_artifacts_0(container=container)

    return

@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["phishinginbox@splunk.com", "not in", "filtered-data:filter_email_artifacts_0:condition_1:artifact:*.cef.toEmail"],
            ["phishinginbox@splunk.com", "not in", "filtered-data:filter_email_artifacts_0:condition_1:artifact:*.cef.emailHeaders.CC"]
        ],
        conditions_dps=[
            ["phishinginbox@splunk.com", "not in", "filtered-data:filter_email_artifacts_0:condition_1:artifact:*.cef.toEmail"],
            ["phishinginbox@splunk.com", "not in", "filtered-data:filter_email_artifacts_0:condition_1:artifact:*.cef.emailHeaders.CC"]
        ],
        name="filter_1:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        attached_suspicious_email(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids and results for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        conditions=[
            ["phishinginbox@splunk.com", "in", "filtered-data:filter_email_artifacts_0:condition_1:artifact:*.cef.toEmail"]
        ],
        conditions_dps=[
            ["phishinginbox@splunk.com", "in", "filtered-data:filter_email_artifacts_0:condition_1:artifact:*.cef.toEmail"]
        ],
        name="filter_1:condition_2",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        reporter_email(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return


@phantom.playbook_block()
def filter_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_2() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["phishinginbox@splunk.com", "in", "filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail"],
            ["splunk.com", "in", "filtered-data:filter_1:condition_1:artifact:*.cef.toEmail"]
        ],
        conditions_dps=[
            ["phishinginbox@splunk.com", "in", "filtered-data:filter_1:condition_1:artifact:*.cef.fromEmail"],
            ["splunk.com", "in", "filtered-data:filter_1:condition_1:artifact:*.cef.toEmail"]
        ],
        name="filter_2:condition_1",
        delimiter=",")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        internal_response_email(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def reporter_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("reporter_email() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_2:artifact:*.id","filtered-data:filter_1:condition_2:artifact:*.id"])

    parameters = []

    # build parameters list for 'reporter_email' call
    for filtered_artifact_0_item_filter_1 in filtered_artifact_0_data_filter_1:
        parameters.append({
            "name": "Reporter Email",
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_filter_1[0],
            "cef_data_type": None,
            "overwrite_tags": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="reporter_email")

    return


@phantom.playbook_block()
def internal_response_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("internal_response_email() called")

    filtered_artifact_0_data_filter_2 = phantom.collect2(container=container, datapath=["filtered-data:filter_2:condition_1:artifact:*.id","filtered-data:filter_2:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'internal_response_email' call
    for filtered_artifact_0_item_filter_2 in filtered_artifact_0_data_filter_2:
        parameters.append({
            "name": "Phishing Pond Response Email",
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_filter_2[0],
            "cef_data_type": None,
            "overwrite_tags": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="internal_response_email")

    return


@phantom.playbook_block()
def attached_suspicious_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("attached_suspicious_email() called")

    filtered_artifact_0_data_filter_1 = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:artifact:*.id","filtered-data:filter_1:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'attached_suspicious_email' call
    for filtered_artifact_0_item_filter_1 in filtered_artifact_0_data_filter_1:
        parameters.append({
            "name": "Attached Suspicious Email",
            "tags": None,
            "label": None,
            "severity": None,
            "cef_field": None,
            "cef_value": None,
            "input_json": None,
            "artifact_id": filtered_artifact_0_item_filter_1[0],
            "cef_data_type": None,
            "overwrite_tags": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="attached_suspicious_email", callback=filter_2)

    return


@phantom.playbook_block()
def filter_email_artifacts_0(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_email_artifacts_0() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["Email", "in", "artifact:*.name"]
        ],
        conditions_dps=[
            ["Email", "in", "artifact:*.name"]
        ],
        name="filter_email_artifacts_0:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

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

    return