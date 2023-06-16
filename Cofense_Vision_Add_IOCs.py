"""
Add or update IOCs in Cofense Vision.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'please_provide_inputs_to_create_or_update_the_iocs' block
    please_provide_inputs_to_create_or_update_the_iocs(container=container)

    return

@phantom.playbook_block()
def please_provide_inputs_to_create_or_update_the_iocs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("please_provide_inputs_to_create_or_update_the_iocs() called")

    # set user and message variables for phantom.prompt call

    user = None
    role = "Administrator"
    message = """Please provide values to create/update the IOCs.\nNote: For optional parameters, please provide space for blank input."""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Source (required)",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Threat Type (required)",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Threat Value (required)",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Threat Level (required)",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Created At (required)",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Updated At",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Source ID (required)",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Requested Expiration",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=30, name="please_provide_inputs_to_create_or_update_the_iocs", parameters=parameters, response_types=response_types, callback=decision_1)

    return


@phantom.playbook_block()
def update_iocs_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_iocs_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    please_provide_inputs_to_create_or_update_the_iocs_result_data = phantom.collect2(container=container, datapath=["please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.0","please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.6","please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.4","please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.5","please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.1","please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.3","please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.2","please_provide_inputs_to_create_or_update_the_iocs:action_result.summary.responses.7","please_provide_inputs_to_create_or_update_the_iocs:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'update_iocs_1' call
    for please_provide_inputs_to_create_or_update_the_iocs_result_item in please_provide_inputs_to_create_or_update_the_iocs_result_data:
        if please_provide_inputs_to_create_or_update_the_iocs_result_item[0] is not None:
            parameters.append({
                "source": please_provide_inputs_to_create_or_update_the_iocs_result_item[0],
                "iocs_json": "",
                "source_id": please_provide_inputs_to_create_or_update_the_iocs_result_item[1],
                "created_at": please_provide_inputs_to_create_or_update_the_iocs_result_item[2],
                "updated_at": please_provide_inputs_to_create_or_update_the_iocs_result_item[3],
                "threat_type": please_provide_inputs_to_create_or_update_the_iocs_result_item[4],
                "threat_level": please_provide_inputs_to_create_or_update_the_iocs_result_item[5],
                "threat_value": please_provide_inputs_to_create_or_update_the_iocs_result_item[6],
                "requested_expiration": please_provide_inputs_to_create_or_update_the_iocs_result_item[7],
                "context": {'artifact_id': please_provide_inputs_to_create_or_update_the_iocs_result_item[8]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update iocs", parameters=parameters, name="update_iocs_1", assets=["cofense_vision"])

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["please_provide_inputs_to_create_or_update_the_iocs:action_result.status", "==", "success"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_iocs_1(action=action, success=success, container=container, results=results, handle=handle)
        return

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