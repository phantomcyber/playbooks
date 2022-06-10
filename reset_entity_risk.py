"""
This playbook grabs all of the contributing risk_rules in the event that haven&#39;t had a risk score reset. It then posts negating risk scores to Splunk after prompting the user for a reason. If no risk rules are present, a comment will be left.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'risk_rule_decision' block
    risk_rule_decision(container=container)

    return

def risk_rule_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_rule_filter() called")

    ################################################################################
    # Grab the available risk rules without a risk score and send them to custom format.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.label", "==", "risk_rule"],
            ["artifact:*.cef._risk_score_reset", "==", ""],
            ["reset_prompt:action_result.status", "==", "success"]
        ],
        name="risk_rule_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        custom_format(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def custom_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("custom_format() called")

    ################################################################################
    # Generate new Splunk events with the correct timestamp and negative risk score.
    ################################################################################

    id_value = container.get("id", None)
    name_value = container.get("name", None)
    filtered_artifact_0_data_risk_rule_filter = phantom.collect2(container=container, datapath=["filtered-data:risk_rule_filter:condition_1:artifact:*.name","filtered-data:risk_rule_filter:condition_1:artifact:*.description","filtered-data:risk_rule_filter:condition_1:artifact:*.data","filtered-data:risk_rule_filter:condition_1:artifact:*.cef"])
    reset_prompt_result_data = phantom.collect2(container=container, datapath=["reset_prompt:action_result.data.*.user","reset_prompt:action_result.summary.responses.0"], action_results=results)

    filtered_artifact_0__name = [item[0] for item in filtered_artifact_0_data_risk_rule_filter]
    filtered_artifact_0__description = [item[1] for item in filtered_artifact_0_data_risk_rule_filter]
    filtered_artifact_0__data = [item[2] for item in filtered_artifact_0_data_risk_rule_filter]
    filtered_artifact_0__cef = [item[3] for item in filtered_artifact_0_data_risk_rule_filter]
    reset_prompt_result_item_0 = [item[0] for item in reset_prompt_result_data]
    reset_prompt_summary_responses_0 = [item[1] for item in reset_prompt_result_data]

    custom_format__splunk_event = None
    custom_format__current_time = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from datetime import datetime
    custom_format__current_time = str(datetime.now())
    custom_format__splunk_event = []
    
    for name, description, artifact_cef, artifact_data in zip(filtered_artifact_0__name, filtered_artifact_0__description, filtered_artifact_0__cef, filtered_artifact_0__data):
        risk_event_data = [item['risk_event'] for item in artifact_data if item.get('risk_event')] 
        if (
            artifact_cef.keys() >= {'_total_risk_score', 'risk_object', 'risk_object_type'}
            and risk_event_data
        ):
            for risk_event in risk_event_data:
                risk_event_id = risk_event['id']
                timestamp = risk_event['timestamp']
                close_reason = reset_prompt_summary_responses_0[0]
                risk_score = (float(artifact_cef['_total_risk_score']) / int(artifact_cef['_event_count'])) * -1
                risk_object = artifact_cef['risk_object']
                risk_object_type = artifact_cef['risk_object_type']
                owner_name_value = reset_prompt_result_item_0[0]
                log_template = (
                    f'{timestamp}, risk_score="{risk_score}", risk_event_id="{risk_event_id}", '
                    f' risk_object="{risk_object}", risk_object_type="{risk_object_type}",'
                    f' close_reason="{close_reason}", close_action_owner="{owner_name_value}", close_time="{custom_format__current_time}", '
                    f' search_name="{name}", risk_message="{description}", soar_event_id="{id_value}", soar_event_name="{name_value}"'
                )
                custom_format__splunk_event.append(log_template)
    
    custom_format__splunk_event = '\r\n'.join(custom_format__splunk_event)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="custom_format:splunk_event", value=json.dumps(custom_format__splunk_event))
    phantom.save_run_data(key="custom_format:current_time", value=json.dumps(custom_format__current_time))

    post_negative_risk_event(container=container)

    return


def risk_rule_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_rule_decision() called")

    ################################################################################
    # Determine if at least one risk_rule exists that hasn't been risk score reset.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["artifact:*.label", "==", "risk_rule"],
            ["artifact:*.cef._risk_score_reset", "==", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        reset_prompt(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    add_not_found_comment(action=action, success=success, container=container, results=results, handle=handle)

    return


def reset_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("reset_prompt() called")

    ################################################################################
    # Prompt the user for required information about the reason for close. This will 
    # be used for the message in the raw event.
    ################################################################################

    # set user and message variables for phantom.prompt call

    user_id = phantom.get_effective_user()
    url = phantom.build_phantom_rest_url('ph_user', user_id)
    response = phantom.requests.get(url, verify=False).json()
    user = response['username']
    message = """Enter a reason for resetting risk."""

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Reason",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="reset_prompt", parameters=parameters, response_types=response_types, callback=risk_rule_filter)

    return

def post_negative_risk_event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("post_negative_risk_event() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Post all of the negative risk events as one block into the risk index that is 
    # new line separated.
    ################################################################################

    custom_format__splunk_event = json.loads(phantom.get_run_data(key="custom_format:splunk_event"))

    parameters = []

    if custom_format__splunk_event is not None:
        parameters.append({
            "data": custom_format__splunk_event,
            "index": "risk",
            "source": "Splunk SOAR",
            "source_type": "stash",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("post data", parameters=parameters, name="post_negative_risk_event", assets=["splunk"], callback=artifact_add_reset_field)

    return


def add_not_found_comment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_not_found_comment() called")

    ################################################################################
    # Adds a comment that let's the user know that this playbook terminated due to 
    # criteria not met.
    ################################################################################

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.comment(container=container, comment="Risk score already reset for the provided artifacts")

    return


def artifact_add_reset_field(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("artifact_add_reset_field() called")

    filtered_artifact_0_data_risk_rule_filter = phantom.collect2(container=container, datapath=["filtered-data:risk_rule_filter:condition_1:artifact:*.id","filtered-data:risk_rule_filter:condition_1:artifact:*.id"])
    custom_format__current_time = json.loads(phantom.get_run_data(key="custom_format:current_time"))

    parameters = []

    # build parameters list for 'artifact_add_reset_field' call
    for filtered_artifact_0_item_risk_rule_filter in filtered_artifact_0_data_risk_rule_filter:
        parameters.append({
            "artifact_id": filtered_artifact_0_item_risk_rule_filter[0],
            "name": None,
            "label": None,
            "severity": None,
            "cef_field": "_risk_score_reset",
            "cef_value": custom_format__current_time,
            "cef_data_type": None,
            "tags": None,
            "overwrite_tags": None,
            "input_json": None,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_update", parameters=parameters, name="artifact_add_reset_field")

    return


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