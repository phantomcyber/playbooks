"""
Retrieve AI-Generated meeting summary and actions items using its recording ID and site url
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'filter_1' block
    filter_1(container=container)

    return

@phantom.playbook_block()
def ai_meeting_summary_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ai_meeting_summary_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    filtered_input_0_site_url = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:site_url"])
    filtered_input_1_recording_id = phantom.collect2(container=container, datapath=["filtered-data:filter_1:condition_1:playbook_input:recording_id"])

    parameters = []

    # build parameters list for 'ai_meeting_summary_1' call
    for filtered_input_0_site_url_item in filtered_input_0_site_url:
        for filtered_input_1_recording_id_item in filtered_input_1_recording_id:
            if filtered_input_0_site_url_item[0] is not None and filtered_input_1_recording_id_item[0] is not None:
                parameters.append({
                    "site_url": filtered_input_0_site_url_item[0],
                    "recording_id": filtered_input_1_recording_id_item[0],
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ai meeting summary", parameters=parameters, name="ai_meeting_summary_1", assets=["marks-personal-webex"], callback=add_note_1)

    return


@phantom.playbook_block()
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("filter_1() called")

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="and",
        conditions=[
            ["playbook_input:recording_id", "!=", ""],
            ["playbook_input:site_url", "!=", ""]
        ],
        conditions_dps=[
            ["playbook_input:recording_id", "!=", ""],
            ["playbook_input:site_url", "!=", ""]
        ],
        name="filter_1:condition_1",
        delimiter=None)

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        ai_meeting_summary_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


@phantom.playbook_block()
def add_note_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("add_note_1() called")

    ai_meeting_summary_1_result_data = phantom.collect2(container=container, datapath=["ai_meeting_summary_1:action_result.data.*.summary"], action_results=results)

    ai_meeting_summary_1_result_item_0 = [item[0] for item in ai_meeting_summary_1_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_note(container=container, content=ai_meeting_summary_1_result_item_0, note_format="markdown", note_type="general", title="Webex Meeting Summary")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    return