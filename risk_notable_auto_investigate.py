"""
This playbook implements an auto-investigate workflow based on a user-defined risk threshold.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'risk_rule_decision' block
    risk_rule_decision(container=container)

    return

def risk_rule_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_rule_decision() called")

    ################################################################################
    # Only proceeds if an artifact with the label "risk_rule" is not present.  
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "risk_rule"]
        ],
        scope="all")

    # call connected blocks if condition 1 matched
    if found_match_1:
        return

    # check for 'else' condition 2
    event_id_filter(action=action, success=success, container=container, results=results, handle=handle)

    return


def risk_notable_import_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_import_data() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/risk_notable_import_data", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/risk_notable_import_data", container=container, name="risk_notable_import_data", callback=update_preprocess_task)

    return


def dispatch_investigate_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_investigate_playbooks() called")

    playbook_tags_combined_value = phantom.concatenate("investigate", "risk_notable")

    inputs = {
        "playbook_repo": "local",
        "playbook_tags": playbook_tags_combined_value,
        "artifact_ids_include": "",
        "indicator_tags_exclude": "",
        "indicator_tags_include": "",
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_investigate_playbooks", callback=dispatch_investigate_playbooks_callback, inputs=inputs)

    return


def dispatch_investigate_playbooks_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_investigate_playbooks_callback() called")

    
    risk_notable_auto_merge(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    enrichment_output_decision(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def add_risk_investigation_workbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_risk_investigation_workbook() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Risk Investigation",
        "container": id_value,
        "start_workbook": True,
        "check_for_existing_workbook": True,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_add", parameters=parameters, name="add_risk_investigation_workbook", callback=start_preprocess_task)

    return


def start_preprocess_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("start_preprocess_task() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "in_progress",
        "container": id_value,
        "task_name": "Preprocess",
        "note_title": None,
        "note_content": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="start_preprocess_task", callback=risk_notable_preprocess)

    return


def update_preprocess_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_preprocess_task() called")

    id_value = container.get("id", None)
    risk_notable_import_data_output_note_title = phantom.collect2(container=container, datapath=["risk_notable_import_data:playbook_output:note_title"])
    risk_notable_import_data_output_note_content = phantom.collect2(container=container, datapath=["risk_notable_import_data:playbook_output:note_content"])

    parameters = []

    # build parameters list for 'update_preprocess_task' call
    for risk_notable_import_data_output_note_title_item in risk_notable_import_data_output_note_title:
        for risk_notable_import_data_output_note_content_item in risk_notable_import_data_output_note_content:
            parameters.append({
                "owner": None,
                "status": None,
                "container": id_value,
                "task_name": "Preprocess",
                "note_title": risk_notable_import_data_output_note_title_item[0],
                "note_content": risk_notable_import_data_output_note_content_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_preprocess_task", callback=mark_preprocess_evidence)

    return


def start_investigate_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("start_investigate_task() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "in_progress",
        "container": id_value,
        "task_name": "Investigate",
        "note_title": None,
        "note_content": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="start_investigate_task", callback=dispatch_investigate_playbooks)

    return


def update_investigate_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_investigate_task() called")

    id_value = container.get("id", None)
    dispatch_investigate_playbooks_output_sub_playbook_outputs = phantom.collect2(container=container, datapath=["dispatch_investigate_playbooks:playbook_output:sub_playbook_outputs.note_title","dispatch_investigate_playbooks:playbook_output:sub_playbook_outputs.note_content"])

    parameters = []

    # build parameters list for 'update_investigate_task' call
    for dispatch_investigate_playbooks_output_sub_playbook_outputs_item in dispatch_investigate_playbooks_output_sub_playbook_outputs:
        parameters.append({
            "owner": None,
            "status": None,
            "container": id_value,
            "task_name": "Investigate",
            "note_title": dispatch_investigate_playbooks_output_sub_playbook_outputs_item[0],
            "note_content": dispatch_investigate_playbooks_output_sub_playbook_outputs_item[1],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_investigate_task", callback=mark_update_investigate_evidence)

    return


def risk_notable_preprocess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_preprocess() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/risk_notable_preprocess", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/risk_notable_preprocess", container=container, name="risk_notable_preprocess", callback=risk_notable_import_data)

    return


def event_id_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("event_id_filter() called")

    ################################################################################
    # Isolate the artifact with a Notable event_id
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""]
        ],
        name="event_id_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        add_risk_investigation_workbook(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def update_notable(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_notable() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Update Splunk with any enrichment from the previous block
    ################################################################################

    dispatch_investigate_playbooks_output_sub_playbook_outputs = phantom.collect2(container=container, datapath=["dispatch_investigate_playbooks:playbook_output:sub_playbook_outputs"], scope="all")
    filtered_artifact_0_data_event_id_filter = phantom.collect2(container=container, datapath=["filtered-data:event_id_filter:condition_1:artifact:*.cef.event_id","filtered-data:event_id_filter:condition_1:artifact:*.id"], scope="all")

    parameters = []

    # build parameters list for 'update_notable' call
    for dispatch_investigate_playbooks_output_sub_playbook_outputs_item in dispatch_investigate_playbooks_output_sub_playbook_outputs:
        for filtered_artifact_0_item_event_id_filter in filtered_artifact_0_data_event_id_filter:
            if filtered_artifact_0_item_event_id_filter[0] is not None:
                parameters.append({
                    "comment": dispatch_investigate_playbooks_output_sub_playbook_outputs_item[0],
                    "event_ids": filtered_artifact_0_item_event_id_filter[0],
                    "context": {'artifact_id': filtered_artifact_0_item_event_id_filter[1]},
                })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_notable", assets=["splunk"])

    return


def risk_threshold_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_threshold_decision() called")

    ################################################################################
    # Determine if the Notable event risk score exceeds the provided risk threshold
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["sum_risk_score:custom_function:total_score", ">=", 250]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        close_preprocess(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 2
    update_investigate_task(action=action, success=success, container=container, results=results, handle=handle)

    return


def risk_notable_auto_containment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_auto_containment() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/risk_notable_auto_containment", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/risk_notable_auto_containment", container=container)

    return


def close_investigate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_investigate() called")

    id_value = container.get("id", None)
    dispatch_investigate_playbooks_output_sub_playbook_outputs = phantom.collect2(container=container, datapath=["dispatch_investigate_playbooks:playbook_output:sub_playbook_outputs.note_title","dispatch_investigate_playbooks:playbook_output:sub_playbook_outputs.note_content"])

    parameters = []

    # build parameters list for 'close_investigate' call
    for dispatch_investigate_playbooks_output_sub_playbook_outputs_item in dispatch_investigate_playbooks_output_sub_playbook_outputs:
        parameters.append({
            "owner": None,
            "status": "complete",
            "container": id_value,
            "task_name": "Investigate",
            "note_title": dispatch_investigate_playbooks_output_sub_playbook_outputs_item[0],
            "note_content": dispatch_investigate_playbooks_output_sub_playbook_outputs_item[1],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="close_investigate", callback=mark_close_investigate_evidence)

    return


def close_preprocess(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_preprocess() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "Preprocess",
        "note_title": None,
        "note_content": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="close_preprocess", callback=close_investigate)

    return


def render_verdict_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("render_verdict_note() called")

    ################################################################################
    # Format a note to explain why auto-containment was invoked.
    ################################################################################

    template = """## SOAR has invoked Auto-Containment\n## The risk rule artifacts have a deduplicated *{0}* points of risk which exceeds the user-defined critical threshold of *250* points\n\n## These detections contributed to auto-containment.\n| Score | Detection Source | Detection Message |\n| --- | --- | --- |\n%%\n| {1} | {2} | ```{3}```|\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "sum_risk_score:custom_function:total_score",
        "filtered-data:risk_rule_filter:condition_1:artifact:*.cef._total_risk_score",
        "filtered-data:risk_rule_filter:condition_1:artifact:*.name",
        "filtered-data:risk_rule_filter:condition_1:artifact:*.description"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="render_verdict_note", scope="all")

    close_render_verdict(container=container)

    return


def close_render_verdict(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_render_verdict() called")

    id_value = container.get("id", None)
    render_verdict_note = phantom.get_format_data(name="render_verdict_note")

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "Render Verdict",
        "note_title": "[Auto-Generated] Containment Required",
        "note_content": render_verdict_note,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="close_render_verdict", callback=risk_notable_auto_containment)

    return


def enrichment_output_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("enrichment_output_decision() called")

    ################################################################################
    # Determine if any playbooks produced a note for enrichment
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["dispatch_investigate_playbooks:playbook_output:sub_playbook_outputs.note_content", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        update_notable(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def mark_update_investigate_evidence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_update_investigate_evidence() called")

    id_value = container.get("id", None)
    update_investigate_task__result = phantom.collect2(container=container, datapath=["update_investigate_task:custom_function_result.data.note_id"])

    parameters = []

    # build parameters list for 'mark_update_investigate_evidence' call
    for update_investigate_task__result_item in update_investigate_task__result:
        parameters.append({
            "container": id_value,
            "content_type": "note_id",
            "input_object": update_investigate_task__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_update_investigate_evidence")

    return


def mark_close_investigate_evidence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_close_investigate_evidence() called")

    id_value = container.get("id", None)
    close_investigate__result = phantom.collect2(container=container, datapath=["close_investigate:custom_function_result.data.note_id"])

    parameters = []

    # build parameters list for 'mark_close_investigate_evidence' call
    for close_investigate__result_item in close_investigate__result:
        parameters.append({
            "container": id_value,
            "content_type": "note_id",
            "input_object": close_investigate__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_close_investigate_evidence", callback=render_verdict_note)

    return


def mark_preprocess_evidence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_preprocess_evidence() called")

    id_value = container.get("id", None)
    update_preprocess_task__result = phantom.collect2(container=container, datapath=["update_preprocess_task:custom_function_result.data.note_id"])

    parameters = []

    # build parameters list for 'mark_preprocess_evidence' call
    for update_preprocess_task__result_item in update_preprocess_task__result:
        parameters.append({
            "container": id_value,
            "content_type": "note_id",
            "input_object": update_preprocess_task__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_preprocess_evidence", callback=start_investigate_task)

    return


def risk_notable_auto_merge(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_auto_merge() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/risk_notable_auto_merge", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/risk_notable_auto_merge", container=container, name="risk_notable_auto_merge", callback=merge_result_decision)

    return


def merge_result_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_result_decision() called")

    ################################################################################
    # Determine if Auto Merge indicates that this event was merged into an existing 
    # investigation.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["risk_notable_auto_merge:playbook_output:merge_result", "!=", "merged into case"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        risk_rule_filter(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


def sum_risk_score(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("sum_risk_score() called")

    ################################################################################
    # Calculate a risk score based on all of the unique risk events
    ################################################################################

    filtered_artifact_0_data_risk_rule_filter = phantom.collect2(container=container, datapath=["filtered-data:risk_rule_filter:condition_1:artifact:*.cef._total_risk_score"], scope="all")

    filtered_artifact_0__cef__total_risk_score = [item[0] for item in filtered_artifact_0_data_risk_rule_filter]

    sum_risk_score__total_score = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    sum_risk_score__total_score = 0
    for score in filtered_artifact_0__cef__total_risk_score:
        sum_risk_score__total_score += float(score)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="sum_risk_score:total_score", value=json.dumps(sum_risk_score__total_score))

    risk_threshold_decision(container=container)

    return


def risk_rule_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_rule_filter() called")

    ################################################################################
    # Get all risk rule artifacts
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.label", "==", "risk_rule"]
        ],
        name="risk_rule_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        sum_risk_score(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

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