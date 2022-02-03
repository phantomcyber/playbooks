"""
This playbook allows automatic progression through the Risk Investigation workbook by starting and updating tasks.
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
    workbook_add(action=action, success=success, container=container, results=results, handle=handle)

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

    # call playbook "community/risk_notable_import_data", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/risk_notable_import_data", container=container, name="risk_notable_import_data", callback=update_preprocess_task)

    return


def risk_notable_enrich(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("risk_notable_enrich() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/risk_notable_enrich", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/risk_notable_enrich", container=container, name="risk_notable_enrich", callback=update_investigate_task)

    return


def workbook_add(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_add() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Risk Investigation",
        "container": id_value,
        "start_workbook": "true",
        "check_for_existing_workbook": "true",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_add", parameters=parameters, name="workbook_add", callback=start_preprocess_task)

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

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_preprocess_task", callback=start_investigate_task)

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

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="start_investigate_task", callback=risk_notable_enrich)

    return


def update_investigate_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_investigate_task() called")

    id_value = container.get("id", None)
    risk_notable_enrich_output_note_title = phantom.collect2(container=container, datapath=["risk_notable_enrich:playbook_output:note_title"])
    risk_notable_enrich_output_note_content = phantom.collect2(container=container, datapath=["risk_notable_enrich:playbook_output:note_content"])

    parameters = []

    # build parameters list for 'update_investigate_task' call
    for risk_notable_enrich_output_note_title_item in risk_notable_enrich_output_note_title:
        for risk_notable_enrich_output_note_content_item in risk_notable_enrich_output_note_content:
            parameters.append({
                "owner": None,
                "status": None,
                "container": id_value,
                "task_name": "Investigate",
                "note_title": risk_notable_enrich_output_note_title_item[0],
                "note_content": risk_notable_enrich_output_note_content_item[0],
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    parameters = []
    for idx, title_item in enumerate(risk_notable_enrich_output_note_title):
        parameters.append({
                "owner": None,
                "status": None,
                "container": id_value,
                "task_name": "Investigate",
                "note_title": risk_notable_enrich_output_note_title[idx][0],
                "note_content": risk_notable_enrich_output_note_content[idx][0],
            })


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="update_investigate_task")

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