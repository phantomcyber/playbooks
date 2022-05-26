"""
This playbook finds similar or duplicate events based on the risk_object field in a Risk Notable. If two or more events are found with no case, a case will be created with the current container. If a case is found, this container will be merged with the case. 
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'find_related_events' block
    find_related_events(container=container)

    return

def related_events_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("related_events_decision() called")

    ################################################################################
    # Determines if one of the related events is a case
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["find_related_events:custom_function_result.data.*.container_type", "==", "case"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        expand_results(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2
    found_match_2 = phantom.decision(
        container=container,
        conditions=[
            ["find_related_events:custom_function_result.data.*.container_id", "!=", ""]
        ])

    # call connected blocks if condition 2 matched
    if found_match_2:
        create_case(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'else' condition 3
    join_format_join(action=action, success=success, container=container, results=results, handle=handle)

    return


def merge_into_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_into_case() called")

    id_value = container.get("id", None)
    filtered_cf_result_0 = phantom.collect2(container=container, datapath=["filtered-data:case_filter:condition_1:expand_results:custom_function_result.data.*.item.container_id"])

    parameters = []

    # build parameters list for 'merge_into_case' call
    for filtered_cf_result_0_item in filtered_cf_result_0:
        parameters.append({
            "workbook": None,
            "container_list": id_value,
            "close_containers": True,
            "target_container": filtered_cf_result_0_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_merge", parameters=parameters, name="merge_into_case", callback=merge_into_case_format)

    return


def workbook_task_update_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_1() called")

    id_value = container.get("id", None)
    merge_all_format = phantom.get_format_data(name="merge_all_format")

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "Investigate",
        "note_title": "[Auto-Generated] Related Events Merged",
        "note_content": merge_all_format,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update_1", callback=format_case_output)

    return


def create_case_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_case_format() called")

    ################################################################################
    # Format a note with a list of all events merged.
    ################################################################################

    template = """Result of merge process:\n\nContainers merged into case {0} - {1}:\n%%\n- {2}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "find_related_events:custom_function_result.data.*.container_id"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="create_case_format")

    workbook_task_update_1(container=container)

    return


def workbook_task_update_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("workbook_task_update_2() called")

    id_value = container.get("id", None)
    merge_individual_format = phantom.get_format_data(name="merge_individual_format")

    parameters = []

    parameters.append({
        "owner": None,
        "status": None,
        "container": id_value,
        "task_name": "Investigate",
        "note_title": "[Auto-Generated] Related Events Merged",
        "note_content": merge_individual_format,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="workbook_task_update_2", callback=format_merge_output)

    return


def merge_into_case_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("merge_into_case_format() called")

    ################################################################################
    # Format a note that shows the result of the merge process.
    ################################################################################

    template = """Result of merge process:\n\nContainers merged into case {0} - {1}:\n%%\n- {2}\n%%\n"""

    # parameter list for template variable replacement
    parameters = [
        "container:id",
        "container:name",
        "process_responses:custom_function:container_list"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="merge_into_case_format")

    workbook_task_update_2(container=container)

    return


def create_case(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("create_case() called")

    id_value = container.get("id", None)
    find_related_events_data = phantom.collect2(container=container, datapath=["find_related_events:custom_function_result.data.*.container_id"])

    find_related_events_data___container_id = [item[0] for item in find_related_events_data]

    parameters = []

    parameters.append({
        "workbook": None,
        "container_list": find_related_events_data___container_id,
        "close_containers": True,
        "target_container": id_value,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################


    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/container_merge", parameters=parameters, name="create_case", callback=create_case_format)

    return


def expand_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("expand_results() called")

    find_related_events__result = phantom.collect2(container=container, datapath=["find_related_events:custom_function_result.data"])

    find_related_events_data = [item[0] for item in find_related_events__result]

    parameters = []

    parameters.append({
        "input_1": find_related_events_data,
        "input_2": None,
        "input_3": None,
        "input_4": None,
        "input_5": None,
        "input_6": None,
        "input_7": None,
        "input_8": None,
        "input_9": None,
        "input_10": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    parameters = []
    for item in find_related_events_data[0]:
        parameters.append({'input_1': item})
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/passthrough", parameters=parameters, name="expand_results", callback=case_filter)

    return


def case_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("case_filter() called")

    ################################################################################
    # Get the related event that is a case.
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["expand_results:custom_function_result.data.*.item.container_type", "==", "case"]
        ],
        name="case_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        merge_into_case(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def format_case_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_case_output() called")

    ################################################################################
    # Format a note indicating a case was created
    ################################################################################

    template = """created case"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_case_output")

    join_format_join(container=container)

    return


def format_merge_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_merge_output() called")

    ################################################################################
    # Format a note indicating the container was merged into a case
    ################################################################################

    template = """merged into case"""

    # parameter list for template variable replacement
    parameters = []

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_merge_output")

    join_format_join(container=container)

    return


def join_format_join(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_join() called")

    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key="join_format_join_called"):
        return

    # save the state that the joined function has now been called
    phantom.save_run_data(key="join_format_join_called", value="format_join")

    # call connected block "format_join"
    format_join(container=container, handle=handle)

    return


def format_join(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_join() called")

    ################################################################################
    # Format a note for output based on the result of one of two outputs. The note 
    # will contain one of "merged into case," "created case", or None.
    ################################################################################

    template = """{0}{1}"""

    # parameter list for template variable replacement
    parameters = [
        "format_case_output:formatted_data",
        "format_merge_output:formatted_data"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_join", drop_none=True)

    return


def find_related_events(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("find_related_events() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "container": id_value,
        "field_list": "risk_object",
        "value_list": None,
        "filter_label": "risk_notable",
        "earliest_time": "-24h",
        "filter_status": "new, open",
        "filter_in_case": None,
        "filter_severity": None,
        "minimum_match_count": "all",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/find_related_containers", parameters=parameters, name="find_related_events", callback=related_events_decision)

    return


def on_finish(container, summary):
    phantom.debug("on_finish() called")

    format_join = phantom.get_format_data(name="format_join")

    output = {
        "merge_result": format_join,
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