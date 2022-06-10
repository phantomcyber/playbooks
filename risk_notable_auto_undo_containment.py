"""
This playbook gathers contained assets and identities from the container and sends them playbooks with &quot;undo_containment&quot; as well as &quot;asset&quot; or &quot;identity&quot; tags.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_risk_recovery_workbook' block
    add_risk_recovery_workbook(container=container)
    # call 'dispatch_asset_undo_containment_playbooks' block
    dispatch_asset_undo_containment_playbooks(container=container)
    # call 'dispatch_identity_undo_containment_playbooks' block
    dispatch_identity_undo_containment_playbooks(container=container)

    return

def dispatch_identity_undo_containment_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_identity_undo_containment_playbooks() called")

    playbook_tags_combined_value = phantom.concatenate("identity", "undo_containment")
    indicator_tags_include_combined_value = phantom.concatenate("known_identity", "contained")

    inputs = {
        "playbook_repo": "local",
        "playbook_tags": playbook_tags_combined_value,
        "artifact_ids_include": "",
        "indicator_tags_exclude": "",
        "indicator_tags_include": indicator_tags_include_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_identity_undo_containment_playbooks", callback=join_get_contained_indicators, inputs=inputs)

    return


def dispatch_asset_undo_containment_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_asset_undo_containment_playbooks() called")

    playbook_tags_combined_value = phantom.concatenate("asset", "undo_containment")
    indicator_tags_include_combined_value = phantom.concatenate("known_asset", "contained")

    inputs = {
        "playbook_repo": "local",
        "playbook_tags": playbook_tags_combined_value,
        "artifact_ids_include": "",
        "indicator_tags_exclude": "",
        "indicator_tags_include": indicator_tags_include_combined_value,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "community/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("community/dispatch_input_playbooks", container=container, name="dispatch_asset_undo_containment_playbooks", callback=join_get_contained_indicators, inputs=inputs)

    return


def close_undo_containment_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_undo_containment_task() called")

    id_value = container.get("id", None)
    format_playbook_note__note_title = json.loads(phantom.get_run_data(key="format_playbook_note:note_title"))
    format_playbook_note__note_content = json.loads(phantom.get_run_data(key="format_playbook_note:note_content"))

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "Undo Containment",
        "note_title": format_playbook_note__note_title,
        "note_content": format_playbook_note__note_content,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="close_undo_containment_task", callback=mark_close_note_evidence)

    return


def add_risk_recovery_workbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_risk_recovery_workbook() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Risk Recovery",
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

    phantom.custom_function(custom_function="community/workbook_add", parameters=parameters, name="add_risk_recovery_workbook", callback=start_undo_containment_task)

    return


def format_playbook_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_playbook_note() called")

    ################################################################################
    # Formats a custom note based on dispatch outputs.
    ################################################################################

    dispatch_identity_undo_containment_playbooks_output_playbook_run_id_list = phantom.collect2(container=container, datapath=["dispatch_identity_undo_containment_playbooks:playbook_output:playbook_run_id_list"])
    dispatch_asset_undo_containment_playbooks_output_playbook_run_id_list = phantom.collect2(container=container, datapath=["dispatch_asset_undo_containment_playbooks:playbook_output:playbook_run_id_list"])
    get_contained_indicators_data = phantom.collect2(container=container, datapath=["get_contained_indicators:custom_function_result.data.*.indicator_value","get_contained_indicators:custom_function_result.data.*.indicator_tags"])

    dispatch_identity_undo_containment_playbooks_output_playbook_run_id_list_values = [item[0] for item in dispatch_identity_undo_containment_playbooks_output_playbook_run_id_list]
    dispatch_asset_undo_containment_playbooks_output_playbook_run_id_list_values = [item[0] for item in dispatch_asset_undo_containment_playbooks_output_playbook_run_id_list]
    get_contained_indicators_data___indicator_value = [item[0] for item in get_contained_indicators_data]
    get_contained_indicators_data___indicator_tags = [item[1] for item in get_contained_indicators_data]

    format_playbook_note__note_title = None
    format_playbook_note__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from itertools import zip_longest

    format_playbook_note__note_title = ""
    format_playbook_note__note_content = ""
    
    def playbook_report(pb_run_id):
        pb_run_url = phantom.build_phantom_rest_url('playbook_run', pb_run_id)
        response = phantom.requests.get(pb_run_url, verify=False).json()
        if response.get('id'):
            message = json.loads(response['message'])
            formatted_content = f"\n#### Playbook Executed - {message['playbook']}\n"
            formatted_content += (
                "| status | action | app | parameters |\n"
                "| --- | --- | --- | --- |\n"
            )
            for result_item in message['result']:
                app_dict = {}
                for item in result_item['app_runs']:
                    param = item['parameter']
                    param.pop('context', None)
                    if item['app'] not in app_dict.keys():
                        app_dict[item['app']] = {'success': [], 'failed': []}
                    if item['status'] == 'success':
                        app_dict[item['app']]['success'].append(param)
                    if item['status'] == 'failed':
                        app_dict[item['app']]['failed'].append(param)
                for app, params in app_dict.items():
                    if params['success']:
                        formatted_content += f"| success | {result_item['action']} | {app} | ```{params['success']}``` |\n"
                    if params['failed']:
                        formatted_content += f"| failed | {result_item['action']} | {app} | ```{params['failed']}``` |\n"
            return formatted_content + "\n&nbsp;\n\n&nbsp;\n\n"
    
    asset_list = []
    asset_contained_list = []
    identity_list = []
    identity_contained_list = []
    misc_contained_list = []
    
    for i_value, i_tag in zip(get_contained_indicators_data___indicator_value, get_contained_indicators_data___indicator_tags):
        if i_tag:
            if 'known_asset' in i_tag:
                asset_list.append(i_value.lower())
            if 'known_identity' in i_tag:
                identity_list.append(i_value.lower())
            if 'known_asset' in i_tag and 'contained' in i_tag:
                asset_contained_list.append(i_value.lower())
            elif 'known_identity' in i_tag and 'contained' in i_tag:
                identity_contained_list.append(i_value.lower())
            elif 'contained' in i_tag:
                 misc_contained_list.append(i_value.lower())
            
                
    if dispatch_asset_undo_containment_playbooks_output_playbook_run_id_list_values:
        format_playbook_note__note_content += (
            "## Asset Undo Containment Report\n\n"
            "| Assets from event | Assets from event still marked as contained |\n"
            "| --- | --- |\n"
        )
        for zipped_list in zip_longest(asset_list, asset_contained_list, fillvalue=" "):
            format_playbook_note__note_content += f"| {zipped_list[0]} | {zipped_list[1]} |\n"
        for run_id in dispatch_asset_undo_containment_playbooks_output_playbook_run_id_list_values:
            if run_id:
                format_playbook_note__note_content += playbook_report(run_id)

    if dispatch_identity_undo_containment_playbooks_output_playbook_run_id_list_values:
        format_playbook_note__note_content += (
            "\n\n## Identity Undo Containment Report\n\n"
            "| Identities from event | Identities from event still marked as contained |\n"
            "| --- | --- |\n"
        )
        for zipped_list in zip_longest(identity_list, identity_contained_list, fillvalue=" "):
            format_playbook_note__note_content += f"| {zipped_list[0]} | {zipped_list[1]} |\n"
        for run_id in dispatch_identity_undo_containment_playbooks_output_playbook_run_id_list_values:
            if run_id:
                format_playbook_note__note_content += playbook_report(run_id)
    
    if misc_contained_list:
        format_playbook_note__note_content += "## Unidentified Entities Still Contained\n"
        for item in misc_contained_list:
            format_playbook_note__note_content += f"- {item}\n"
        format_playbook_note__note_content += "(Manual action likely required)"
                
    if format_playbook_note__note_content:
        format_playbook_note__note_title = "[Auto-Generated] Revert Containment Summary"

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_playbook_note:note_title", value=json.dumps(format_playbook_note__note_title))
    phantom.save_run_data(key="format_playbook_note:note_content", value=json.dumps(format_playbook_note__note_content))

    close_undo_containment_task(container=container)
    notable_artifact_filter(container=container)

    return


def mark_close_note_evidence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_close_note_evidence() called")

    id_value = container.get("id", None)
    close_undo_containment_task__result = phantom.collect2(container=container, datapath=["close_undo_containment_task:custom_function_result.data.note_id"])

    parameters = []

    # build parameters list for 'mark_close_note_evidence' call
    for close_undo_containment_task__result_item in close_undo_containment_task__result:
        parameters.append({
            "container": id_value,
            "content_type": "note_id",
            "input_object": close_undo_containment_task__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_close_note_evidence")

    return


def join_get_contained_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_get_contained_indicators() called")

    if phantom.completed(playbook_names=["dispatch_identity_undo_containment_playbooks", "dispatch_asset_undo_containment_playbooks"], custom_function_names=["start_undo_containment_task"]):
        # call connected block "get_contained_indicators"
        get_contained_indicators(container=container, handle=handle)

    return


def get_contained_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_contained_indicators() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags_or": "known_asset, known_identity",
        "tags_and": "contained",
        "container": id_value,
        "tags_exclude": None,
        "indicator_timerange": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_get_by_tag", parameters=parameters, name="get_contained_indicators", callback=format_playbook_note)

    return


def start_undo_containment_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("start_undo_containment_task() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "in_progress",
        "container": id_value,
        "task_name": "Undo Containment",
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

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="start_undo_containment_task", callback=join_get_contained_indicators)

    return


def notable_artifact_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("notable_artifact_filter() called")

    ################################################################################
    # Finds artifacts with a notable event_id
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.event_id", "!=", ""]
        ],
        name="notable_artifact_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        update_splunk(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def update_splunk(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("update_splunk() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    comment_formatted_string = phantom.format(
        container=container,
        template="""From event: {0}\n\n{1}""",
        parameters=[
            "container:url",
            "format_playbook_note:custom_function:note_content"
        ])

    ################################################################################
    # Updates Splunk Enterprise Security with a containment action note.
    ################################################################################

    filtered_artifact_0_data_notable_artifact_filter = phantom.collect2(container=container, datapath=["filtered-data:notable_artifact_filter:condition_1:artifact:*.cef.event_id","filtered-data:notable_artifact_filter:condition_1:artifact:*.id"])

    parameters = []

    # build parameters list for 'update_splunk' call
    for filtered_artifact_0_item_notable_artifact_filter in filtered_artifact_0_data_notable_artifact_filter:
        if filtered_artifact_0_item_notable_artifact_filter[0] is not None:
            parameters.append({
                "comment": comment_formatted_string,
                "event_ids": filtered_artifact_0_item_notable_artifact_filter[0],
                "context": {'artifact_id': filtered_artifact_0_item_notable_artifact_filter[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("update event", parameters=parameters, name="update_splunk", assets=["splunk"])

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