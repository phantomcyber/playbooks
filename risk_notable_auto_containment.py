"""
Implements an auto-containment of available assets and identities found in artifacts with high risk scores or confirmed threats.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # call 'add_risk_response_workbook' block
    add_risk_response_workbook(container=container)
    # call 'tag_assets_and_identities' block
    tag_assets_and_identities(container=container)

    return

def start_protect_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("start_protect_task() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "owner": None,
        "status": "in_progress",
        "container": id_value,
        "task_name": "Protect Assets and Users",
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

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="start_protect_task", callback=join_high_risk_artifact_filter)

    return


def add_risk_response_workbook(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_risk_response_workbook() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "workbook": "Risk Response",
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

    phantom.custom_function(custom_function="community/workbook_add", parameters=parameters, name="add_risk_response_workbook", callback=start_protect_task)

    return


def close_protect_task(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_protect_task() called")

    id_value = container.get("id", None)
    format_containment_note__note_title = json.loads(phantom.get_run_data(key="format_containment_note:note_title"))
    format_containment_note__note_content = json.loads(phantom.get_run_data(key="format_containment_note:note_content"))

    parameters = []

    parameters.append({
        "owner": None,
        "status": "complete",
        "container": id_value,
        "task_name": "Protect Assets and Users",
        "note_title": format_containment_note__note_title,
        "note_content": format_containment_note__note_content,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/workbook_task_update", parameters=parameters, name="close_protect_task", callback=close_protect_task_callback)

    return


def close_protect_task_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("close_protect_task_callback() called")

    
    mark_containment_report_as_evidence(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    add_risk_recovery_workbook(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def tag_assets_and_identities(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("tag_assets_and_identities() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/splunk_enterprise_security_tag_assets_and_identities", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/splunk_enterprise_security_tag_assets_and_identities", container=container, name="tag_assets_and_identities", callback=join_high_risk_artifact_filter)

    return


def join_high_risk_artifact_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_high_risk_artifact_filter() called")

    if phantom.completed(custom_function_names=["start_protect_task"], playbook_names=["tag_assets_and_identities"]):
        # call connected block "high_risk_artifact_filter"
        high_risk_artifact_filter(container=container, handle=handle)

    return


def high_risk_artifact_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("high_risk_artifact_filter() called")

    ################################################################################
    # Isolate artifacts with tags "high_risk_score" or "high_threat"
    ################################################################################

    # collect filtered artifact ids and results for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        logical_operator="or",
        conditions=[
            ["high_threat", "in", "artifact:*.tags"],
            ["high_risk_score", "in", "artifact:*.tags"]
        ],
        name="high_risk_artifact_filter:condition_1",
        scope="all")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        dispatch_identity_containment_playbooks(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        dispatch_asset_containment_playbooks(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return


def dispatch_identity_containment_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_identity_containment_playbooks() called")

    filtered_artifact_0_data_high_risk_artifact_filter = phantom.collect2(container=container, datapath=["filtered-data:high_risk_artifact_filter:condition_1:artifact:*.id"], scope="all")

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_high_risk_artifact_filter]

    playbook_tags_combined_value = phantom.concatenate("identity", "containment")

    inputs = {
        "playbook_repo": "local",
        "playbook_tags": playbook_tags_combined_value,
        "artifact_ids_include": filtered_artifact_0__id,
        "indicator_tags_exclude": "contained",
        "indicator_tags_include": "known_identity",
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/dispatch_input_playbooks", container=container, name="dispatch_identity_containment_playbooks", callback=join_get_not_contained_indicators, inputs=inputs)

    return


def dispatch_asset_containment_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_asset_containment_playbooks() called")

    filtered_artifact_0_data_high_risk_artifact_filter = phantom.collect2(container=container, datapath=["filtered-data:high_risk_artifact_filter:condition_1:artifact:*.id"], scope="all")

    filtered_artifact_0__id = [item[0] for item in filtered_artifact_0_data_high_risk_artifact_filter]

    playbook_tags_combined_value = phantom.concatenate("asset", "containment")

    inputs = {
        "playbook_repo": "local",
        "playbook_tags": playbook_tags_combined_value,
        "artifact_ids_include": filtered_artifact_0__id,
        "indicator_tags_exclude": "contained",
        "indicator_tags_include": "known_asset",
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    # call playbook "local/dispatch_input_playbooks", returns the playbook_run_id
    playbook_run_id = phantom.playbook("local/dispatch_input_playbooks", container=container, name="dispatch_asset_containment_playbooks", callback=join_get_not_contained_indicators, inputs=inputs)

    return


def join_format_containment_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_containment_note() called")

    if phantom.completed(custom_function_names=["collect_hosts_and_users", "get_contained_indicators"]):
        # call connected block "format_containment_note"
        format_containment_note(container=container, handle=handle)

    return


def format_containment_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_containment_note() called")

    ################################################################################
    # Format a custom report based on which playbooks were dispatched
    ################################################################################

    dispatch_asset_containment_playbooks_output_playbook_run_id_list = phantom.collect2(container=container, datapath=["dispatch_asset_containment_playbooks:playbook_output:playbook_run_id_list"])
    dispatch_identity_containment_playbooks_output_playbook_run_id_list = phantom.collect2(container=container, datapath=["dispatch_identity_containment_playbooks:playbook_output:playbook_run_id_list"])
    get_not_contained_indicators_data = phantom.collect2(container=container, datapath=["get_not_contained_indicators:custom_function_result.data.*.indicator_value","get_not_contained_indicators:custom_function_result.data.*.indicator_tags"])
    collect_hosts_and_users_data = phantom.collect2(container=container, datapath=["collect_hosts_and_users:custom_function_result.data.*.artifact_value"])
    get_contained_indicators_data = phantom.collect2(container=container, datapath=["get_contained_indicators:custom_function_result.data.*.indicator_value"])

    dispatch_asset_containment_playbooks_output_playbook_run_id_list_values = [item[0] for item in dispatch_asset_containment_playbooks_output_playbook_run_id_list]
    dispatch_identity_containment_playbooks_output_playbook_run_id_list_values = [item[0] for item in dispatch_identity_containment_playbooks_output_playbook_run_id_list]
    get_not_contained_indicators_data___indicator_value = [item[0] for item in get_not_contained_indicators_data]
    get_not_contained_indicators_data___indicator_tags = [item[1] for item in get_not_contained_indicators_data]
    collect_hosts_and_users_data___artifact_value = [item[0] for item in collect_hosts_and_users_data]
    get_contained_indicators_data___indicator_value = [item[0] for item in get_contained_indicators_data]

    format_containment_note__note_title = None
    format_containment_note__note_content = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    from itertools import zip_longest
    
    format_containment_note__note_title = ""
    format_containment_note__note_content = ""
    
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
            return formatted_content + "\n&nbsp;\n\n&nbsp;\n"
    
    asset_list = []
    asset_contained_list = []
    identity_list = []
    identity_contained_list = []
    misc_not_contained_list = []
    
    for i_value, i_tag in zip(get_not_contained_indicators_data___indicator_value, get_not_contained_indicators_data___indicator_tags):
        if i_tag:
            if 'known_asset' in i_tag:
                asset_list.append(i_value.lower())
                if 'contained' in i_tag:
                    asset_contained_list.append(i_value.lower())
            if 'known_identity' in i_tag:
                identity_list.append(i_value.lower())
                if 'contained' in i_tag:
                    identity_contained_list.append(i_value.lower())
    
    for value in collect_hosts_and_users_data___artifact_value:
        if value.lower() not in asset_list and value.lower() not in identity_list:
            misc_not_contained_list.append(value)
                
    if dispatch_asset_containment_playbooks_output_playbook_run_id_list_values:
        format_containment_note__note_content += (
            "## Asset Containment Report\n\n"
            "| Known Assets from event | Known Assets contained |\n"
            "| --- | --- |\n"
        )
        for zipped_list in zip_longest(asset_list, asset_contained_list, fillvalue=" "):
            format_containment_note__note_content += f"| {zipped_list[0]} | {zipped_list[1]} |\n"
        for run_id in dispatch_asset_containment_playbooks_output_playbook_run_id_list_values:
            format_containment_note__note_content += playbook_report(run_id)

    if dispatch_identity_containment_playbooks_output_playbook_run_id_list_values:
        format_containment_note__note_content += (
            "## Identity Containment Report\n\n"
            "| Known Identities from event | Known Identities contained |\n"
            "| --- | --- |\n"
        )
        for zipped_list in zip_longest(identity_list, identity_contained_list, fillvalue=" "):
            format_containment_note__note_content += f"| {zipped_list[0]} | {zipped_list[1]} |\n"
        for run_id in dispatch_identity_containment_playbooks_output_playbook_run_id_list_values:
            format_containment_note__note_content += playbook_report(run_id)
    
    if misc_not_contained_list:
        misc_not_contained_list = set(misc_not_contained_list)
        format_containment_note__note_content += f"## Unidentified Entities Not Contained \n"
        for item in misc_not_contained_list:
            format_containment_note__note_content += f"- {item}\n"
        format_containment_note__note_content += "(Manual action may be required)"
                
    if format_containment_note__note_content:
        format_containment_note__note_title = "[Auto-Generated] Containment Summary"

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="format_containment_note:note_title", value=json.dumps(format_containment_note__note_title))
    phantom.save_run_data(key="format_containment_note:note_content", value=json.dumps(format_containment_note__note_content))

    close_protect_task(container=container)

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

    phantom.custom_function(custom_function="community/workbook_add", parameters=parameters, name="add_risk_recovery_workbook")

    return


def mark_containment_report_as_evidence(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("mark_containment_report_as_evidence() called")

    id_value = container.get("id", None)
    close_protect_task__result = phantom.collect2(container=container, datapath=["close_protect_task:custom_function_result.data.note_id"])

    parameters = []

    # build parameters list for 'mark_containment_report_as_evidence' call
    for close_protect_task__result_item in close_protect_task__result:
        parameters.append({
            "container": id_value,
            "content_type": "note_id",
            "input_object": close_protect_task__result_item[0],
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/mark_evidence", parameters=parameters, name="mark_containment_report_as_evidence")

    return


def join_get_not_contained_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_get_not_contained_indicators() called")

    if phantom.completed(playbook_names=["dispatch_identity_containment_playbooks", "dispatch_asset_containment_playbooks"]):
        # call connected block "get_not_contained_indicators"
        get_not_contained_indicators(container=container, handle=handle)

    return


def get_not_contained_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_not_contained_indicators() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags_or": "known_identity, known_asset",
        "tags_and": None,
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

    phantom.custom_function(custom_function="community/indicator_get_by_tag", parameters=parameters, name="get_not_contained_indicators", callback=get_not_contained_indicators_callback)

    return


def get_not_contained_indicators_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_not_contained_indicators_callback() called")

    
    collect_hosts_and_users(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    get_contained_indicators(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


def collect_hosts_and_users(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("collect_hosts_and_users() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags": None,
        "scope": "all",
        "container": id_value,
        "data_types": "user, user name, username, user_name, host, host name, hostname, host_name",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/collect_by_cef_type", parameters=parameters, name="collect_hosts_and_users", callback=join_format_containment_note)

    return


def get_contained_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("get_contained_indicators() called")

    id_value = container.get("id", None)

    parameters = []

    parameters.append({
        "tags_or": "contained",
        "tags_and": None,
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

    phantom.custom_function(custom_function="community/indicator_get_by_tag", parameters=parameters, name="get_contained_indicators", callback=join_format_containment_note)

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