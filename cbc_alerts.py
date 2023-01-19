"""
Carbon Black Cloud alerts playbook
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'decision_1' block
    decision_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.type", "==", "CB_ANALYTICS"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        cf_local_get_alert_triage_url_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        get_enriched_event_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        conditions=[
            ["artifact:*.cef.type", "==", "WATCHLIST"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        cf_local_get_process_analysis_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        get_process_metadata_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def get_process_metadata_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_process_metadata_1() called')

    # collect data for 'get_process_metadata_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.threat_cause_process_guid', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_process_metadata_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'process_guid': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get process metadata", parameters=parameters, assets=['test configuration asset'], callback=join_prompt_watchlist_action, name="get_process_metadata_1")

    return

def prompt_watchlist_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_watchlist_action() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Select action to perform on process hash {0}"""

    # parameter list for template variable replacement
    parameters = [
        "get_process_metadata_1:action_result.data.*.details.process_sha256",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Add  to watchlist/feed",
                    "Remove from watchlist/feed",
                    "Ban hash",
                    "Unban hash",
                    "Dismiss alert",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_watchlist_action", parameters=parameters, response_types=response_types, callback=decision_2)

    return

def join_prompt_watchlist_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_prompt_watchlist_action() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['get_process_metadata_1', 'prompt_confirm_process_analysis']):
        
        # call connected block "prompt_watchlist_action"
        prompt_watchlist_action(container=container, handle=handle)
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Remove from watchlist/feed", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_feed_or_watchlist(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Unban hash", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        unban_hash_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 3
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Dismiss alert", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 3 matched
    if matched:
        join_dismiss_alert_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 4
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Add to watchlist/feed", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 4 matched
    if matched:
        prompt_feed_or_watchlist(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 5
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Ban hash", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 5 matched
    if matched:
        ban_hash_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def dismiss_alert_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('dismiss_alert_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'dismiss_alert_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'dismiss_alert_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'alert_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="dismiss alert", parameters=parameters, assets=['test configuration asset'], name="dismiss_alert_2")

    return

def join_dismiss_alert_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_dismiss_alert_2() called')
    
    # if the joined function has already been called, do nothing
    if phantom.get_run_data(key='join_dismiss_alert_2_called'):
        return

    # no callbacks to check, call connected block "dismiss_alert_2"
    phantom.save_run_data(key='join_dismiss_alert_2_called', value='dismiss_alert_2', auto=True)

    dismiss_alert_2(container=container, handle=handle)
    
    return

def add_ioc_to_feed_or_watchlist_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_ioc_to_feed_or_watchlist_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_ioc_to_feed_or_watchlist_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.threat_cause_actor_sha256', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['prompt_feed_watchlist_name:action_result.summary.responses.0', 'prompt_feed_watchlist_name:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['prompt_report_name:action_result.summary.responses.0', 'prompt_report_name:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_ioc_to_feed_or_watchlist_1' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            for results_item_2 in results_data_2:
                if container_item[0] and results_item_2[0]:
                    parameters.append({
                        'ioc_id': "",
                        'feed_id': results_item_1[0],
                        'cbc_field': "process_hash",
                        'ioc_value': container_item[0],
                        'report_id': results_item_2[0],
                        'watchlist_id': "",
                        # context (artifact id) is added to associate results with the artifact
                        'context': {'artifact_id': results_item_1[1]},
                    })

    phantom.act(action="add ioc to feed or watchlist", parameters=parameters, assets=['test configuration asset'], name="add_ioc_to_feed_or_watchlist_1")

    return

def ban_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ban_hash_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ban_hash_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_process_metadata_1:action_result.data.*.details.process_sha256', 'get_process_metadata_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'ban_hash_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'process_hash': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="ban hash", parameters=parameters, assets=['test configuration asset'], name="ban_hash_1")

    return

def unban_hash_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('unban_hash_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'unban_hash_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_process_metadata_1:action_result.data.*.details.process_sha256', 'get_process_metadata_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'unban_hash_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'process_hash': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="unban hash", parameters=parameters, assets=['test configuration asset'], name="unban_hash_1")

    return

def prompt_alert_triage_confirm(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_alert_triage_confirm() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Click  [Here]({0}) to view Alert Triage page in CBC. Add a comment below."""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_get_alert_triage_url_4:custom_function_result.data.console_url",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_alert_triage_confirm", parameters=parameters, response_types=response_types, callback=join_prompt_choose_cbabalytics_action)

    return

def cf_local_get_process_analysis_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_process_analysis_url_1() called')
    
    parameters = []

    parameters.append({
        'asset': None,
        'alert_id': None,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_process_analysis_url", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_process_analysis_url', parameters=parameters, name='cf_local_get_process_analysis_url_1', callback=prompt_confirm_process_analysis)

    return

def cf_local_get_alert_triage_url_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('cf_local_get_alert_triage_url_4() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.id', 'artifact:*.id'])
    container_property_0 = [
        [
            container.get("asset_name"),
        ],
    ]

    parameters = []

    container_property_0_0 = [item[0] for item in container_property_0]
    container_data_0_0 = [item[0] for item in container_data_0]

    parameters.append({
        'asset': container_property_0_0,
        'alert_id': container_data_0_0,
    })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "local/get_alert_triage_url", returns the custom_function_run_id
    phantom.custom_function(custom_function='local/get_alert_triage_url', parameters=parameters, name='cf_local_get_alert_triage_url_4', callback=prompt_alert_triage_confirm)

    return

def get_enriched_event_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_enriched_event_1() called')

    # collect data for 'get_enriched_event_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_enriched_event_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'alert_id': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get enriched event", parameters=parameters, assets=['test configuration asset'], callback=join_prompt_choose_cbabalytics_action, name="get_enriched_event_1")

    return

def prompt_choose_cbabalytics_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_choose_cbabalytics_action() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Select an action"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Set device policy",
                    "Dismiss alert",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_choose_cbabalytics_action", response_types=response_types, callback=decision_3)

    return

def join_prompt_choose_cbabalytics_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_prompt_choose_cbabalytics_action() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['prompt_alert_triage_confirm', 'get_enriched_event_1']):
        
        # call connected block "prompt_choose_cbabalytics_action"
        prompt_choose_cbabalytics_action(container=container, handle=handle)
    
    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Set device policy", "==", "prompt_choose_cbabalytics_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        prompt_device_policy(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    join_dismiss_alert_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def prompt_device_policy(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_device_policy() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Enter device policy"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_device_policy", response_types=response_types, callback=set_device_policy_1)

    return

def set_device_policy_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('set_device_policy_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'set_device_policy_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.device_id', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['prompt_device_policy:action_result.parameter.message', 'prompt_device_policy:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'set_device_policy_1' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            if container_item[0]:
                parameters.append({
                    'device_id': container_item[0],
                    'policy_id': "",
                    'policy_name': results_item_1[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': container_item[1]},
                })

    phantom.act(action="set device policy", parameters=parameters, assets=['test configuration asset'], name="set_device_policy_1")

    return

def prompt_feed_or_watchlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_feed_or_watchlist() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Choose a feed or a watchlist"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Feed",
                    "Watchlist",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_feed_or_watchlist", response_types=response_types, callback=prompt_feed_watchlist_name)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Feed", "==", "prompt_feed_or_watchlist:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        decision_5(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Watchlist", "==", "prompt_feed_or_watchlist:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        decision_6(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Add to watchlist/feed", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_ioc_to_feed_or_watchlist_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Remove from watchlist/feed", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_ioc_v2_feed(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def remove_ioc_from_feed_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('remove_ioc_from_feed_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'remove_ioc_from_feed_1' call

    parameters = []
    
    # build parameters list for 'remove_ioc_from_feed_1' call
    parameters.append({
        'ioc_id': "",
        'feed_id': "",
        'ioc_value': "",
        'report_id': "",
    })

    phantom.act(action="remove ioc from feed", parameters=parameters, assets=['test configuration asset'], name="remove_ioc_from_feed_1")

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Add to watchlist/feed", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        add_ioc_to_feed_or_watchlist_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Remove from watchlist/feed", "==", "prompt_watchlist_action:action_result.summary.responses.0"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        format_ioc_v2_watchlist(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    return

def remove_ioc_from_watchlist_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('remove_ioc_from_watchlist_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'remove_ioc_from_watchlist_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['prompt_report_name:action_result.summary.responses.0', 'prompt_report_name:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['prompt_feed_watchlist_name:action_result.summary.responses.0', 'prompt_feed_watchlist_name:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_ioc_v2_watchlist__as_list')

    parameters = []
    
    # build parameters list for 'remove_ioc_from_watchlist_1' call
    for formatted_part_1 in formatted_data_1:
        for results_item_1 in results_data_1:
            for results_item_2 in results_data_2:
                parameters.append({
                    'ioc_id': "",
                    'ioc_value': formatted_part_1,
                    'report_id': results_item_1[0],
                    'watchlist_id': results_item_2[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="remove ioc from watchlist", parameters=parameters, assets=['test configuration asset'], name="remove_ioc_from_watchlist_1")

    return

def prompt_feed_watchlist_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_feed_watchlist_name() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Enter feed/watchlist name"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_feed_watchlist_name", response_types=response_types, callback=prompt_report_name)

    return

def add_ioc_to_feed_or_watchlist_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_ioc_to_feed_or_watchlist_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'add_ioc_to_feed_or_watchlist_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.threat_cause_actor_sha256', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['prompt_report_name:action_result.summary.responses.0', 'prompt_report_name:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['prompt_feed_watchlist_name:action_result.summary.responses.0', 'prompt_feed_watchlist_name:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'add_ioc_to_feed_or_watchlist_2' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            for results_item_2 in results_data_2:
                if container_item[0] and results_item_1[0]:
                    parameters.append({
                        'ioc_id': "",
                        'feed_id': "",
                        'cbc_field': "process_hash",
                        'ioc_value': container_item[0],
                        'report_id': results_item_1[0],
                        'watchlist_id': results_item_2[0],
                        # context (artifact id) is added to associate results with the artifact
                        'context': {'artifact_id': container_item[1]},
                    })

    phantom.act(action="add ioc to feed or watchlist", parameters=parameters, assets=['test configuration asset'], name="add_ioc_to_feed_or_watchlist_2")

    return

def prompt_report_name(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_report_name() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Enter Report Name"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_report_name", response_types=response_types, callback=decision_4)

    return

def prompt_confirm_process_analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_confirm_process_analysis() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Please click [Here]({0})  for Process Analysis. Add a comment below.{0}"""

    # parameter list for template variable replacement
    parameters = [
        "cf_local_get_process_analysis_url_1:custom_function_result.data.console_url",
    ]

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="prompt_confirm_process_analysis", parameters=parameters, response_types=response_types, callback=join_prompt_watchlist_action)

    return

def format_ioc_v2_feed(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ioc_v2_feed() called')
    
    template = """(process_hash:{0})"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.threat_cause_actor_sha256",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ioc_v2_feed")

    remove_ioc_from_feed_1(container=container)

    return

def format_ioc_v2_watchlist(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ioc_v2_watchlist() called')
    
    template = """(process_hash:{0})"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.threat_cause_actor_sha256",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ioc_v2_watchlist")

    remove_ioc_from_watchlist_1(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return