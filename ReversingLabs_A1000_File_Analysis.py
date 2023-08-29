"""
Queries ReversingLabs A1000 appliance for classification report.  If file is not present on te appliance, uploads the file and retrieves report.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'a1000_get_report' block
    a1000_get_report(container=container)

    return

def a1000_get_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('a1000_get_report() called')

    # collect data for 'a1000_get_report' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'a1000_get_report' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                'retry': False,
                'fields': "",
                'skip_reanalysis': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get detailed report", parameters=parameters, assets=['reversinglabs_a1000_v2'], callback=check_if_report_available, name="a1000_get_report")

    return

def a1000_detonate_file(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('a1000_detonate_file() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'a1000_detonate_file' call
    filtered_results_data_1 = phantom.collect2(container=container, datapath=["filtered-data:check_if_report_available:condition_1:a1000_get_report:action_result.parameter.hash", "filtered-data:check_if_report_available:condition_1:a1000_get_report:action_result.parameter.context.artifact_id"])

    parameters = []
    
    # build parameters list for 'a1000_detonate_file' call
    for filtered_results_item_1 in filtered_results_data_1:
        if filtered_results_item_1[0]:
            parameters.append({
                'vault_id': filtered_results_item_1[0],
                'file_name': "sample",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': filtered_results_item_1[1]},
            })

    phantom.act(action="detonate file", parameters=parameters, assets=['reversinglabs_a1000_v2'], callback=a1000_get_report_2, name="a1000_detonate_file", parent_action=action)

    return

def check_if_report_available(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('check_if_report_available() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["a1000_get_report:action_result.status", "==", "failed"],
        ],
        name="check_if_report_available:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        a1000_detonate_file(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["a1000_get_report:action_result.status", "==", "success"],
        ],
        name="check_if_report_available:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        pass

    return

def a1000_get_report_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('a1000_get_report_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'a1000_get_report_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['a1000_detonate_file:action_result.parameter.vault_id', 'a1000_detonate_file:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'a1000_get_report_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                'retry': True,
                'fields': "",
                'skip_reanalysis': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get detailed report", parameters=parameters, assets=['reversinglabs_a1000_v2'], name="a1000_get_report_2", parent_action=action)

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