"""
This playbook acts on processes that have been determined to be malicious (ie spawned shells like cmd or powershell).

It terminates these processes via  Windows Remote Management.

It then queries Splunk to determine if that process launches any child processes.  If child processes are found, the playbook then attempts to terminate those via Windows Remote Management.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Terminate_Process' block
    Terminate_Process(container=container)

    return

def Format_Splunk_Search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Format_Splunk_Search() called')
    
    template = """index=* dest={1} parent_process_id={0} | fields *"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.process_id",
        "artifact:*.cef.destinationAddress",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Format_Splunk_Search")

    Find_Child_Processes(container=container)

    return

def Terminate_Process(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Terminate_Process() called')

    # collect data for 'Terminate_Process' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.cef.process_id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'Terminate_Process' call
    for container_item in container_data:
        parameters.append({
            'ip_hostname': container_item[0],
            'pid': container_item[1],
            'name': "",
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[2]},
        })

    phantom.act(action="terminate process", parameters=parameters, assets=['winrm'], callback=Format_Splunk_Search, name="Terminate_Process")

    return

def Find_Child_Processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Find_Child_Processes() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Find_Child_Processes' call
    formatted_data_1 = phantom.get_format_data(name='Format_Splunk_Search')

    parameters = []
    
    # build parameters list for 'Find_Child_Processes' call
    parameters.append({
        'command': "search",
        'query': formatted_data_1,
        'display': "",
        'parse_only': "",
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=Terminate_Child_Processes, name="Find_Child_Processes")

    return

def Terminate_Child_Processes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Terminate_Child_Processes() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Terminate_Child_Processes' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])
    results_data_1 = phantom.collect2(container=container, datapath=['Find_Child_Processes:action_result.data.*.ProcessId', 'Find_Child_Processes:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Terminate_Child_Processes' call
    for container_item in container_data:
        for results_item_1 in results_data_1:
            parameters.append({
                'ip_hostname': container_item[0],
                'pid': results_item_1[0],
                'name': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="terminate process", parameters=parameters, assets=['winrm'], name="Terminate_Child_Processes", parent_action=action)

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