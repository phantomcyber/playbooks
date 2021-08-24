"""
This playbook demonstrates the integration between Splunk SOAR and EndaceProbe. It operates on syslog messages forwarded by the Phantom App for Splunk. The playbook queries EndaceProbe for packets of interests and on successful match downloads PCAP files in the Splunk SOAR local storage. The downloading of actual files is conditional and depends upon event severity and/or number of Bytes matched (default is 10MB and can be changed). For PCAPs greater than 10MB, a EndaceP2P download link is provided as a 'note' to the user.

Thanks to Soumen Chakraborty for this contribution.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'epoch_to_timestamp' block
    epoch_to_timestamp(container=container)

    return

"""
Search for PCAP on EndaceProbe
"""
def Query_EndaceProbe(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Query_EndaceProbe() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Query_EndaceProbe' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.cef.destinationAddress', 'artifact:*.cef.sourcePort', 'artifact:*.cef.destinationPort', 'artifact:*.cef.transportProtocol', 'artifact:*.id'])
    custom_function_results_data_1 = phantom.collect2(container=container, datapath=['epoch_to_timestamp:custom_function_result.data.datetime_string'], action_results=results)

    parameters = []
    
    # build parameters list for 'Query_EndaceProbe' call
    for container_item in container_data:
        for custom_function_results_item_1 in custom_function_results_data_1:
            if container_item[0] and container_item[1] and container_item[4]:
                parameters.append({
                    'time': custom_function_results_item_1[0],
                    'host1': container_item[0],
                    'host2': container_item[1],
                    'port1': container_item[2],
                    'port2': container_item[3],
                    'end_time': "",
                    'protocol': container_item[4],
                    'span_after': 30,
                    'start_time': "",
                    'span_before': 3600,
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': container_item[5]},
                })

    phantom.act(action="run query", parameters=parameters, assets=['endace_probe'], callback=Query_Success, name="Query_EndaceProbe")

    return

"""
Check whether the PCAP has more than 27 bytes, which is the size of an empty PCAP.
"""
def Query_Success(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Query_Success() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Query_EndaceProbe:action_result.data.*.flow.results.total.flowByteCount", ">", 27],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        High_Severity_Event(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Failed_Status(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Automatically get the PCAP if the event is high severity.
"""
def High_Severity_Event(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('High_Severity_Event() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["artifact:*.severity", "==", "high"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Get_PCAP(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    PCAP_size_check(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Download PCAP from EndaceProbe
"""
def Get_PCAP(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_PCAP() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_PCAP' call
    results_data_1 = phantom.collect2(container=container, datapath=['Query_EndaceProbe:action_result.summary.pcap_id', 'Query_EndaceProbe:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Get_PCAP' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'pcap_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get pcap", parameters=parameters, assets=['endace_probe'], name="Get_PCAP")

    return

def PCAP_size_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('PCAP_size_check() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Query_EndaceProbe:action_result.data.*.flow.results.total.flowByteCount", ">", 10000000],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Get_PCAP_Status(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Get_PCAP_under_10MB(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Only get the status if the PCAP is too large.
"""
def Get_PCAP_Status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_PCAP_Status() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_PCAP_Status' call
    results_data_1 = phantom.collect2(container=container, datapath=['Query_EndaceProbe:action_result.summary.pcap_id', 'Query_EndaceProbe:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Get_PCAP_Status' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'pcap_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get status", parameters=parameters, assets=['endace_probe'], callback=Extract_PCAP_Links, name="Get_PCAP_Status")

    return

def PCAP_Links(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('PCAP_Links() called')
    
    template = """{0}"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:Extract_PCAP_Links:condition_1:Get_PCAP_Status:action_result.data.*.datamine.links.2.href",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="PCAP_Links", separator=", ")

    Add_Links_to_note(container=container)

    return

def Get_PCAP_under_10MB(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_PCAP_under_10MB() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_PCAP_under_10MB' call
    results_data_1 = phantom.collect2(container=container, datapath=['Query_EndaceProbe:action_result.summary.pcap_id', 'Query_EndaceProbe:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Get_PCAP_under_10MB' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'pcap_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="get pcap", parameters=parameters, assets=['endace_probe'], name="Get_PCAP_under_10MB")

    return

"""
Document the failed search when the byte count shows an empty PCAP.
"""
def Failed_Status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Failed_Status() called')
    
    template = """Search Failed with Status - {0}"""

    # parameter list for template variable replacement
    parameters = [
        "Query_EndaceProbe:action_result.status",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="Failed_Status", separator=", ")

    add_note_6(container=container)

    return

def Add_Links_to_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Add_Links_to_note() called')

    formatted_data_1 = phantom.get_format_data(name='PCAP_Links')

    note_title = "EndaceP2P Link"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def add_note_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_note_6() called')

    formatted_data_1 = phantom.get_format_data(name='Failed_Status')

    note_title = "Search Status"
    note_content = formatted_data_1
    note_format = "markdown"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

def Extract_PCAP_Links(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Extract_PCAP_Links() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["downloadPcap", "in", "Get_PCAP_Status:action_result.data.*.datamine.links.*.name"],
        ],
        name="Extract_PCAP_Links:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        PCAP_Links(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Convert the epoch time to a timestamp.
"""
def epoch_to_timestamp(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('epoch_to_timestamp() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.endaceDateTime', 'artifact:*.id'])
    literal_values_0 = [
        [
            "epoch",
            "%Y-%m-%dT%H:%M:%SZ",
        ],
    ]

    parameters = []

    for item0 in container_data_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': None,
                'modification_unit': None,
                'input_format_string': item1[0],
                'output_format_string': item1[1],
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='epoch_to_timestamp', callback=Query_EndaceProbe)

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