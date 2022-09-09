"""
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import os, inspect, threading, requests, time, sys
import phantom.vault as Vault

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'Port_and_Protocol' block
    Port_and_Protocol(container=container)

    return

def Port_and_Protocol(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Port_and_Protocol() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Please Provide Input details"""

    #responses:
    response_types = [
        {
            "prompt": "Provide Port to be blocked",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "Protocol of Port",
            "options": {
                "type": "list",
                "choices": [
                    "TCP",
                    "UDP",
                ]
            },
        },
        {
            "prompt": "Do You want to allow traffic on this port ?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Port_and_Protocol", separator=", ", response_types=response_types, callback=decision_1)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_1() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Port_and_Protocol:action_result.summary.responses.2", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Time_Range_To_Allow_Traffic(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Get_IP_List_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Time_Range_To_Allow_Traffic(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Time_Range_To_Allow_Traffic() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Please provide Input parameters to allow the traffic"""

    #responses:
    response_types = [
        {
            "prompt": "Start Time   (Valid date format: MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss)   ",
            "options": {
                "type": "message",
            },
        },
        {
            "prompt": "End Time   (Valid date format: MM/DD/YYYY hh:mm:ss and YYYY/MM/DD hh:mm:ss)   ",
            "options": {
                "type": "message",
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Time_Range_To_Allow_Traffic", separator=", ", response_types=response_types, callback=Get_Traffic_Analysis)

    return

def Create_Virtual_Service(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Virtual_Service() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Create_Virtual_Service' call
    results_data_1 = phantom.collect2(container=container, datapath=['Port_and_Protocol:action_result.summary.responses.1', 'Port_and_Protocol:action_result.summary.responses.0', 'Port_and_Protocol:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Create_Virtual_Service' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and results_item_1[1]:
            parameters.append({
                'name': "VS-SplunkSOAR-{}-{}".format(results_item_1[1],results_item_1[0]),
                'port': results_item_1[1],
                'protocol': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="create virtual service", parameters=parameters, assets=['illumio'], callback=decision_4, name="Create_Virtual_Service", parent_action=action)

    return

def Provision_Object_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Provision_Object_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Provision_Object_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['Create_Virtual_Service:action_result.data.*.href', 'Create_Virtual_Service:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Provision_Object_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hrefs': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="provision objects", parameters=parameters, assets=['illumio'], callback=decision_7, name="Provision_Object_1")

    return

def Get_IP_List_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_IP_List_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_IP_List_1' call

    parameters = []
    
    # build parameters list for 'Get_IP_List_1' call
    parameters.append({
        'fqdn': "",
        'name': "Any (0.0.0.0/0 and ::/0)",
        'ip_address': "",
        'description': "",
    })

    phantom.act(action="get ip lists", parameters=parameters, assets=['illumio'], callback=Create_Ruleset, name="Get_IP_List_1")

    return

def join_Get_IP_List_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Get_IP_List_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Create_Service_Binding', 'Provision_Object_1', 'Create_Service_Binding_2', 'Create_Virtual_Service']):
        
        # call connected block "Get_IP_List_1"
        Get_IP_List_1(container=container, handle=handle)
    
    return

def Create_Rule(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Rule() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Create_Rule' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_IP_List_1:action_result.data.*.ip_lists.*.href', 'Get_IP_List_1:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Create_Virtual_Service:action_result.data.*.href', 'Create_Virtual_Service:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_3 = phantom.collect2(container=container, datapath=['Create_Ruleset:action_result.data.*.href', 'Create_Ruleset:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Create_Rule' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            for results_item_3 in results_data_3:
                if results_item_1[0] and results_item_2[0] and results_item_3[0]:
                    parameters.append({
                        'consumers': results_item_1[0],
                        'providers': results_item_2[0],
                        'ruleset_href': results_item_3[0],
                        'resolve_consumers_as': "workloads",
                        'resolve_providers_as': "virtual_services",
                        # context (artifact id) is added to associate results with the artifact
                        'context': {'artifact_id': results_item_1[1]},
                    })

    phantom.act(action="create rule", parameters=parameters, assets=['illumio'], callback=decision_10, name="Create_Rule", parent_action=action)

    return

def Create_Enforcement_Boundary_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Enforcement_Boundary_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Create_Enforcement_Boundary_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['Port_and_Protocol:action_result.summary.responses.1', 'Port_and_Protocol:action_result.summary.responses.0', 'Port_and_Protocol:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Get_IP_List_1:action_result.data.*.ip_lists.*.href', 'Get_IP_List_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Create_Enforcement_Boundary_1' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_1[1] and results_item_2[0]:
                parameters.append({
                    'name': "EB-SplunkSOAR-{}-{}".format(results_item_1[1],results_item_1[0]),
                    'port': results_item_1[1],
                    'protocol': results_item_1[0],
                    'consumers': results_item_2[0],
                    'providers': "ams",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[2]},
                })

    phantom.act(action="create enforcement boundary", parameters=parameters, assets=['illumio'], callback=decision_5, name="Create_Enforcement_Boundary_1", parent_action=action)

    return

def join_Create_Enforcement_Boundary_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Create_Enforcement_Boundary_1() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Create_Rule', 'Provision_Object_2']):
        
        # call connected block "Create_Enforcement_Boundary_1"
        Create_Enforcement_Boundary_1(container=container, handle=handle)
    
    return

def Provision_Object_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Provision_Object_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Provision_Object_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['Create_Ruleset:action_result.data.*.href', 'Create_Ruleset:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Provision_Object_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hrefs': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="provision objects", parameters=parameters, assets=['illumio'], callback=Create_Enforcement_Boundary_1, name="Provision_Object_2", parent_action=action)

    return

def Update_Enforcement_Mode(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_Enforcement_Mode() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Do you want to Update Enforcement mode ?"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Update_Enforcement_Mode", separator=", ", response_types=response_types, callback=decision_2)

    return

def join_Update_Enforcement_Mode(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Update_Enforcement_Mode() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Provision_Object_3', 'Create_Enforcement_Boundary_1']):
        
        # call connected block "Update_Enforcement_Mode"
        Update_Enforcement_Mode(container=container, handle=handle)
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_2() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Update_Enforcement_Mode:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Get_Workloads_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def Provision_Object_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Provision_Object_3() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Provision_Object_3' call
    results_data_1 = phantom.collect2(container=container, datapath=['Create_Enforcement_Boundary_1:action_result.data.*.href', 'Create_Enforcement_Boundary_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Provision_Object_3' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hrefs': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="provision objects", parameters=parameters, assets=['illumio'], callback=Update_Enforcement_Mode, name="Provision_Object_3")

    return

def Update_Enforcement_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_Enforcement_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_Enforcement_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_Workloads_1:action_result.data.*.workloads.*.href', 'Get_Workloads_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Update_Enforcement_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'workload_hrefs': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="update enforcement mode", parameters=parameters, assets=['illumio'], name="Update_Enforcement_1")

    return

def Create_Enforcement_Boundary_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Enforcement_Boundary_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Create_Enforcement_Boundary_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['Port_and_Protocol:action_result.summary.responses.1', 'Port_and_Protocol:action_result.summary.responses.0', 'Port_and_Protocol:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Get_IP_List_2:action_result.data.*.ip_lists.*.href', 'Get_IP_List_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Create_Enforcement_Boundary_2' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_2[0]:
                parameters.append({
                    'name': "EB-SplunkSOAR-{}-{}".format(results_item_1[1],results_item_1[0]),
                    'port': results_item_1[1],
                    'protocol': results_item_1[0],
                    'consumers': results_item_2[0],
                    'providers': "ams",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[2]},
                })

    phantom.act(action="create enforcement boundary", parameters=parameters, assets=['illumio'], callback=decision_6, name="Create_Enforcement_Boundary_2", parent_action=action)

    return

def Get_IP_List_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_IP_List_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_IP_List_2' call

    parameters = []
    
    # build parameters list for 'Get_IP_List_2' call
    parameters.append({
        'fqdn': "",
        'name': "Any (0.0.0.0/0 and ::/0)",
        'ip_address': "",
        'description': "",
    })

    phantom.act(action="get ip lists", parameters=parameters, assets=['illumio'], callback=Create_Enforcement_Boundary_2, name="Get_IP_List_2")

    return

def Update_Enforcement_Mode2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_Enforcement_Mode2() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Do you want to Update Enforcement mode ?"""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="Update_Enforcement_Mode2", separator=", ", response_types=response_types, callback=decision_3)

    return

def join_Update_Enforcement_Mode2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_Update_Enforcement_Mode2() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['Provision_Object_4', 'Create_Enforcement_Boundary_2']):
        
        # call connected block "Update_Enforcement_Mode2"
        Update_Enforcement_Mode2(container=container, handle=handle)
    
    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_3() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Update_Enforcement_Mode2:action_result.summary.responses.0", "==", "Yes"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        Get_Workloads_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2

    return

def Provision_Object_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Provision_Object_4() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Provision_Object_4' call
    results_data_1 = phantom.collect2(container=container, datapath=['Create_Enforcement_Boundary_2:action_result.data.*.href', 'Create_Enforcement_Boundary_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Provision_Object_4' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hrefs': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="provision objects", parameters=parameters, assets=['illumio'], callback=Update_Enforcement_Mode2, name="Provision_Object_4")

    return

def Update_Enforcement_Mode_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Update_Enforcement_Mode_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Update_Enforcement_Mode_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_Workloads_2:action_result.data.*.workloads.*.href', 'Get_Workloads_2:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Update_Enforcement_Mode_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'workload_hrefs': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="update enforcement mode", parameters=parameters, assets=['illumio'], name="Update_Enforcement_Mode_2")

    return

def Create_Service_Binding(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Service_Binding() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Create_Service_Binding' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_Traffic_Analysis:action_result.data.*.traffic_flows.*.dst.workload.href', 'Get_Traffic_Analysis:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Provision_Object_1:action_result.data.*.provisioned_href.0', 'Provision_Object_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Create_Service_Binding' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_2[0]:
                parameters.append({
                    'workload_hrefs': results_item_1[0],
                    'virtual_service_href': results_item_2[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="create service binding", parameters=parameters, assets=['illumio'], callback=Get_IP_List_1, name="Create_Service_Binding")

    return

def Create_Ruleset(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Ruleset() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Create_Ruleset' call
    results_data_1 = phantom.collect2(container=container, datapath=['Port_and_Protocol:action_result.summary.responses.0', 'Port_and_Protocol:action_result.summary.responses.1', 'Port_and_Protocol:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Create_Ruleset' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and results_item_1[1]:
            parameters.append({
                'name': "RS-SplunkSOAR-{}-{}".format(results_item_1[0],results_item_1[1]),
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[2]},
            })

    phantom.act(action="create ruleset", parameters=parameters, assets=['illumio'], callback=Create_Rule, name="Create_Ruleset", parent_action=action)

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_4() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['Get_Traffic_Analysis:action_result.data.*.traffic_flows.*.dst.workload.href'], action_results=results)
    workload_list = []
    for val in results_data_1:
        phantom.debug(type(val[0]))
        if val[0]:
            workload_list.append(val[0])

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Found existing virtual service", "in", "Create_Virtual_Service:action_result.message"],
            [workload_list, "==", []],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Provisioning Virtual Service and Create Service binding', 
                     content='Skipping Provisioning Virtual Service and Create Service binding as found existing Virtual Service and no workloads found in Get Traffic Analysis')
        Get_IP_List_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Found existing virtual service", "in", "Create_Virtual_Service:action_result.message"],
        ])

    # call connected blocks if condition 2 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Provisioning Virtual Service', 
                     content='Skipping Provisioning Virtual Service as found existing Virtual Service')
        Create_Service_Binding_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    Provision_Object_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_5() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Found existing enforcement boundary", "in", "Create_Enforcement_Boundary_1:action_result.message"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Provisioning of Enforcement Boundary', 
                     content='Skipping Provisioning of Enforcement Boundary as Enforcement Boundary already exist')
        Update_Enforcement_Mode(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Provision_Object_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_6() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Found existing enforcement boundary", "in", "Create_Enforcement_Boundary_2:action_result.message"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Provisioning of Enforcement Boundary', 
                     content='Skipping Provisioning of Enforcement Boundary as Enforcement Boundary already exist')
        Update_Enforcement_Mode2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Provision_Object_4(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_7() called')

    results_data_1 = phantom.collect2(container=container, datapath=['Get_Traffic_Analysis:action_result.data.*.traffic_flows.*.dst.workload.href'], action_results=results)
    workload_list = []
    for val in results_data_1:
        phantom.debug(type(val[0]))
        if val[0]:
            workload_list.append(val[0])

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            [workload_list, "==", []],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Create Service binding', 
                     content='Skipping Create Service binding as no workloads found in Get Traffic Analysis')
        Get_IP_List_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Create_Service_Binding(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Get_Traffic_Analysis(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_Traffic_Analysis() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_Traffic_Analysis' call
    results_data_1 = phantom.collect2(container=container, datapath=['Time_Range_To_Allow_Traffic:action_result.summary.responses.0', 'Time_Range_To_Allow_Traffic:action_result.summary.responses.1', 'Time_Range_To_Allow_Traffic:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Port_and_Protocol:action_result.summary.responses.1', 'Port_and_Protocol:action_result.summary.responses.0', 'Port_and_Protocol:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Get_Traffic_Analysis' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_1[1] and results_item_2[0] and results_item_2[1]:
                parameters.append({
                    'start_time': results_item_1[0],
                    'end_time': results_item_1[1],
                    'port': results_item_2[1],
                    'protocol': results_item_2[0],
                    'policy_decisions': "potentially_blocked,unknown",
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[2]},
                })

    phantom.act(action="get traffic analysis", parameters=parameters, assets=['illumio'], callback=Create_Virtual_Service, name="Get_Traffic_Analysis")

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_8() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_Workloads_1:action_result.data.*.workloads.*.href", "==", ""],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Update Enforcement Mode', 
                     content='Skipping Update Enforcement Mode as no workloads found in Visibility Only')
        return

    # call connected blocks for 'else' condition 2
    Update_Enforcement_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_9() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Get_Workloads_2:action_result.data.*.workloads.*.href", "==", None],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Update Enforcement Mode', 
                     content='Skipping Update Enforcement Mode as no workloads found in Visibility Only')
        return

    # call connected blocks for 'else' condition 2
    Update_Enforcement_Mode_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('decision_10() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["Found existing rule", "in", "Create_Rule:action_result.message"],
        ])

    # call connected blocks if condition 1 matched
    if matched:
        phantom.add_note(container=container, 
                     note_type='general', 
                     title='Skipped Provisioning of Ruleset', 
                     content='Skipping Provisioning of Ruleset as Rule already exist inside Ruleset')
        Create_Enforcement_Boundary_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 2
    Provision_Object_2(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

def Create_Service_Binding_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Create_Service_Binding_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Create_Service_Binding_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['Get_Traffic_Analysis:action_result.data.*.traffic_flows.*.dst.workload.href', 'Get_Traffic_Analysis:action_result.parameter.context.artifact_id'], action_results=results)
    results_data_2 = phantom.collect2(container=container, datapath=['Create_Virtual_Service:action_result.data.*.href', 'Create_Virtual_Service:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'Create_Service_Binding_2' call
    for results_item_1 in results_data_1:
        for results_item_2 in results_data_2:
            if results_item_1[0] and results_item_2[0]:
                parameters.append({
                    'workload_hrefs': results_item_1[0],
                    'virtual_service_href': results_item_2[0],
                    # context (artifact id) is added to associate results with the artifact
                    'context': {'artifact_id': results_item_1[1]},
                })

    phantom.act(action="create service binding", parameters=parameters, assets=['illumio'], callback=Get_IP_List_1, name="Create_Service_Binding_2")

    return

def Get_Workloads_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_Workloads_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_Workloads_1' call

    parameters = []
    
    # build parameters list for 'Get_Workloads_1' call
    parameters.append({
        'max_results': sys.maxsize,
        'enforcement_mode': "VISIBILITY_ONLY",
        'online': "",
        'managed': "",
        'name': "",
        'labels': "",
        'public_ip_address': "",
        'description': "",
        'hostname': "",
        'os_id': "",
    })

    phantom.act(action="get workloads", parameters=parameters, assets=['illumio'], callback=decision_8, name="Get_Workloads_1")

    return

def Get_Workloads_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('Get_Workloads_2() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'Get_Workloads_2' call

    parameters = []
    
    # build parameters list for 'Get_Workloads_2' call
    parameters.append({
        'max_results': sys.maxsize,
        'enforcement_mode': "VISIBILITY_ONLY",
        'online': "",
        'managed': "",
        'name': "",
        'labels': "",
        'public_ip_address': "",
        'description': "",
        'hostname': "",
        'os_id': "",
    })

    phantom.act(action="get workloads", parameters=parameters, assets=['illumio'], callback=decision_9, name="Get_Workloads_2")

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