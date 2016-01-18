"""
This playbook runs all the CiscoISE actions one by one.
"""

import phantom.rules as phantom
import json

def get_parameters(success, results):

    if not success:
        return []

    if (not results):
        return []
        
    parameters = []
    
    if ('action_results' not in results[0]):
        return []

    result_items = results[0]['action_results']

    for result_item in result_items:

        phantom.debug(result_item)

        if ('parameter' not in result_item):
            continue
        
        if ('ip_macaddress' not in result_item['parameter']):
            continue
            
        param = {"ip_macaddress": result_item["parameter"]["ip_macaddress"]}
            
        parameters.append(param)
        
    return parameters

def terminate_session_cb(action, success, container, results, handle):

    if not success:
        return

    return

def unquarantine_device_cb(action, success, container, results, handle):

    if not success:
        return

    input_parameters = get_parameters(success, results)
    
    parameters = []
    
    for parameter in input_parameters:
        parameters.append({"macaddress": parameter["ip_macaddress"]})
        
    phantom.debug(json.dumps(parameters, indent=4))

    phantom.act('terminate session', parameters=parameters, assets=["ciscoise"], callback=terminate_session_cb)

    return

def quarantine_device_cb(action, success, container, results, handle):

    if not success:
        return
    
    parameters = get_parameters(success, results)

    phantom.act('unquarantine device', parameters=parameters, assets=["ciscoise"], callback=unquarantine_device_cb)

    return

def list_sessions_cb(action, success, container, results, handle):

    if not success:
        return
    
    result_items = phantom.parse_success(results)
                
    phantom.debug(json.dumps(result_items, indent=4))
              
    parameters = []
    
    for item in result_items:
        
        if ('calling_station_id' not in item):
            continue
            
        param = {"ip_macaddress": item["calling_station_id"]}
        parameters.append(param)

    phantom.act('quarantine device', parameters=parameters, assets=["ciscoise"], callback=quarantine_device_cb)

    return


def on_start(container):

    phantom.act('list sessions', parameters=[{ }], assets=["ciscoise"], callback=list_sessions_cb)

    return

def on_finish(container, summary):

    phantom.debug("Summary: " + summary)

    return
