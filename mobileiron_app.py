"""
This playbook runs all the MobileIron actions one by one.
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
        
        if ('uuid' not in result_item['parameter']):
            continue
            
        param = {"uuid": result_item["parameter"]["uuid"], "reason": "Locking IT"}
            
        parameters.append(param)
        
    return parameters

def unlock_device_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def lock_device_cb(action, success, incident, results, handle):

    parameters = get_parameters(success, results)
    
    if (not parameters):
        return
    
    phantom.act('unlock device', parameters=parameters, assets=["mobileiron"], callback=unlock_device_cb)

    return

def get_system_info_cb(action, success, incident, results, handle):

    parameters = get_parameters(success, results)
    
    if (not parameters):
        return

    phantom.act('lock device', parameters=parameters, assets=["mobileiron"], callback=lock_device_cb)

    return

def list_devices_cb(action, success, incident, results, handle):

    if not success:
        return
    
    result_items = phantom.parse_success(results)
                
    phantom.debug(result_items)
              
    parameters = []
    
    for item in result_items:
        
        if ('uuid' not in item):
            continue
            
        param = {"uuid": item["uuid"]}
        parameters.append(param)

    phantom.act('get system info', parameters=parameters, assets=["mobileiron"], callback=get_system_info_cb)

    return


def on_start(incident):

    phantom.act('list devices', parameters=[{ "start_index" : "0",  "limit" : "100" }], assets=["mobileiron"], callback=list_devices_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
