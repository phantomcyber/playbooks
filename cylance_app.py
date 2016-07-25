""" 
This playbook runs Cylance actions one by one.
Last updated by Phantom Team: July 11th, 2016
"""
import phantom.rules as phantom
import json

def hunt_file_cb(action, success, container, results, handle):

    if not success:
        return

    return

def get_file_info_cb(action, success, container, results, handle):

    if not success:
        return

    return

def block_hash_cb(action, success, container, results, handle):

    if not success:
        return

    return

def unblock_hash_cb(action, success, container, results, handle):

    if not success:
        return

    return

def get_file_cb(action, success, container, results, handle):

    if not success:
        return

    return

def get_system_info_cb(action, success, container, results, handle):

    if not success:
        return
    
    parameters = []
    parameters.append({
        "hash": "B3B207DFAB2F429CC352BA125BE32A0CAE69FE4BF8563AB7D0128BBA8C57A71C"
    })

    phantom.act("hunt file", parameters=parameters, assets=["cylance_1"]) # callback=hunt_file_cb

    phantom.act("get file info", parameters=parameters, assets=["cylance_1"]) # callback=get_file_info_cb



    phantom.act("block hash", parameters=parameters, assets=["cylance_1"]) # callback=block_hash_cb

    phantom.act("unblock hash", parameters=parameters, assets=["cylance_1"]) # callback=unblock_hash_cb

    phantom.act("get file", parameters=parameters, assets=["cylance_1"]) # callback=get_file_cb

    return

def list_endpoints_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({"device_id": "a43572bf-fd4c-4534-a5e6-e1231b002a9a"})

    phantom.act("get system info", parameters=parameters, assets=["cylance_1"], callback=get_system_info_cb)

    return


def on_start(container):

    parameters = []

    parameters.append({})

    phantom.act("list endpoints", parameters=parameters, assets=["cylance_1"], callback=list_endpoints_cb)

    return

def on_finish(container, summary):

    # This function is called after all actions are completed.
    # Summary and/or action results can be collected here.

    # summary_json = phantom.get_summary()
    # summary_results = summary_json['result']
    # for result in summary_results:
            # action_run_id = result['id']
            # action_results = phantom.get_action_results(action_run_id=action_run_id)
    return