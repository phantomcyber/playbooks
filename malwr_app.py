"""
This Playbook executes the malwr actions one by one
Last updated by Phantom Team: May 19, 2016
"""

import phantom.rules as phantom
import json

def detonate_file_cb(action, success, container, results, handle):

    if not success:
        return

    task_ids = phantom.collect(results, "action_result.data.*.id")
    
    phantom.debug(task_ids)
    
    parameters = []
    
    for task_id in task_ids:
        parameters.append({'id': task_id})
        
    
    phantom.act("get report", parameters=parameters, assets=["malwr"])

    return


def on_start(container):
    
    # set of file contains that are supported by the action
    allowed_file_types = set(["pdf", "pe file", "flash" "doc"])
    
    # get all the vault items
    vault_items = phantom.get_vault_item_info(get_hashes=False)
    
    # the lambda function that will be used for the filter
    get_related_files = lambda x: bool(allowed_file_types.intersection(x['contains']))
    
    # get all the vault items that are of type allowed_file_types
    vault_infos = filter(get_related_files, vault_items)
    
    # phantom.debug(vault_infos)
    
    parameters = []

    for vault_info in vault_infos:
        parameters.append({
            "vault_id": vault_info['vault_document_id'],
            "share": False,
            "private": True,
        })
        
    # parameters = parameters[:2]

    phantom.act("detonate file", parameters=parameters, assets=["malwr"], callback=detonate_file_cb)

    return

def on_finish(container, summary):

    return
