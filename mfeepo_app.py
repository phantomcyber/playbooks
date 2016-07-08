"""
Playbook for showing the basic functionality of the McAfee ePO app
by running through all of its actions one by one
"""
import phantom.rules as phantom
import json

def get_device_info_cb(action, success, container, results, handle):

    if not success:
        return

    return

def add_tag_cb(action, success, container, results, handle):

    if not success:
        return

    return

def add_tag1_cb(action, success, container, results, handle):

    if not success:
        return

    return

def remove_tag_cb(action, success, container, results, handle):

    if not success:
        return

    return

def quarantine_device_cb(action, success, container, results, handle):

    if not success:
        return

    return

def unquarantine_device_cb(action, success, container, results, handle):

    if not success:
        return

    return


def on_start(container):

    parameters = []

    parameters.append({"ip_hostname": "ePO",})

    phantom.act("get device info", parameters=parameters, assets=["epo3"]) # callback=get_device_info_cb

    parameters = []

    parameters.append({
        "ip_hostname": "ePO",
        "tag": "Server",
        "wakeup_agent": False,
    })

    phantom.act("add tag", parameters=parameters, assets=["epo3"]) # callback=add_tag_cb

    parameters = []

    parameters.append({
        "ip_hostname": "ePO",
        "tag": "Server",
        "wakeup_agent": False,
    })

    phantom.act("add tag", parameters=parameters, assets=["epo3"]) # callback=add_tag1_cb

    parameters = []

    parameters.append({
        "ip_hostname": "ePO",
        "tag": "Server",
        "wakeup_agent": True,
    })

    phantom.act("remove tag", parameters=parameters, assets=["epo3"]) # callback=remove_tag_cb

    parameters = []

    parameters.append({
        "ip_hostname": "ePO",
        "wakeup_agent": "",
    })

    phantom.act("quarantine device", parameters=parameters, assets=["epo3"]) # callback=quarantine_device_cb

    parameters = []

    parameters.append({
        "ip_hostname": "ePO",
        "wakeup_agent": "",
    })

    phantom.act("unquarantine device", parameters=parameters, assets=["epo3"]) # callback=unquarantine_device_cb

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
