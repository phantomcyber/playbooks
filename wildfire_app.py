"""
This playbook runs all wildfire actions one by one.
Last updated by Phantom Team: May 19, 2016
"""
import phantom.rules as phantom
import json

def get_pcap_cb(action, success, container, results, handle):

    if not success:
        return

    return

def get_file_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({
        "hash": "b90b5735bc4661a02cb214c6e1d3890eb55a0c46b9d3b6bb6a1ab285c2fa7d9b",
        "platform": "Default",
    })

    phantom.act("get pcap", parameters=parameters, assets=["wildfire"]) # callback=get_pcap_cb

    return

def get_report_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({"hash": "b90b5735bc4661a02cb214c6e1d3890eb55a0c46b9d3b6bb6a1ab285c2fa7d9b",})

    phantom.act("get file", parameters=parameters, assets=["wildfire"], callback=get_file_cb)

    return

def detonate_file_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({"id": "b90b5735bc4661a02cb214c6e1d3890eb55a0c46b9d3b6bb6a1ab285c2fa7d9b",})

    phantom.act("get report", parameters=parameters, assets=["wildfire"], callback=get_report_cb)

    return


def on_start(container):

    parameters = []

    parameters.append({
        "vault_id": "2694666a756bb8ed44109eccf466dafad7b336b8",
        "file_name": "",
    })

    phantom.act("detonate file", parameters=parameters, assets=["wildfire"], callback=detonate_file_cb)

    return

def on_finish(container, summary):

    # This function is called after all actions are completed.
    # Summary and/or action results can be collected here.

    # summary_json = phantom.get_summary()
    # summary_results = summary_json['result']
    # for result in summary_results:
            # app_runs = result['app_runs']
            # for app_run in app_runs:
                    # app_run_id = app_run['app_run_id']
                    # action_results = phantom.get_action_results(app_run_id=app_run_id)
    return
