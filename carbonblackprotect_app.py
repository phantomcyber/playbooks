"""
This is a playbook for the actions of the Carbon Black Protection (bit9) app
Last made changes on July 26
"""
import phantom.rules as phantom
import json

def block_hash_cb(action, success, container, results, handle):

    if not success:
        return

    return

def unblock_hash_cb(action, success, container, results, handle):

    if not success:
        return

    return

def hunt_file_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({"hash": "c6ea58cc1c16ec0f7bbd4b8e4bf28910",})

    phantom.act("block hash", parameters=parameters, assets=["cbprotect"]) # callback=block_hash_cb

    parameters = []

    parameters.append({
        "hash": "c6ea58cc1c16ec0f7bbd4b8e4bf28910",
        "file_state": "approved",
    })

    phantom.act("unblock hash", parameters=parameters, assets=["cbprotect"]) # callback=unblock_hash_cb

    return


def on_start(container):

    parameters = []

    parameters.append({
        "hash": "c6ea58cc1c16ec0f7bbd4b8e4bf28910",
        "get_details": False,
    })

    phantom.act("hunt file", parameters=parameters, assets=["cbprotect"], callback=hunt_file_cb)

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
