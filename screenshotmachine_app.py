"""
This playbook runs the screenshot action.
"""

import phantom.rules as phantom
import json

def get_screenshot_cb(action, success, container, results, handle):

    if not success:
        return

    return


def on_start(container):

    parameters = []

    parameters.append({"url": "www.amazon.com",})

    phantom.act("get screenshot", parameters=parameters, assets=["screenshot"]) # callback=get_screenshot_cb

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
