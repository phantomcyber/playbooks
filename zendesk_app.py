"""Executes Zendesk app actions one by one.
Last updated by Phantom Team: August 09, 2016
"""

import phantom.rules as phantom
import json

def get_ticket_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({
        "query": "\"Herman\"",
        "max_results": "",
    })

    phantom.act("run query", parameters=parameters, assets=["zendesk"])

    return

def update_ticket_cb(action, success, container, results, handle):

    parameters = []

    parameters.append({"id": "1",})

    phantom.act("get ticket", parameters=parameters, assets=["zendesk"], callback=get_ticket_cb)

    return

def create_ticket_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({
        "id": "1",
        "fields": "{\"status\": \"solved\"}",
    })

    phantom.act("update ticket", parameters=parameters, assets=["zendesk"], callback=update_ticket_cb)

    return

def list_tickets_cb(action, success, container, results, handle):

    if not success:
        return

    parameters = []

    parameters.append({
        "subject": "Zeus detections",
        "description": "Remediate quickly",
        "fields": "",
    })

    phantom.act("create ticket", parameters=parameters, assets=["zendesk"], callback=create_ticket_cb)

    return


def on_start(container):

    parameters = []

    parameters.append({"max_results": "",})

    phantom.act("list tickets", parameters=parameters, assets=["zendesk"], callback=list_tickets_cb)

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
