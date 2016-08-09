"""
This playbook runs all the RT actions one by one.
Last updated by Phantom Team: August 09, 2016
"""

import phantom.rules as phantom
import json

def get_ticket_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def create_ticket_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.debug("results: {0}".format(json.dumps(results)))

    data = results[0]['action_results'][0]['data']

    id = data[0]['id']

    phantom.act('get ticket', parameters=[{ "id" : id}], assets=["rt"], callback=get_ticket_cb) 

    return

def list_tickets_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('create ticket', parameters=[{ "subject" : "Zeus Incident.",  "text" : "Please look into this",  "priority" : "3" }], assets=["rt"], callback=create_ticket_cb)

    return


def on_start(incident):

    phantom.act('list tickets', parameters=[{ }], assets=["rt"], callback=list_tickets_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
