"""
This playbook runs all the jira actions one by one.
"""

import phantom.rules as phantom
import json

def list_tickets_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def get_ticket_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('list tickets', parameters=[{ "project_key" : 'AP', "max_results": "50"}], assets=["jira"], callback=list_tickets_cb) 

    return

def create_ticket_cb(action, success, incident, results, handle):

    if not success:
        return


    phantom.debug("results: {0}".format(json.dumps(results)))

    data = results[0]['action_results'][0]['data']

    id = data[0]['id']

    phantom.act('get ticket', parameters=[{ "id" : id}], assets=["jira"], callback=get_ticket_cb) 

    return

def list_projects_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('create ticket', parameters=[{ "description" : "Zeus, Multiple action need to be taken",  "project_key" : "AP",  "summary" : "Zeus" }], assets=["jira"], callback=create_ticket_cb) 
    return 

def on_start(incident): 
    phantom.act('list projects', parameters=[{ }], assets=["jira"], callback=list_projects_cb) 
    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
