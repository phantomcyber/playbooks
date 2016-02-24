"""
This playbook runs all the servicenow actions one by one.
"""

import phantom.rules as phantom
import json

def update_ticket_cb(action, success, incident, results, handle):

    phantom.debug("results: {0}".format(json.dumps(results)))

    data = results[0]['action_results'][0]['data']

    id = data[0]['sys_id']

    phantom.act('get ticket', parameters=[{ "id" : id}], assets=["servicenow"]) 
    
    return


def get_ticket_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.debug("results: {0}".format(json.dumps(results)))

    data = results[0]['action_results'][0]['data']

    id = data[0]['sys_id']
    
    # stringized version of a dictionary
    fields_to_update = '{"short_description": "Zeus, Run file reputation actions only", "made_sla": false}'

    phantom.act('update ticket', parameters=[{ "id" : id, "fields": fields_to_update}], assets=["servicenow"], callback=update_ticket_cb) 

    return

def create_ticket_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.debug("results: {0}".format(json.dumps(results)))

    data = results[0]['action_results'][0]['data']

    id = data[0]['sys_id']

    phantom.act('get ticket', parameters=[{ "id" : id}], assets=["servicenow"], callback=get_ticket_cb) 

    return

def list_tickets_cb(action, success, incident, results, handle):

    if not success:
        return

    # setting 'other' fields
    fields_to_update = '{"made_sla": true}'

    phantom.act('create ticket', parameters=[{ "short_description" : "Zeus, Multiple action need to be taken",  "description" : "Investigative actions to check for the presence of Zeus", "fields": fields_to_update}], assets=["servicenow"], callback=create_ticket_cb) 
    return 

def on_start(incident): 
    phantom.act('list tickets', parameters=[{ }], assets=["servicenow"], callback=list_tickets_cb) 
    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return

