"""
This playbook runs all the jira actions one by one.
Last updated by Phantom Team: August 09, 2016
"""

import phantom.rules as phantom
import json

def list_tickets_cb(action, success, incident, results, handle):

    if not success:
        return

    # create an e.g. dictionary that uses the simple key: value format, also uses a custom field
    update_fields = {"summary": "Zeus detected DETECTED, Please fix it now or else it might become too much of an issue", 
                     "components" : [{"remove" : {"name" : "firstcomponent"}}, {"add" : {"name" : "secondcomponent"}}],
                     "Custom Text Field One": "This is custom text"
                    }
    
    # Create a string version of the same, since we are running from the playbook
    update_fields = json.dumps(update_fields)
    
    phantom.act('update ticket', parameters=[{ "id" : 'AP-32', "update_fields": update_fields}], assets=["jira"]) 


    # create an e.g. dictionary that uses the update format, uses some custom fields too.
    update_fields = {"update": 
                     {
                        "components" : [
                            {"remove" : {"name" : "firstcomponent"}},
                            {"add" : {"name" : "secondcomponent"}}
                            ],
                        "Custom Label Field Two": [{"set": ["CUSTOMFIRSTLABEL"]}], 
                        "Custom Checkbox Field Three": [{"set": [{"value": "Three"}]}]
                     }}
    
    # Create a string version of the same, since we are running from the playbook
    # no need to do this if running from the UI
    update_fields = json.dumps(update_fields)
    
    phantom.act('update ticket', parameters=[{ "id" : 'AP-32', "update_fields": update_fields}], assets=["jira"]) 

    
    # create an e.g. dictionary that uses the fields format
    update_fields = {"fields":{"labels" : ["FIRSTLABEL"]}}
    
    # Create a string version of the same, since we are running from the playbook
    update_fields = json.dumps(update_fields)
    
    phantom.act('update ticket', parameters=[{ "id" : 'AP-32', "update_fields": update_fields}], assets=["jira"]) 

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
