"""
This playbook runs all the qradar actions one by one.
"""
import phantom.rules as phantom
import json

def list_offenses_cb(action, success, incident, results, handle):

    if not success:
        return
    
    # dump the results
    phantom.debug(json.dumps(results, indent=4))
    
    data = None
    
    # Get the data from results, ideally we would loop over the results
    try:
        data = results[0]['action_results'][0]['data']
    except:
        return
        
    if (not data):
        return
    
    # data is a list of offenses, only work on the 1st one for now
    try:
        offense_id = data[0]['id']
    except:
        return
    
    # Execute all the actions that can be made on an offense id
    phantom.act('get events', parameters=[{ "count" : "10",  "offense_id" : offense_id }], assets=["qradar_entr"], callback=get_events_cb)

    phantom.act('get flows', parameters=[{ "count" : "10",  "ip" : "10.16.1.60",  "offense_id" : offense_id }], assets=["qradar_entr"], callback=get_flows_cb)

    phantom.act('get flows', parameters=[{ "count" : "10",  "offense_id" : offense_id }], assets=["qradar_entr"], callback=get_flows1_cb)

    phantom.act('offense details', parameters=[{ "offense_id" : offense_id }], assets=["qradar_entr"], callback=offense_details_cb)

    return

def get_events_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def get_flows_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def get_flows1_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def offense_details_cb(action, success, incident, results, handle):

    if not success:
        return

    return


def on_start(incident):

    # First get the list of offenses
    phantom.act('list offenses', parameters=[{ "count" : "10" }], assets=["qradar_entr"], callback=list_offenses_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
