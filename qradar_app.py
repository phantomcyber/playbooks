"""
This playbook runs all the qradar actions one by one.
"""
import phantom.rules as phantom
import json

def list_offenses_cb(action, success, incident, results, handle):

    if not success:
        return

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

    phantom.act('list offenses', parameters=[{ "count" : "10" }], assets=["qradar_entr"], callback=list_offenses_cb)

    phantom.act('get events', parameters=[{ "count" : "10",  "offense_id" : "9" }], assets=["qradar_entr"], callback=get_events_cb)

    phantom.act('get flows', parameters=[{ "count" : "10",  "ip" : "10.16.1.60",  "offense_id" : "1" }], assets=["qradar_entr"], callback=get_flows_cb)

    phantom.act('get flows', parameters=[{ "count" : "10",  "offense_id" : "2" }], assets=["qradar_entr"], callback=get_flows1_cb)

    phantom.act('offense details', parameters=[{ "offense_id" : "3" }], assets=["qradar_entr"], callback=offense_details_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
