"""
This playbook runs all the CarbonBlack actions one by one.
"""
import phantom.rules as phantom
import json

def hunt_file_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def run_query_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def run_query1_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def list_alerts_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def create_alert_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def on_start(incident): 

    phantom.act('hunt file', parameters=[{ "hash" : "27801bdf0aaa0da87dbf7637396cd40d" }], assets=["carbonblack"], callback=hunt_file_cb) 
    phantom.act('run query', parameters=[{ "query" : "company_name:Microsoft",  "type" : "binary" }], assets=["carbonblack"], callback=run_query_cb) 
    phantom.act('run query', parameters=[{ "query" : "company_name:Microsoft",  "type" : "process" }], assets=["carbonblack"], callback=run_query1_cb) 

    phantom.act('list alerts', parameters=[{ }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('create alert', parameters=[{ "read_only" : "False",  "query" : "md5:27801bdf0aaa0da87dbf7637396cd40d",  "type" : "process",  "name" : "PSCP_Started" }], assets=["carbonblack"], callback=create_alert_cb) 
    phantom.act('list endpoints', parameters=[{ }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('quarantine device', parameters=[{"ip_hostname": "10.17.1.44" }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('get system info', parameters=[{"ip_hostname": "10.17.1.44" }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('unquarantine device', parameters=[{"ip_hostname": "10.17.1.44" }], assets=["carbonblack"], callback=list_alerts_cb) 
    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
