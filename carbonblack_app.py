"""
This playbook runs all the carbonblack actions one by one.
Last updated by Phantom Team: August 09, 2016
"""
import phantom.rules as phantom
import json
from datetime import datetime
from datetime import timedelta 

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

def block_hash_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('unblock hash', parameters=[{"hash": "f2c7bb8acc97f92e987a2d4087d021b1"}], assets=["carbonblack"])
        
    return

def unblock_hash_cb(action, success, incident, results, handle):

    phantom.act('block hash', parameters=[{"hash": "f2c7bb8acc97f92e987a2d4087d021b1", "comment": "From Playbook"}], assets=["carbonblack"], callback=block_hash_cb)
        
    return

def on_start(incident): 
    
    phantom.act('hunt file', parameters=[{ "hash" : "27801bdf0aaa0da87dbf7637396cd40d"}], assets=["carbonblack"], callback=hunt_file_cb) 
    phantom.act('run query', parameters=[{ "query" : "company_name:Microsoft",  "type" : "binary" }], assets=["carbonblack"], callback=run_query_cb) 
    phantom.act('run query', parameters=[{ "query" : "company_name:Microsoft",  "type" : "process" }], assets=["carbonblack"], callback=run_query1_cb) 
    
    phantom.act('list alerts', parameters=[{ }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('create alert', parameters=[{ "read_only" : "False",  "query" : "md5:27801bdf0aaa0da87dbf7637396cd40d",  "type" : "process",  "name" : "PSCP_Started" }], assets=["carbonblack"], callback=create_alert_cb) 
    phantom.act('list endpoints', parameters=[{ }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('quarantine device', parameters=[{"ip_hostname": "10.17.1.44" }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('get system info', parameters=[{"ip_hostname": "10.17.1.44" }], assets=["carbonblack"], callback=list_alerts_cb) 
    phantom.act('unquarantine device', parameters=[{"ip_hostname": "10.17.1.44" }], assets=["carbonblack"], callback=list_alerts_cb)
    
    # Start this action after a while, else the server gets too busy and live session creation takes a lot of time.
    when = datetime.now()+timedelta(seconds=60)
    phantom.act('list processes', parameters=[{"ip_hostname": "10.17.1.50" }], assets=["carbonblack"], callback=list_alerts_cb, start_time=when)
    when = datetime.now()+timedelta(seconds=30)    
    phantom.act('get file info', parameters=[{"hash": "5FB30FE90736C7FC77DE637021B1CE7C" }], assets=["carbonblack"], start_time=when)
    phantom.act('unblock hash', parameters=[{"hash": "f2c7bb8acc97f92e987a2d4087d021b1"}], assets=["carbonblack"], callback=unblock_hash_cb) 


    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
