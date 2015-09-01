"""
This sample rule shows calling one or more actions scheduled in the future.
"""
import json
import phantom.rules as phantom
from datetime import datetime
from datetime import timedelta 

def on_start(incident):
    # schedule gelolocation lookup 1 minute after now
    
    params=[]
    params.append({'ip':'1.1.1.1'})
    
    when = datetime.now()+timedelta(seconds=10)
    phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=str(params), start_time=when)
    
    when = datetime.now()+timedelta(seconds=20)
    phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=str(params), start_time=when)
    
    when = datetime.now()+timedelta(seconds=30)
    phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=str(params), start_time=when)
    
    when = datetime.now()+timedelta(seconds=40)
    phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=str(params), start_time=when)
    
    when = datetime.now()+timedelta(seconds=50)
    phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=str(params), start_time=when)
    
    when = datetime.now()+timedelta(seconds=60)
    phantom.act("geolocate ip", parameters=params, callback=generic_cb, handle=str(params), start_time=when)

def generic_cb(action_name, status, incident, results, handle):
    phantom.debug('Action '+action_name+ (' SUCCEEDED' if status else ' FAILED'))
    phantom.debug('My Handle: '+handle)
    return



def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  


