"""
This playbook runs all the pan actions one by one.
"""

import phantom.rules as phantom
import json
from datetime import datetime
from datetime import timedelta 

def block_url_cb(action, success, container, results, handle):

    if not success:
        return

    return

def unblock_ip_cb(action, success, container, results, handle):

    if not success:
        return
    
    when = datetime.now()+timedelta(seconds=40) 
    phantom.act('block url', parameters=[{ "url" : "www.yahoo.com" }], assets=["pan"], callback=block_url_cb, start_time=when)

    return

def block_ip_cb(action, success, container, results, handle):

    if not success:
        return

    when = datetime.now()+timedelta(seconds=40) 
    phantom.act('unblock ip', parameters=[{ "ip" : "192.94.73.3" }], assets=["pan"], callback=unblock_ip_cb, start_time=when)

    return

def block_application_cb(action, success, container, results, handle):

    if not success:
        return

    when = datetime.now()+timedelta(seconds=40) 
    
    # Block www.freeshell.org, configure the action after a while, noticed that the commit is still not finished
    # on the remote device
    phantom.act('block ip', parameters=[{ "ip" : "192.94.73.3" }], assets=["pan"], callback=block_ip_cb, start_time=when)

    return

def list_applications_cb(action, success, container, results, handle):

    if not success:
        return

    phantom.act('block application', parameters=[{ "application" : "ftp" }], assets=["pan"], callback=block_application_cb)

    return


def on_start(incident):

    phantom.act('list applications', parameters=[{ }], assets=["pan"], callback=list_applications_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
