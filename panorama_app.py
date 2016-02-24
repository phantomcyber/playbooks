"""
This playbook runs all the panorama actions one by one.
"""

import phantom.rules as phantom
import json
from datetime import datetime
from datetime import timedelta 



def unblock_ip_cb(action, success, container, results, handle):

    if not success:
        return

    return

def unblock_application_cb(action, success, container, results, handle):

    if not success:
        return

    ips = set(phantom.collect(container, 'artifact:*.cef.destinationAddress'))

    parameters = []

    for ip in ips:
        parameters.append({ "ip" : ip,  "device_group" : "My Device Group"})

    if parameters:        
        # Wait for a few seconds for the policy change from the previous action to take affect
        when = datetime.now()+timedelta(seconds=30)
        phantom.act('unblock ip', parameters=parameters, assets=["panorama"], callback=unblock_ip_cb, start_time=when)

    return


def unblock_url_cb(action, success, container, results, handle):

    if not success:
        return

    # Wait for a few seconds for the policy change from the previous action to take affect
    when = datetime.now()+timedelta(seconds=30)
    phantom.act('unblock application', parameters=[{ "application" : "ftp",  "device_group" : "My Device Group"}], assets=["panorama"],
                callback=unblock_application_cb, start_time=when)

    return

def list_applications_cb(action, success, container, results, handle):

    if not success:
        return

    urls = set(phantom.collect(container, 'artifact:*.cef.requestURL'))

    parameters = []

    for url in urls:
        parameters.append({ "url" : url,  "device_group" : "My Device Group"})

    if parameters:
        # Wait for a few seconds for the policy change from the previous action to take affect
        when = datetime.now()+timedelta(seconds=30)
        phantom.act('unblock url', parameters=parameters, assets=["panorama"], callback=unblock_url_cb, start_time=when)

    return

def block_url_cb(action, success, container, results, handle):

    if not success:
        return
    
    phantom.act('list applications', parameters=[], assets=["panorama"], callback=list_applications_cb)

    return

def block_application_cb(action, success, container, results, handle):

    if not success:
        return

    urls = set(phantom.collect(container, 'artifact:*.cef.requestURL'))

    parameters = []

    for url in urls:
        parameters.append({ "url" : url,  "device_group" : "My Device Group",  "policy_type" : "pre-rulebase",  "policy_name" : "BlockURLTestRule" })

    if parameters:
        # Wait for a few seconds for the policy change from the previous action to take affect
        when = datetime.now()+timedelta(seconds=30)
        phantom.act('block url', parameters=parameters, assets=["panorama"], callback=block_url_cb, start_time=when)

    return

def block_ip_cb(action, success, container, results, handle):

    if not success:
        return

    # Wait for a few seconds for the policy change from the previous action to take affect
    when = datetime.now()+timedelta(seconds=30)
    phantom.act('block application', parameters=[{ "application" : "ftp",  "device_group" : "My Device Group",  "policy_type" : "pre-rulebase",  "policy_name" : "BlockAppTestRule" }], assets=["panorama"],
                callback=block_application_cb, start_time=when)

    return


def on_start(container):

    ips = set(phantom.collect(container, 'artifact:*.cef.destinationAddress'))

    parameters = []

    for ip in ips:
        parameters.append({ "ip" : ip,  "device_group" : "My Device Group",  "policy_type" : "pre-rulebase",  "policy_name" : "BlockIPTestRule" })

    if parameters:
        phantom.act('block ip', parameters=parameters, assets=["panorama"], callback=block_ip_cb)

    return

def on_finish(container, summary):

    phantom.debug("Summary: " + summary)
    
    return
