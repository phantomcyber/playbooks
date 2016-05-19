"""
This playbook runs all the Juniper SRX actions one by one.
Last updated by Phantom Team: May 19, 2016
"""

import phantom.rules as phantom
import json

def unblock_application_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def unblock_ip_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('unblock application', parameters=[{ "application" : "junos-http",  "from_zone" : "trust",  "to_zone" : "untrust" }], assets=["junipersrx"], callback=unblock_application_cb)

    return

def block_application_cb(action, success, incident, results, handle):

    if not success:
        return

    ips = set(phantom.collect(incident, 'artifact:*.cef.destinationAddress', scope='all'))

    parameters = []

    for ip in ips:
        parameters.append({ "ip" : ip,  "from_zone" : "trust",  "to_zone" : "untrust" })

    if parameters:
        phantom.act('unblock ip', parameters=parameters, assets=["junipersrx"], callback=unblock_ip_cb)

    return

def block_ip_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('block application', parameters=[{ "application" : "junos-http",  "from_zone" : "trust",  "to_zone" : "untrust" }], assets=["junipersrx"], callback=block_application_cb)

    return


def on_start(incident):

    ips = set(phantom.collect(incident, 'artifact:*.cef.destinationAddress', scope='all'))

    parameters = []

    for ip in ips:
        parameters.append({ "ip" : ip,  "from_zone" : "trust",  "to_zone" : "untrust" })

    if parameters:
        phantom.act('block ip', parameters=parameters, assets=["junipersrx"], callback=block_ip_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
