"""
This rule runs all the CiscoASA actions one by one.
"""

import phantom.rules as phantom
import json

def unblock_ip_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def block_ip_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('unblock ip', parameters=[{ "dest" : "10.10.10.2",  "access-list" : "inside_access_in",  "direction" : "in",  "interface" : "inside",  "src" : "any" }], assets=["ciscoasa"], callback=unblock_ip_cb)

    return

def get_config_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('block ip', parameters=[{ "src" : "any",  "direction" : "in",  "dest" : "10.10.10.2",  "access-list" : "inside_access_in",  "interface" : "inside" }], assets=["ciscoasa"], callback=block_ip_cb)

    return

def get_version_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('get config', parameters=[{ }], assets=["ciscoasa"], callback=get_config_cb)

    return


def on_start(incident):

    phantom.act('get version', parameters=[{ }], assets=["ciscoasa"], callback=get_version_cb)

    return

def on_finish(incident, summary):
    phantom.debug("Summary: " + summary)
    return
