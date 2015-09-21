"""
This playbook runs all the pan actions one by one.
"""

import phantom.rules as phantom
import json

def block_url_cb(action, success, container, results, handle):

    if not success:
        return

    return

def unblock_ip_cb(action, success, container, results, handle):

    if not success:
        return

    phantom.act('block url', parameters=[{ "url" : "www.yahoo.com" }], assets=["pan"], callback=block_url_cb)

    return

def block_ip_cb(action, success, container, results, handle):

    if not success:
        return

    phantom.act('unblock ip', parameters=[{ "ip" : "192.94.73.3" }], assets=["pan"], callback=unblock_ip_cb)

    return

def block_application_cb(action, success, container, results, handle):

    if not success:
        return

    # Block www.freeshell.org
    phantom.act('block ip', parameters=[{ "ip" : "192.94.73.3" }], assets=["pan"], callback=block_ip_cb)

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
