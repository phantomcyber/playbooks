"""
This playbook runs the 'test connectivity' action on all possible assets currently configured.
"""

import phantom.rules as phantom
import json

def get_report_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def on_start(incident):

    # run test connectivity on all available assets
    phantom.act('test connectivity', parameters=[], callback=get_report_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return