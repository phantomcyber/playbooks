"""
This playbook runs the PassiveTotal actions one after another.
"""

import phantom.rules as phantom
import json

def ip_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def domain_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('ip reputation', parameters=[{ "ip" : "1.1.1.1" }], assets=["passivetotal"], callback=ip_reputation_cb)

    return


def on_start(incident):

    phantom.act('domain reputation', parameters=[{ "domain" : "bjtuangouwang.com" }], assets=["passivetotal"], callback=domain_reputation_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return