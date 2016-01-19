"""
This playbook runs the OpenDNS actions one after another.
"""

import phantom.rules as phantom
import json

def whois_domain_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def ip_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('whois domain', parameters=[{ "domain" : "bjtuangouwang.com" }], assets=["opendns_investigate"], callback=whois_domain_cb)

    return

def domain_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('ip reputation', parameters=[{ "ip" : "1.1.1.1" }], assets=["opendns_investigate"], callback=ip_reputation_cb)

    return


def on_start(incident):

    phantom.act('domain reputation', parameters=[{ "domain" : "bjtuangouwang.com" }], assets=["opendns_investigate"], callback=domain_reputation_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return