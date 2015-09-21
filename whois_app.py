"""
This playbook runs all the whois actions one by one.
"""

import phantom.rules as phantom
import json

def whois_domain_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def whois_ip_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('whois domain', parameters=[{ "domain" : "amazon.com" }], assets=["whois"], callback=whois_domain_cb)

    return


def on_start(incident):

    phantom.act('whois ip', parameters=[{ "ip" : "134.170.188.221" }], assets=["whois"], callback=whois_ip_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return

