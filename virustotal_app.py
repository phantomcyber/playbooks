"""
This playbook runs all the VirusTotal actions one by one.
"""

import phantom.rules as phantom
import json
import time

def ip_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def url_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    # Add sleep here to _not_ hit the VT rate limit.
    time.sleep(1)
    phantom.act('ip reputation', parameters=[{ "ip" : "134.170.188.221"}], assets=["virustotal_private"], callback=ip_reputation_cb)

    return

def domain_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    # Add sleep here to _not_ hit the VT rate limit.
    time.sleep(1)
    phantom.act('url reputation', parameters=[{ "url" : "http://www.advancesrl.eu/tjjyeqyfjz/gmiuxfhgsb.html"}], assets=["virustotal_private"], callback=url_reputation_cb)

    return

def file_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    # Add sleep here to _not_ hit the VT rate limit. Not needed if VT Private API is used.
    time.sleep(1)
    phantom.act('domain reputation', parameters=[{ "domain" : "amazon.com"}], assets=["virustotal_private"], callback=domain_reputation_cb)

    return


def on_start(incident):

    phantom.act('file reputation', parameters=[{ "hash" : "7896b9b34bdbedbe7bdc6d446ecb09d5"}, {"hash": "99017f6eebbac24f351415dd410d522d"}], assets=["virustotal_private"], callback=file_reputation_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
