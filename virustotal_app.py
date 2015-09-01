"""
This rule runs all the VirusTotal actions one by one.
"""

import phantom.rules as phantom
import json

def ip_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def url_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('ip reputation', parameters=[{ "ip" : "134.170.188.221, 10.10.0.206" }], assets=["virustotal_private"], callback=ip_reputation_cb)

    return

def domain_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('url reputation', parameters=[{ "url" : "www.advancesrl.eu/tjjyeqyfjz/gmiuxfhgsb.html, www.howaboutthatrightnownotpresent.com" }], assets=["virustotal_private"], callback=url_reputation_cb)

    return

def file_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('domain reputation', parameters=[{ "domain" : "amazon.com, google.com" }], assets=["virustotal_private"], callback=domain_reputation_cb)

    return


def on_start(incident):

    phantom.act('file reputation', parameters=[{ "hash" : "7896b9b34bdbedbe7bdc6d446ecb09d5, 99017f6eebbac24f351415dd410d522d, ce0296e2d77ec3bb112e270fc260f274, 3828f4f998aefe0282e4c9cd642ac110dd3745d6" }], assets=["virustotal_private"], callback=file_reputation_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: "+summary)

    return  

