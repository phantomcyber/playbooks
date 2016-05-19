"""
This playbook runs all the maxmind actions one by one.
Last updated by Phantom Team: May 19, 2016
"""

import phantom.rules as phantom
import json

def geolocate_ip_cb(action, success, incident, results, handle):

    if not success:
        return

    return


def on_start(incident):

    phantom.act('geolocate ip', parameters=[{"ip": "192.94.73.9"}, {"ip": "1.1.1.1"}, {"ip": "74.125.239.105"}, {"ip": "10.10.0.0"}], assets=["maxmind"], callback=geolocate_ip_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
