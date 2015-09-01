"""
This rule runs all the FireSIGHT actions one by one.
"""

import phantom.rules as phantom
import json


def get_signature_details_cb(action, success, incident, results, handle):

    if not success:
        return

    return


def on_start(incident):

    phantom.act('get signature details', parameters=[{ "snort_id" : "34944" }], assets=["firesight"], callback=get_signature_details_cb)

    return


def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
