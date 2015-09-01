"""
This rule runs all the ReversingLabs actions one by one.
"""

import phantom.rules as phantom
import json

def file_reputation_cb(action, success, incident, results, handle):

    if not success:
        return

    return


def on_start(incident):

    phantom.act('file reputation', parameters=[{ "hash" : "7896B9B34BDBEDBE7BDC6D446ECB09D5" }], assets=["reversinglabs_private"], callback=file_reputation_cb)

    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  

