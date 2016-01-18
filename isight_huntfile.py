"""
This playbook collects the file hashes in an artifact and executes 'hunting' action on an asset, to detect the presence of the file
in an enterprise.
"""

import phantom.rules as phantom
import json

def hunt_file_cb(action, success, campaign, results, handle):

    if not success:
        return

    return


def on_start(campaign):

    md5s = set(phantom.collect(campaign, 'artifact:*.cef.fileHash'))

    parameters = []

    for md5 in md5s:
        parameters.append({ "hash" : md5 })

    if parameters:
        phantom.act('hunt file', parameters=parameters, assets=["carbonblack"], callback=hunt_file_cb)

    return

def on_finish(campaign, summary):

    phantom.debug("Summary: " + summary)

    return

