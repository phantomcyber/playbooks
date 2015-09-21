"""
This playbook runs all the smtp actions one by one.
"""

import phantom.rules as phantom
import json

def send_email_cb(action, success, incident, results, handle):

    if not success:
        return

    return


def on_start(incident):

    phantom.act('send email', parameters=[{ "body" : "This is a test mail, Executed from a playbook",  "to" : "notifications@phanom.us",  "subject" : "Test Email from playbook" }], assets=["smtp"], callback=send_email_cb)

    return

def on_finish(incident, summary):
    phantom.debug("Summary: " + summary)
    return
