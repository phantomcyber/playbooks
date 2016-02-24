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

    phantom.act('send email', parameters=[{ "body" : "This is a test mail, Executed from a playbook",  "to" : "notifications@phantom.us",  "subject" : "Test Email from playbook" }], assets=["smtp"], callback=send_email_cb)
    html_body = '<html>'
    html_body += 'This is a test mail,<br>'
    html_body += 'Executed from a playbook for '
    html_body += '<a href="{base_url}/container/{container_id}"><b>this container</b></a>.<br>'.format(base_url=phantom.get_base_url(), container_id=incident['id'])
    html_body += '</html>'
    
    phantom.act('send email', parameters=[{ "body" : html_body,  "to" : "notifications@phantom.us",  "subject" : "Test HTML Email from playbook" }], assets=["smtp"], callback=send_email_cb)


    return

def on_finish(incident, summary):
    phantom.debug("Summary: " + summary)
    return
