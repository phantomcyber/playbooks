"""This playbook executes the wepawet actions one by one."""

import phantom.rules as phantom
import json


def on_start(container):

    parameters = []

    parameters.append({
        "vault_id": "014B3BD178A68F3FB7F7D79E6EA7015EE8B3D0E4 ",
        "file_name": "funny_beach.swf",
    })

    phantom.act("detonate file", parameters=parameters, assets=["wepawet"])

    parameters = []

    parameters.append({"url": "http://www.google.com",})

    phantom.act("detonate url", parameters=parameters, assets=["wepawet"])

    return

def on_finish(container, summary):

    return
