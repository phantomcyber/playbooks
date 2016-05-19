"""
This playbook runs all urlvoid actions one by one.
Last updated by Phantom Team: May 19, 2016
"""
import phantom.rules as phantom
import json


def on_start(container):

    parameters = []

    parameters.append({"domain": "gumblar.cn",})

    phantom.act("domain reputation", parameters=parameters, assets=["urlvoid"])

    return

def on_finish(container, summary):

    return
