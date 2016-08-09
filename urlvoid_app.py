"""
This Playbook executes all urlvoid actions
Last Updated on August 9, 2016
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
