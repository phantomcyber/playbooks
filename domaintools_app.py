"""
This playbook runs all the DomainTools app actions.
Last Updated on August 9, 2016
"""

import phantom.rules as phantom
import json


def on_start(container):

    parameters = []

    parameters.append({"domain": "phantomcyber.com",})

    phantom.act("whois domain", parameters=parameters, assets=["domaintools"])

    parameters = []

    parameters.append({"ip": "1.1.1.1",})

    phantom.act("whois ip", parameters=parameters, assets=["domaintools"])

    parameters = []

    parameters.append({"domain": "phantomcyber.com",})

    phantom.act("whois history", parameters=parameters, assets=["domaintools"])

    parameters = []

    parameters.append({"domain": "amazon.com",})

    phantom.act("reverse domain", parameters=parameters, assets=["domaintools"])

    parameters = []

    parameters.append({"ip": "172.217.2.36",})

    phantom.act("reverse ip", parameters=parameters, assets=["domaintools"])

    parameters = []

    parameters.append({"domain": "amazon.com",})

    phantom.act("hosting history", parameters=parameters, assets=["domaintools"])

    parameters = []

    parameters.append({
        "query": "google",
        "days_back": "",
        "status": "",
    })

    phantom.act("recent domains", parameters=parameters, assets=["domaintools"])

    return

def on_finish(container, summary):

    return
