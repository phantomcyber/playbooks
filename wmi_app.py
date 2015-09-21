"""
This playbook runs all the wmi actions one by one.
"""
import phantom.rules as phantom
import json

def run_query_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def list_users_cb(action, success, incident, results, handle):

    if not success:
        return

    ip_hostnames = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress'))

    parameters = []

    for ip_hostname in ip_hostnames:
        parameters.append({ "query" : "select SessionId from Win32_Process Where Name = 'notepad.exe'",  "ip_hostname" : ip_hostname })

    phantom.act('run query', parameters=parameters, assets=["domainctrl1"], callback=run_query_cb)

    return

def get_system_info_cb(action, success, incident, results, handle):

    if not success:
        return

    ip_hostnames = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress'))

    parameters = []

    for ip_hostname in ip_hostnames:
        parameters.append({ "ip_hostname" : ip_hostname })

    phantom.act('list users', parameters=parameters, assets=["domainctrl1"], callback=list_users_cb)

    return

def list_services_cb(action, success, incident, results, handle):

    if not success:
        return

    ip_hostnames = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress'))

    parameters = []

    for ip_hostname in ip_hostnames:
        parameters.append({ "ip_hostname" : ip_hostname })

    phantom.act('get system info', parameters=parameters, assets=["domainctrl1"], callback=get_system_info_cb)

    return


def on_start(incident):

    ip_hostnames = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress'))

    parameters = []

    for ip_hostname in ip_hostnames:
        parameters.append({ "ip_hostname" : ip_hostname })

    phantom.act('list services', parameters=parameters, assets=["domainctrl1"], callback=list_services_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return

