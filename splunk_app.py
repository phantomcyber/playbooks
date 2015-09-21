"""
This playbook runs all the splunk actions one by one.
"""

import phantom.rules as phantom
import json

def run_query_cb(action, success, incident, results, handle):

    if not success:
        return
    
    phantom.debug(results)

    return

def get_host_events_cb(action, success, incident, results, handle):

    if not success:
        return

    phantom.act('run query', parameters=[{ "query" : "sourcetype=DhcpSrvLog | regex _raw=\"^(10|11|12),\" | head 10"}], assets=["splunk_entr"], callback=run_query_cb)

    return


def on_start(incident):

    ip_hostnames = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress', scope='all'))

    parameters = []

    for ip_hostname in ip_hostnames:
        parameters.append({ "last_n_days" : "2",  "ip_hostname" : ip_hostname })

    phantom.act('get host events', parameters=parameters, assets=["splunk_entr"], callback=get_host_events_cb)

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
