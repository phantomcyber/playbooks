"""
This playbook runs all the Tanium actions one by one.
Last updated by Phantom Team: August 09, 2016
"""

import phantom.rules as phantom
import json


def list_questions_cb(action, success, incident, results, handle):
    if success:
        succ_results = phantom.get_successful_action_results_v2(results)
        results = succ_results[0]['data']
        for result in results:
            query = result['name']
            phantom.debug('query: {0}'.format(query))
            params=[{'query':query}]
            phantom.act('run query', parameters=params, assets=['tanium'], name="Query: {0}".format(query))

def reboot_system_cb(action, success, container, results, handle):
    if success:
        phantom.set_action_limit(300) 
        phantom.act('list questions', parameters=[{ }], assets=["tanium"], callback=list_questions_cb)

def terminate_process_cb(action, success, container, results, handle):
    if success:
        sourceAddress = set(phantom.collect(container, 'artifact:*.cef.sourceAddress'))
        parameters = []
        for ip_hostname in sourceAddress :
            parameters.append({
                "ip_hostname": ip_hostname,
            })
        phantom.act("reboot system", parameters=parameters, assets=["tanium"], callback=reboot_system_cb)

def on_start(container):
    sourceAddress = set(phantom.collect(container, 'artifact:*.cef.sourceHostName'))
    parameters = []
    for ip_hostname in sourceAddress :
        parameters.append({
            "ip_hostname": ip_hostname,
            "name": "notepad.exe",
        })

    phantom.act("terminate process", parameters=parameters, assets=["tanium"], callback=terminate_process_cb)

def on_finish(container, summary):
    """ finish """
