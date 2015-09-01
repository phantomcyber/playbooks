"""
This sample rule shows calling a playbook from a playbook
Incident id: 2a76c74c-5713-11e4-8a26-9b99986c1e2a
"""
import json
import phantom.rules as phantom

def on_start(incident):
    # lets do VT lookup of file hashes in the artifacts of an incident

    phantom.playbook('basic_playbook', incident)

    return


def generic_cb(action_name, status, incident, results, handle):
    phantom.debug('Action '+action_name+ (' SUCCEEDED' if status else ' FAILED'))
    return


def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  
