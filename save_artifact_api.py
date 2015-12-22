"""
This sample playbook shows the usage of phantom.save_artifact API.
"""
import phantom.rules as phantom
import json
import uuid

def on_start(incident):
    
    # note - re-running this playbook will not work as duplicate artifacts are not added resulting in an error
    cef = {}
    cef['sourceAddress'] = '1.1.1.1'
    
    artifact_id = phantom.save_artifact(incident, None, cef, 'netflow', 'test_event', 'high', str(uuid.uuid4()), 'network')
    
    phantom.debug('Artifact id: '+str(artifact_id))
    
    phantom.discontinue()

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return

