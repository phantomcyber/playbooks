"""
This sample rule shows the usage of phantom.save_artifact API.
"""
import phantom.rules as phantom
import json
import uuid

def on_start(incident):
    
    cef = {}
    cef['sourceAddress'] = '1.1.1.1'
    
    artifact_id = phantom.save_artifact(incident, None, cef, 'netflow', 'test_event', 'high', str(uuid.uuid4()), 'network')
    
    phantom.debug('Artifact id: '+artifact_id)
    
    phantom.discontinue()

    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return

