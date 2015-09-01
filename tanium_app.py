"""
This rule runs all the Tanium actions one by one.
"""

import phantom.rules as phantom
import json

def default_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def list_questions_cb(action, success, incident, results, handle):

    if not success:
        return

    succ_results = phantom.get_successful_action_results_v2(results)
    
    results = succ_results[0]['data']
    
    for result in results:
        
        query = result['name']
        phantom.debug('query: {0}'.format(query))
        params=[{'query':query}]
        phantom.act('run query', parameters=params, assets=['tanium'], callback=default_cb)
    
    return


def on_start(incident):

    phantom.set_action_limit(300) 
    phantom.act('list questions', parameters=[{ }], assets=["tanium"], callback=list_questions_cb)

    return

def on_finish(incident, summary):
    
    phantom.debug("Summary: " + summary)
    
    return
