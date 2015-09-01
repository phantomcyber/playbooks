"""
This rule demonstrates the use of custom lists for use in formulating an action reponse rule. 
"""
import json
import phantom.rules as phantom

def on_start(incident):
    # Check if any of the attacked IPs are test machines
    #
    # api phantom.datastore_present returns a json dictionary with 2 fields
    # 1. 'present' indicating that the any of the items (attacked IPs) matched the entries in the list
    # 2. An array of rows of 'test_machines' list that matched the entries in the items (attacked IPs)
    # 
    phantom.debug("Starting the rule to test lists related APIs")

    test_machine_ips = phantom.datastore_get("test_machines")
    phantom.debug(test_machine_ips)

    result = phantom.datastore_present("test_machines", ['1.1.1.1'])
    phantom.debug(result)
    if result['present'] == True:
        phantom.debug("Found IP in lists")
    
        
    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  

