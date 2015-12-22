"""
This playbook demonstrates the use of custom lists for use in formulating an action reponse playbook. 
"""
import json
import phantom.rules as phantom

def on_start(incident):

    phantom.debug("Starting the rule to test lists related APIs")

    # Basic example to get a list, which has been defined in the custom_lists of Automation section
    test_machine_ips = phantom.datastore_get("test_machines")
    phantom.debug(test_machine_ips)


    # Example to check the presence of an item in the list
    result = phantom.datastore_present("test_machines", ['1.1.1.1'])
    phantom.debug(result)
    if len(result) > 0:
        phantom.debug("Found IP in list: test_machines")
    
    # Example to add items to a existing list
    phantom.datastore_add('test_machines', '9.9.9.9')
    test_machine_ips = phantom.datastore_get('test_machines')
    phantom.debug(test_machine_ips)

    result = phantom.datastore_present("test_machines", '9.9.9.9')
    phantom.debug(result)
    if len(result) > 0:
        phantom.debug("Found IP in list: test_machines"+json.dumps(result))

    result = phantom.datastore_present("test_machines", ['9.9.9.9','1.1.1.1'])
    phantom.debug(result)
    if len(result) > 0:
        phantom.debug("Found IP in list: test_machines"+json.dumps(result))

        
    # Example to delete an item from the list
    phantom.datastore_delete('test_machines', '9.9.9.9')
    test_machine_ips = phantom.datastore_get('test_machines')
    phantom.debug(test_machine_ips)
    
    return

def on_finish(incident, summary):
    phantom.debug("Summary: "+summary)
    return  

