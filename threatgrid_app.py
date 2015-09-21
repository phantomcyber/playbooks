"""
This playbook runs threatgrid actions one by one.
"""

import phantom.rules as phantom
import re

internal_ip = r"^10.\d{1,3}.\d{1,3}.\d{1,3}$"


def detonate_url_cb(action, success, incident, results, handle):

    if not success:
        return

    return

def detonate_file_cb(action, success, incident, results, handle):
        
    if not success:
        return

    phantom.act('detonate url', parameters=[{ "url" : "www.phantomcyber.com" }], assets=["threatgrid"], callback=detonate_url_cb)

    return 
        
def get_process_file_cb(action, success, incident, results, handle):
    
    if not success:
        return

    phantom.debug(results)
                
    parameters = []
              
    result_items = phantom.parse_success(results)
                
    phantom.debug(result_items)
               
    phantom.debug(results)
                 
    for item in result_items:
        parameters.append({ "vault_id": item['vault_id'], 'file_name': item['name']})
        #vault_id = results[0]['action_results'][0]['data'][0]['vault_id']
    
    phantom.act('detonate file', parameters=parameters, assets=["threatgrid"], callback=detonate_file_cb)
    
    return
        

def on_start(incident):

    ip_hostnames = set(phantom.collect(incident, 'artifact:*.cef.sourceAddress', scope='all'))

    parameters = []

    for ip_hostname in ip_hostnames:
        if (re.match(internal_ip, ip_hostname)):
            phantom.debug("ip: {0} is internal, will be executing the action".format(ip_hostname))
            parameters.append({ "ip_hostname" : ip_hostname,  "name" : "infostealer*.exe" })

    if parameters:
        phantom.act('get process file', parameters=parameters, assets=["domainctrl1"], callback=get_process_file_cb)
    
    return

def on_finish(incident, summary):

    phantom.debug("Summary: " + summary)

    return
