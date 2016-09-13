import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

"""
The hunting Playbook queries a number of internal security technologies in order to determine if any of the artifacts present in your data source have been observed in your environment.  By selecting this Playbook you will be guided through the configuration of a number of common endpoint technologies next.
"""
#################
# It is important to NOTE that the following are examples of determining the presence and risk of the 
# content and results. The examples below demonstrate how to navigate the results returned from action
# execution runs and serve as guidelines.  It is encouraged that the analyst study the data types 
# returned from the action execution and determine which fields and thresholds should be used to determine
# malicious activity for your environment.
#################
def ip_is_suspicious(results):  

    for result in results:
        
        # check for action: whois ip
        if result['action']=='hunt ip': 
            
            if result['app']=='AutoFocus':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            count=data.get('count')
                            if count!=None and count>5:
                                return True

            if result['app']=='iSight Partners':
                for action_result in result['action_results']:
                    # iSight Partners errors at the moment
                    phantom.debug('')                     
                        
    return False

def domain_is_suspicious(results):

    for result in results:
        
        # check for action: domain reputation
        if result['action']=='hunt domain':
            
            if result['app']=='AutoFocus':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:                    
                        for data in action_result['data']:
                            count=data.get('count')
                            if count!=None and count>5:                            
                                return True

            if result['app']=='iSight Partners':
                for action_result in result['action_results']:
                    # iSight Partners errors at the moment
                    phantom.debug('')    
    return False

def file_is_suspicious(results):

    for result in results:
        
        # check for action: file reputation
        if result['action']=='hunt file':
            
            if result['app']=='Carbon Black Protection (Bit9)':
                for action_result in result['action_results']:
                    # If the prevelence value is greater than 5, then report its presence
                    prevalence=action_result['summary'].get('prevalence')
                    if prevalence!=None and prevalence>5:
                        return True

            if result['app']=='Cylance':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for l1_data in action_result['data']:
                            if l1_data.get('data')!=None:
                                for l2_data in l1_data['data']:
                                    exploit_attempts=l2_data.get('exploit_attempts')
                                    if exploit_attempts!=None and exploit_attempts>1:
                                        return True
                            
            if result['app']=='AutoFocus':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:                    
                        for data in action_result['data']:
                            count=data.get('count')
                            if count!=None and count>5:
                                return True                  
                    
            if result['app']=='Carbon Black Response':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:                                        
                        for data in action_result['data']:
                            if data['binary'].get('results')!=None:
                                for bin_result in data['binary']['results']:
                                    host_count=bin_result.get('host_count')
                                    if host_count!=None and host_count>5:
                                        return True
                            
            if result['app']=='iSight Partners':
                for action_result in result['action_results']:
                    # iSight Partners errors at the moment
                    phantom.debug('')   
                    
    return False

def url_is_suspicious(results):

    for result in results:
        
        # check for action: detonate url
        if result['action']=='hunt url':
            
            if result['app']=='AutoFocus':
                for action_result in result['action_results']:
                    if action_result.get('data'):
                        for data in action_result['data']:
                            count=data.get('count')
                            if count!=None and count>5:
                                return True
                        
            if result['app']=='iSight Partners':
                for action_result in result['action_results']:
                    # iSight Partners errors at the moment
                    phantom.debug('')     
                        
    return False

# End - Global Code block
##############################

def on_start(container):
    
    # call 'hunt_source_ip' block
    hunt_source_ip(container=container)

    # call 'hunt_dest_ip' block
    hunt_dest_ip(container=container)

    # call 'hunt_file_1' block
    hunt_file_1(container=container)

    # call 'hunt_url_1' block
    hunt_url_1(container=container)

    # call 'hunt_dest_domain' block
    hunt_dest_domain(container=container)

    # call 'hunt_source_domain' block
    hunt_source_domain(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    if ip_is_suspicious(results):
        phantom.debug("IP Presence - Take Action")        

    return

def hunt_source_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'hunt_source_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_source_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'scope': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt ip", parameters=parameters, callback=decision_1, name="hunt_source_ip")    
    
    return

def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'hunt_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_file_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'scope': "",
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt file", parameters=parameters, callback=decision_3, name="hunt_file_1")    
    
    return

def hunt_dest_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'hunt_dest_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_dest_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                'scope': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt ip", parameters=parameters, callback=decision_2, name="hunt_dest_ip")    
    
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if ip_is_suspicious(results):
        phantom.debug("IP Presence - Take Action")        

    return

def decision_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if file_is_suspicious(results):
        phantom.debug("File Presence - Take Action")        

    return

def decision_4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if url_is_suspicious(results):
        phantom.debug("URL Presence - Take Action")        

    return

def hunt_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'hunt_url_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_url_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                'scope': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt url", parameters=parameters, callback=decision_4, name="hunt_url_1")    
    
    return

def hunt_dest_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'hunt_dest_domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_dest_domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'scope': "",
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt domain", parameters=parameters, callback=decision_5, name="hunt_dest_domain")    
    
    return

def hunt_source_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'hunt_source_domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_source_domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'scope': "",
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt domain", parameters=parameters, callback=decision_6, name="hunt_source_domain")    
    
    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if domain_is_suspicious(results):
        phantom.debug("Domain Presence - Take Action")        
        
    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if domain_is_suspicious(results):
        phantom.debug("Domain Presence - Take Action")        

    return

def on_finish(container, summary):

    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return
