import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

import traceback

def get_filtered_assets(action, excluded_products=None):
    
    supported_assets = phantom.get_assets(action=action)
    phantom.debug(supported_assets)
    ret_assets=[]
    
    if not supported_assets:
        return []
    
    if excluded_products:
        excluded_products = [x.lower() for x in excluded_products]
    
    for asset in supported_assets:
        if excluded_products:
            if asset['product_name'].lower() not in excluded_products:
                ret_assets.append(asset['name'])
        else:
            ret_assets.append(asset['name'])
    
    phantom.debug(ret_assets)
    return ret_assets

def asset_configured(action):
    assets = phantom.get_assets(action=action)
    if assets:
        return True
    
    return False

def escalate(container):
    phantom.set_severity(container, "high")
    
def deescalate(container):
    phantom.set_severity(container, "low")
    phantom.close(container)

    
def is_bad_domain(results):
    
    ODNS_KP = 'NORTH KOREA'
    DT_KP = 'kp'
    ATS_KP = 'North Korea'
    WHOIS_KP = 'KP'
    
    ret_data=[]
    
    try:
        #phantom.debug("domain investigation results: {}".format(results))

        collected = phantom.collect2(action_results=results, 
                                     datapath=["action",                                                #0
                                               "app",                                                   #1
                                               "status",                                                #2
                                               "action_result.summary.country",                         #3
                                               "action_result.data.*.registrantCountry",                #4
                                               "action_result.data.*.contacts.registrant.country",      #5
                                               "action_result.summary.country_code"])                   #6
        
        phantom.debug(collected)     
        
        for item in collected:
            
            ret_item = {}        

            if item[0] == "whois domain" and item[1] == "DomainTools" and item[2] == "success":
                if item[3]:
                    ret_item['bad']= item[3] == DT_KP
                    ret_data.append(ret_item) 
                    continue

            if item[0] == "whois domain" and item[1] == "OpenDNS Investigate" and item[2] == "success":
                if item[4]:
                    for country in item[4]:
                        if ret_item['bad']:  # checking if the value has been set yet
                            if ret_item['bad'] == False:  # Checking if the 'bad' bit has been already met.
                                ret_item['bad']= item[4] == ODNS_KP
                                ret_data.append(ret_item)
                                continue
                        else:
                            ret_item['bad']= item[4] == ODNS_KP
                            ret_data.append(ret_item)
                            continue

            if item[0] == "whois domain" and item[1] == "ThreatStream" and item[2] == "success":
                if item[5]:
                    for country in item[5]:
                        if ret_item['bad']:  # checking if the value has been set yet
                            if ret_item['bad'] == False:  # Checking if the 'bad' bit has been already met.
                                ret_item['bad']= item[5] == ATS_KP
                                ret_data.append(ret_item)
                                continue
                        else:
                            ret_item['bad']= item[5] == ATS_KP
                            ret_data.append(ret_item) 
                            continue

            if item[0] == "whois domain" and item[1] == "Whois" and item[2] == "success":
                if item[6]:
                    ret_item['bad']= item[6] == WHOIS_KP
                    ret_data.append(ret_item)
                    continue
        
        
    except:
        phantom.error("Exception ocurred in parsing results: {}".format(traceback.format_exc()))
        
    return ret_data        

def is_present(results):
    
    ret_data=[]
    
    try:
        #phantom.debug("ip investigation results: {}".format(results))
        
        collected = phantom.collect2(action_results=results, 
                                     datapath=["action",                                        #0
                                               "app",                                           #1
                                               "status",                                        #2
                                               "action_result.summary.total_devices",           #3 
                                               "action_result.data.*.process.total_results",    #4
                                               "action_result.summary.prevalence",              #5
                                               "action_result.summary.device_count"])           #6
                                               
        
        phantom.debug(collected)        

        for item in collected:
            ret_item = {}        
        
            if item[0] == "hunt file" and item[1] == "CylancePROTECT" and item[2] == "success":
                if item[3]:
                    ret_item['bad']= item[3] > 0
                    ret_data.append(ret_item)
                    continue    
                    
            if item[0] == "hunt file" and item[1] == "Carbon Black" and item[2] == "success":
                if item[4]:
                    for count in item[4]:
                        if ret_item['bad']:  # checking if the value has been set yet
                            if ret_item['bad'] == False:  # Checking if the threshold has been already met.
                                ret_item['bad']= count > 0
                                ret_data.append(ret_item)
                                continue
                        else:
                            ret_item['bad']= count > 0
                            ret_data.append(ret_item)
                            continue
                    
            if item[0] == "hunt file" and item[1] == "Carbon Black Protection" and item[2] == "success":
                if item[5]:
                    ret_item['bad']= item[5] > 0
                    ret_data.append(ret_item)
                    continue   
                    
            if item[0] == "hunt file" and item[1] == "Falcon Host API" and item[2] == "success":
                if item[6]:
                    ret_item['bad']= item[6] > 0
                    ret_data.append(ret_item)
                    continue                       
                    
            if item[0] == "hunt domain" and item[1] == "Falcon Host API" and item[2] == "success":
                if item[6]:
                    ret_item['bad']= item[6] > 0
                    ret_data.append(ret_item)
                    continue   
                    
    except:
        phantom.error("Exception ocurred in parsing results: {}".format(traceback.format_exc()))
        
    return ret_data     

def is_bad_ip(results):
    
    CAP_KP = 'KP'
    
    ret_data=[]
    
    try:
        #phantom.debug("ip investigation results: {}".format(results))
        
        collected = phantom.collect2(action_results=results, 
                                     datapath=["action",                                        #0
                                               "app",                                           #1
                                               "status",                                        #2
                                               "action_result.summary.country_code"])           #3
                                               
        
        phantom.debug(collected)        

        for item in collected:
            ret_item = {}        
        
            if item[0] == "whois ip" and item[1] == "Whois" and item[2] == "success":
                if item[3]:
                    ret_item['bad']= item[3] == CAP_KP
                    ret_data.append(ret_item)
                    continue        
                    
    except:
        phantom.error("Exception ocurred in parsing results: {}".format(traceback.format_exc()))
        
    return ret_data        

def is_positive_query(results):
    
    ret_data=[]
    
    try:
        #phantom.debug("query results: {}".format(results))
        
        collected = phantom.collect2(action_results=results, 
                                     datapath=["action",                                        #0
                                               "app",                                           #1
                                               "status"])                                       #2
        
        phantom.debug(collected)        
        
    except:
        phantom.error("Exception ocurred in parsing results: {}".format(traceback.format_exc()))
        
    return ret_data


# checks across all hash info providers if the hash is bad or not
def is_bad_file(results):
    
    BAD_THRESHOLD = 5
    THREATSCORE_THRESHOLD = 70
    
    ret_data=[]
    
    try:
        #phantom.debug("hash investigation results: {}".format(results))
        
        collected = phantom.collect2(action_results=results, 
                                     datapath=["action",                                                #0
                                               "app",                                                   #1
                                               "status",                                                #2
                                               "action_result.summary.positives",                       #3
                                               "action_result.parameter.hash",                          #4
                                               "action_result.parameter.context.artifact_id",           #5
                                               "action_result.summary.total_positives",                 #6 Malwr
                                               "action_result.data.*.threat.score",                     #7 Threat Grid
                                               "action_result.data.*.report.virustotal.positives",      #8 Cuckoo   
                                               "action_result.data.*.report.malicious_activity.*.type", #9 Lastline
                                               "action_result.summary.malware"])                        #10 WildFire

        
        phantom.debug(collected)
    
        for item in collected:
            ret_item = {}
            ret_item['hash'] = item[4]
            ret_item['artifact_id'] = item[5]

            if item[0] == "file reputation" and item[1] == "ReversingLabs" and item[2] == "success":
                if item[3] and item[4] and item[5]:
                    ret_item['bad']= item[3] > BAD_THRESHOLD
                    ret_data.append(ret_item)
                    continue
                    
            if item[0] == "file reputation" and item[1] == "VirusTotal" and item[2] == "success":
                if item[3] and item[4] and item[5]:
                    ret_item['bad']= item[3] > BAD_THRESHOLD
                    ret_data.append(ret_item)
                    continue

            if item[0] == "detonate file" and item[1] == "Malwr" and item[2] == "success":
                if item[6]:
                    ret_item['bad']= item[6] > BAD_THRESHOLD
                    ret_data.append(ret_item)
                    continue

            if item[0] == "detonate file" and item[1] == "Threat Grid" and item[2] == "success":
                if item[7]:
                    for threatscore in item[7]:
                        if ret_item['bad']: # checking if the value has been set yet
                            if ret_item['bad'] == False:  # Checking if the threatscore threshold has been already met.
                                ret_item['bad']= threatscore > THREATSCORE_THRESHOLD
                                ret_data.append(ret_item)
                                continue
                        else:
                            ret_item['bad']= threatscore > THREATSCORE_THRESHOLD
                            ret_data.append(ret_item)
                            continue

            if item[0] == "detonate file" and item[1] == "Cuckoo" and item[2] == "success":
                if item[8]:
                    for positives in item[8]:
                        if ret_item['bad']: # checking if the value has been set yet
                            if ret_item['bad'] == False:  # Checking if the threatscore threshold has been already met.
                                ret_item['bad']= positives > BAD_THRESHOLD
                                ret_data.append(ret_item)
                                continue
                        else:
                            ret_item['bad']= positives > BAD_THRESHOLD
                            ret_data.append(ret_item)
                            continue

            if item[0] == "detonate file" and item[1] == "Lastline" and item[2] == "success":
                if item[9]:
                    ret_item['bad']= item[9] > THREATSCORE_THRESHOLD
                    ret_data.append(ret_item)
                    continue                     
            
            if item[0] == "detonate file" and item[1] == "WildFire" and item[2] == "success":
                if item[10]:
                    ret_item['bad']= item[10] > THREATSCORE_THRESHOLD
                    ret_data.append(ret_item)
                    continue                
                    
    except:
        phantom.error("Exception ocurred in parsing results: {}".format(traceback.format_exc()))
        
    return ret_data

# End - Global Code block
##############################

def on_start(container):

    # call 'hunt_domain_1' block
    hunt_domain_1(container=container)
    
    # call 'hunt_file_1' block
    hunt_file_1(container=container)
    
    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    # call 'whois_domain_1' block
    whois_domain_1(container=container)

    # call 'run_query_1' block
    run_query_1(container=container)

    return

def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.summary.positives", ">=", 5],
            ["hunt_file_1:action_result.summary.prevalence", ">=", 1],
        ],
        logical_operator='and')

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_file_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

##- special functions for decision_1

def join_decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    # check if all connected incoming actions are done i.e. have succeeded or failed
    if phantom.actions_done([ 'file_reputation_1','hunt_file_1' ]):

        # call connected block "decision_1"
        decision_1(container=container, handle=handle)
    
    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    assets = get_filtered_assets("file reputation", excluded_products=["VirusTotal", "TitaniumCloud"])
    
    if not assets:
        return
    
    # collect data for 'file_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("file reputation", parameters=parameters, callback=join_decision_1, name="file_reputation_1", assets=assets)    
    
    return

def whois_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    assets = get_filtered_assets("whois domain", excluded_products=["Whois"])
    if not assets:
        return
    
    # collect data for 'whois_domain_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_domain_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    #assets = []          
            
    #assets = phantom.get_assets("whois domain")
    
    if parameters:
        phantom.act("whois domain", parameters=parameters, name="whois_domain_1", assets=assets)    
    
    return

def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    assets = get_filtered_assets("run query", excluded_products=["Exchange", "Windows Server", "Zendesk"])
    return

    if not assets:
        return
    
    container_data_src = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])
    container_data_dst = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'run_query_1' call
    
    assets = phantom.get_assets("run query")
    
    if parameters and assets:
        for asset in assets:
            if asset['product_name'] == "Splunk Enterprise":
                for container_item in container_data_src:
                    if container_item[0]:
                        parameters.append({
                            'query': container_item[0],
                            'display': "",
                            # context (artifact id) is added to associate results with the artifact
                            'context': {'artifact_id': container_item[1]},
                        })
            
                for container_item in container_data_dst:
                    if container_item[0]:
                        parameters.append({
                            'query': container_item[0],
                            'display': "",
                            # context (artifact id) is added to associate results with the artifact
                            'context': {'artifact_id': container_item[1]},
                        })
    
                phantom.act("run query", parameters=parameters, assets=[asset], name="run_query_1")
                continue
            elif asset['product_name'] == "Tanium":
                # define a TANIUM query here
                #phantom.act("run query", parameters=parameters, assets=[target_asset['name']], name="run_query_1")
                continue
            elif asset['product_name'] == "Carbon Black":
                # define a CarbonBlack query here
                #phantom.act("run query", parameters=parameters, assets=[target_asset['name']], name="run_query_1")
                continue
    
    return

def hunt_domain_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    assets = get_filtered_assets("hunt domain", excluded_products=["AutoFocus","ThreatScape"])
    
    if not assets:
        return
    
    # collect data for 'hunt_domain_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'hunt_domain_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                'count_only': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt domain", parameters=parameters, assets=assets, callback=decision_2, name="hunt_domain_1")    
        
    return

def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["hunt_domain_1:action_result.parameter.count_only", ">=", 1],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        get_device_info_1(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def get_device_info_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    assets = get_filtered_assets("get device info")
    
    if not assets:
        return

    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_device_info_1' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.deviceAddress', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'get_device_info_1' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'ip_hostname': filtered_container_item[0],
            })

    if parameters:
        phantom.act("get device info", parameters=parameters, assets=assets, name="get_device_info_1")    
    
    return

def get_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    assets = get_filtered_assets("get file")
    
    if not assets:
        return

    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_file_1' call
    inputs_data_1 = phantom.collect2(container=container, datapath=['hunt_file_1:artifact:*.cef.fileHash', 'hunt_file_1:artifact:*.id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_file_1' call
    for inputs_item_1 in inputs_data_1:
        if inputs_item_1[0]:
            parameters.append({
                'hash': inputs_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': inputs_item_1[1]},
            })

    if parameters:
        phantom.act("get file", parameters=parameters, assets=assets[0]['name'], callback=detonate_file_2, name="get_file_1")    
    
    return

def hunt_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    assets = get_filtered_assets("hunt file", excluded_products=["AutoFocus","ThreatScape", "CylancePROTECT"])
    if not assets:
        return
    
    # collect data for 'hunt_file_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    # build parameters list for 'hunt_file_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'hash': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("hunt file", parameters=parameters, assets=assets, callback=join_decision_1, name="hunt_file_1")    
        
    # Spec ial handling for Cylance since Cylance only uses SHA2 Hashes
    assets=[]
    cylance_parameters=[]
    cylance_assets = phantom.get_assets("hunt file")
    for asset in assets:
        if asset['product_name'].lower() == "CylancePROTECT".lower():
            
            assets=asset['name']
            
            for container_item in container_data:
                if container_item[0]:
                    if len(container_item[0]) == 64:
                        cylance_parameters.append({
                            'hash': container_item[0],
                            # context (artifact id) is added to associate results with the artifact
                            'context': {'artifact_id': container_item[1]},
                        })
            break
            
    if cylance_parameters:
        phantom.act("hunt file", parameters=parameters, assets=assets, callback=join_decision_1, name="hunt_file_1")    

    return

def detonate_file_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):
    
    assets = get_filtered_assets("detonate file")
    if not assets:
        return

    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'detonate_file_2' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_file_1:action_result.data.*.vault_id', 'get_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'detonate_file_2' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'file_name': "",
                'vault_id': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    if parameters:
        phantom.act("detonate file", parameters=parameters, assets=assets, name="detonate_file_2", parent_action=action)    
    
    return

def on_finish(container, summary):

    # This function is called after all actions are completed.
    # summary of all the action and/or all detals of actions 
    # can be collected here.

    ip_actions = []
    domain_actions = []
    file_actions = []
    hunt_actions = []
    query_actions = []
    
    # ip actions
    ip_actions.append('whois ip')
    
    #domain actions
    domain_actions.append('whois domain')
    
    #file actions
    file_actions.append('file reputation')
    file_actions.append('detonate file')
    
    #hunting actions
    hunt_actions.append('hunt file')
    hunt_actions.append('hunt domain')
    
    # query actions
    query_actions.append('run query')

    summary_json = phantom.get_summary()
    if 'result' in summary_json:

        for action_result in summary_json['result']:

            if 'action_run_id' in action_result:

                action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=True, flatten=False)
                if action_results:

                    if action_results[0]['action'] in ip_actions:
                        data = is_bad_ip(action_results)
                        for item in data:
                            if item['bad'] == True:
                                escalate(container)
                                return

                    if action_results[0]['action'] in domain_actions:
                        data = is_bad_domain(action_results)
                        for item in data:
                            if item['bad'] == True:
                                escalate(container)
                                return

                    if action_results[0]['action'] in file_actions:
                        data = is_bad_file(action_results)
                        for item in data:
                            if item['bad'] == True:
                                escalate(container)
                                return

                    if action_results[0]['action'] in hunt_actions:
                        data = is_present(action_results)
                        for item in data:
                            if item['bad'] == True:
                                escalate(container)
                                return   

                    if action_results[0]['action'] in query_actions:
                        data = is_positive_query(action_results)
                        for item in data:
                            if item['bad'] == True:
                                escalate(container)
                                return                                
    return