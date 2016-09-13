import phantom.rules as phantom
import json
from datetime import datetime, timedelta

##############################
# Start - Global Code Block

"""
The investigative Playbook queries a number of external reputation and intelligence services in order to enrich events coming from your data source.  By selecting this Playbook you will be guided through the configuration of a number of common IP, file, domain, and URL reputation services next.
"""
#################
# It is important to NOTE that the following are examples of determining the malicious nature of the 
# content and results. The examples below demonstrate how to navigate the results returned from action
# execution runs and serve as guidelines.  It is encouraged that the analyst study the data types 
# returned from the action execution and determine which fields and thresholds should be used to determine
# malicious activity for your environment.
#################
def is_bad_ip(results):  

    for result in results:
        
        # check for action: reverse ip
        if result['action']=='reverse ip':
            
            if result['app']=='DomainTools':
                for action_result in result['action_results']:
                    # NOTE that this type of investigation alone may not be enough to conclude that an IP is bad. 
                    # The list of domains associated with the IP can be used to launch other investigations or 
                    # compare against a list of known malicious domains. 
                    #
                    # The following line of code will just demonstrate interacting with the return data
                    total_domains=action_result['summary'].get('total_domains')
                    if total_domains!=None and total_domains>500:
                        phantom.debug(action_result['summary']['total_domains'])
                        
        # check for action: whois ip
        if result['action']=='whois ip': 
            
            if result['app']=='WHOIS':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # Checking if the country code is equal to North Korea
                            asn_country_code=data.get('asn_country_code')
                            if asn_country_code!=None and asn_country_code=='KP':
                                return True
            
            if result['app']=='DomainTools':
                for result in results:
                    for action_result in result['action_results']:
                        if action_result.get('data')!=None:                        
                            for data in action_result['data']:
                                if data['parsed_whois'].get('contacts')!=None:
                                    for contact in data['parsed_whois']['contacts']:
                                        # Checking if the country code is equal to North Korea
                                        country=contact.get('country')
                                        if country!=None and country=='kp':
                                            return True
                                
        # check for action: reputation
        if result['action']=='ip reputation':
            
            if result['app']=='OpenDNS Investigate':
                for action_result in result['action_results']:
                    # If reputation comes back malicious, then we know this is a bad IP
                    ip_status=action_result['summary'].get('ip_status')
                    if ip_status!=None and ip_status=='MALICIOUS':
                        return True
                    
            if result['app']=='VirusTotal':
                for action_result in result['action_results']:
                    # If reputation comes back with more than 10 detected malicious URLs,  then we know this is a bad IP
                    detected_urls=action_result['summary'].get('detected_urls')
                    if detected_urls!=None and detected_urls>10:
                        return True
                
            # if result['app']=='ThreatStream':
                # Not much information available in ThreatStream app that allows one to conclude whether an IP 
                # is malicious.
                
            if result['app']=='PassiveTotal':
                for action_result in result['action_results']:
                    # Check if reputation service is watching the IP
                    being_watched=action_result['summary'].get('being_watched')
                    if being_watched!=None and being_watched==True:
                        return True
                
        # check for action: geolocate ip        
        if result['action']=='geolocate ip':

            if result['app']=='MaxMind':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:                    
                        for data in action_result['data']:
                            # Checking if the country code is equal to North Korea
                            country_iso_code=data.get('country_iso_code')
                            if country_iso_code!=None and country_iso_code=='KP':
                                return True
                        
    return False

def is_bad_user(results):
    
    for result in results:
        
        # check for action: reverse ip
        if result['action']=='get user attributes':
            
            if result['app']=='LDAP':
                # As an example, will use the failed password count to determine if the user is bad
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:                                       
                        for data in action_result['data']:
                            # Checking if bad password count has exceeded 20
                            badpwdcount=data.get('badpwdcount')
                            if badpwdcount!=None and int(data['badpwdcount'])>20:
                                return True
                        
    return False

def is_bad_domain(results):

    for result in results:
        
        # check for action: domain reputation
        if result['action']=='domain reputation':
            
            if result['app']=='OpenDNS Investigate':
                for action_result in result['action_results']:
                    # Check against the domain status for MALICIOUS from OpenDNS Investigate
                    domain_status=action_result['summary'].get('domain_status')
                    if domain_status!=None and domain_status=='MALICIOUS':
                        return True
                
            if result['app']=='VirusTotal':
                for action_result in result['action_results']:
                    # If reputation comes back with more than 10 detected malicious URLs,  then we know this is a bad Domain
                    detected_urls=action_result['summary'].get('detected_urls')
                    if detected_urls!=None and detected_urls>10:
                        return True       

            if result['app']=='ThreatStream':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If threat_type is malware or c2, then we know this is a bad domain
                            threat_type=data.get('threat_type')
                            if (threat_type!=None) and ((threat_type=='malware') or (threat_type=='c2')):
                                return True

            if result['app']=='PassiveTotal':
                for action_result in result['action_results']:
                    # Check if reputation service is watching the Domain
                    being_watched=action_result['summary'].get('being_watched')
                    if being_watched!=None and being_watched==True:                    
                        return True                     
                
            if result['app']=='URLVoid':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If the detections count is greater than 0, then we know this is a bad domain
                            count=data['response']['detections'].get('count')
                            if count!=None and int(count)>0:
                                return True

        # check for action: lookup domain                
        if result['action']=='lookup domain':
            
            if result['app']=='DNS':
                for action_result in result['action_results']:
                    # NOTE that this type of investigation alone may not be enough to conclude that a Domain is bad. 
                    # The list of IPs associated with the Domain can be used to launch other investigations or 
                    # compare against a list of known malicious IPs. 
                    #
                    # The following line of code will just demonstrate interacting with the return data
                    total_ips=action_result['summary'].get('total_ips')
                    if total_ips!=None and total_ips>10:
                        phantom.debug(total_ips)

        # check for action: whois domain
        if result['action']=='whois domain':
            
            if result['app']=='OpenDNS Investigate':
                for action_result in result['action_results']:
                    # If domain is in North Korea, the domain is bad
                    country=action_result['summary'].get('country')
                    if country!=None and country=='NORTH KOREA':
                        return True
                
            if result['app']=='ThreatStream':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If the domain is registered to North Kore, the domain is bad
                            country=data['contacts']['registrant'].get('country')
                            if country!=None and country=='North Korea':
                                return True
                
            if result['app']=='WHOIS':
                for action_result in result['action_results']:
                    # If the domain is registered to North Kore, the domain is bad
                    country=action_result['summary'].get('country')
                    if country!=None and country=='KP':
                        return True
                
            # if result['app']=='DomainTools':
                # Not much information available in ThreatStream app that allows one to conclude whether a Domain
                # is malicious.   
                
        # check for action: reverse domain
        if result['action']=='reverse domain':
            phantom.debug('')
            # if result['app']=='DomainTools':
                # Not much information available in ThreatStream app that allows one to conclude whether a Domain
                # is malicious.                   
                
    return False

def is_bad_file(results):

    for result in results:
        
        # check for action: file reputation
        if result['action']=='file reputation':
            
            if result['app']=='ReversingLabs':
                for action_result in result['action_results']:
                    # If number of positives triggered is greater than 5, then the file is bad
                    positives=action_result['summary'].get('positives')
                    if positives!=None and positives>5:
                        return True
                
            if result['app']=='VirusTotal':
                for action_result in result['action_results']:
                    # If number of positives triggered is greater than 5, then the file is bad
                    positives=action_result['summary'].get('positives')
                    if positives!=None and positives>5:                    
                        return True
                
            # if result['app']=='ThreatStream':
                # Not much information available in ThreatStream app that allows one to conclude whether an IP 
                # is malicious.  

        # check for action: file reputation
        if result['action']=='detonate file':
            
            if result['app']=='Cyphort':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If the Malware Category is Virus, then the file is bad
                            # NOTE that this is an example of interpreting the results.  Other result data
                            # and values should be analyzed. 
                            malware_category=data['analysis_details']['analysis_details'].get('malware_category')
                            if malware_category!=None and malware_category=='Virus': 
                                return True
                
            if result['app']=='Cuckoo':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If virustotal positives is greater than 5, then the file is bad
                            positives=data['report']['virustotal'].get('positives')
                            if positives!=None and positives>5:
                                return True
                
            #if result['app']=='Malwr':
                # Malwr seems to not be working
                
            if result['app']=='Threat Grid':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If the threat score is > 70, then the file is bad
                            score=data['threat'].get('score')
                            if score!=None and score>70:
                                return True
                
            if result['app']=='Lastline':
                for action_result in result['action_results']:
                    # If the score is > 70, then the file is bad
                    score=action_result['summary'].get('score')
                    if score!=None and score>70:
                        return True
                
            # if result['app']=='WildFire':
                # Wildire to be determined when API key is restored. 
    
    return False

def is_bad_url(results):

    for result in results:
        
        # check for action: detonate url
        if result['action']=='detonate url':
            
            if result['app']=='Cuckoo':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If virustotal positives is greater than 5, then the URL is bad
                            positives=data['report']['virustotal'].get('positives')
                            if positives!=None and positives>5:
                                return True  

            if result['app']=='Threat Grid':
                for action_result in result['action_results']:
                    if action_result.get('data')!=None:
                        for data in action_result['data']:
                            # If the threat score is > 70, then the URL is bad
                            score=data['threat'].get('score')
                            if score!=None and score>70:
                                return True

            if result['app']=='Lastline':
                for action_result in result['action_results']:
                    # If the summary score is > 70, then the URL is bad
                    score=action_result['summary'].data('score')
                    if score!=None and score>70:
                        return True
                
            # if result['app']=='urlQuery':
                # urlQuery having SSL handshake problems 

        # check for action: url reputation
        if result['action']=='url reputation':
            
            if result['app']=='VirusTotal':
                for action_result in result['action_results']:
                    # If number of positives triggered is greater than 5, then the URL is bad
                    positives=action_result['summary'].get('positives')
                    if positives!=None and positives>5:
                        return True

    return False

# End - Global Code block
##############################

def on_start(container):
    
    # call 'reverse_src_ip' block
    reverse_src_ip(container=container)

    # call 'whois_src_ip' block
    whois_src_ip(container=container)

    # call 'ip_src_reputation' block
    ip_src_reputation(container=container)

    # call 'geolocate_src_ip' block
    geolocate_src_ip(container=container)

    # call 'geolocate_dst_ip' block
    geolocate_dst_ip(container=container)

    # call 'ip_dst_reputation' block
    ip_dst_reputation(container=container)

    # call 'reverse_dst_ip' block
    reverse_dst_ip(container=container)

    # call 'whois_dst_ip' block
    whois_dst_ip(container=container)

    # call 'file_reputation_1' block
    file_reputation_1(container=container)

    # call 'url_reputation_1' block
    url_reputation_1(container=container)

    # call 'detonate_url_1' block
    detonate_url_1(container=container)

    # call 'get_dst_user_attr' block
    get_dst_user_attr(container=container)

    # call 'get_src_user_attr_2' block
    get_src_user_attr_2(container=container)

    # call 'get_src_user_attr' block
    get_src_user_attr(container=container)

    # call 'get_dst_user_attr_2' block
    get_dst_user_attr_2(container=container)

    # call 'lookup_src_Domain' block
    lookup_src_Domain(container=container)

    # call 'lookup_dst_Domain' block
    lookup_dst_Domain(container=container)

    # call 'whois_dst_Domain' block
    whois_dst_Domain(container=container)

    # call 'reverse_dst_Domain' block
    reverse_dst_Domain(container=container)

    # call 'domain_dst_Reputation' block
    domain_dst_Reputation(container=container)

    # call 'whois_src_Domain' block
    whois_src_Domain(container=container)

    # call 'reverse_src_Domain' block
    reverse_src_Domain(container=container)

    # call 'domain_src_Reputation' block
    domain_src_Reputation(container=container)

    return

def reverse_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'reverse_src_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'reverse_src_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("reverse ip", parameters=parameters, callback=decision_24, name="reverse_src_ip")    
    
    return

def whois_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'whois_src_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_src_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("whois ip", parameters=parameters, callback=decision_23, name="whois_src_ip")    
    
    return

def ip_src_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'ip_src_reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_src_reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("ip reputation", parameters=parameters, callback=decision_22, name="ip_src_reputation")    
    
    return

def geolocate_src_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'geolocate_src_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_src_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("geolocate ip", parameters=parameters, callback=decision_21, name="geolocate_src_ip")    
    
    return

def get_src_user_attr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'get_src_user_attr' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_src_user_attr' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'username': container_item[0],
                'fields': "",
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("get user attributes", parameters=parameters, callback=decision_5, name="get_src_user_attr")    
    
    return

def get_dst_user_attr_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'get_dst_user_attr_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_dst_user_attr_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'username': container_item[0],
                'fields': "",
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("get user attributes", parameters=parameters, callback=decision_19, name="get_dst_user_attr_2")    
    
    return

def decision_24(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")
    
    return

def reverse_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'reverse_dst_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'reverse_dst_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("reverse ip", parameters=parameters, callback=decision_14, name="reverse_dst_ip")    
    
    return

def decision_14(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")        

    return

def detonate_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'detonate_url_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'detonate_url_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("detonate url", parameters=parameters, callback=decision_7, name="detonate_url_1")    
    
    return

def url_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'url_reputation_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation_1' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("url reputation", parameters=parameters, callback=decision_8, name="url_reputation_1")    
    
    return

def get_src_user_attr_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'get_src_user_attr_2' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceUserId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_src_user_attr_2' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'username': container_item[0],
                'fields': "",
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("get user attributes", parameters=parameters, callback=decision_6, name="get_src_user_attr_2")    
    
    return

def decision_10(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def reverse_dst_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'reverse_dst_Domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'reverse_dst_Domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("reverse domain", parameters=parameters, callback=decision_13, name="reverse_dst_Domain")    
    
    return

def decision_11(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def lookup_src_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'lookup_src_Domain' call
    filtered_container_data = phantom.collect2(container=container, datapath=['filtered-artifact:*.cef.sourceDnsDomain', 'filtered-artifact:*.id'], filter_artifacts=filtered_artifacts)

    parameters = []
    
    # build parameters list for 'lookup_src_Domain' call
    for filtered_container_item in filtered_container_data:
        if filtered_container_item[0]:
            parameters.append({
                'domain': filtered_container_item[0],
                'type': "",
            })

    if parameters:
        phantom.act("lookup domain", parameters=parameters, callback=decision_26, name="lookup_src_Domain")    
    
    return

def decision_27(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def whois_src_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'whois_src_Domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_src_Domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("whois domain", parameters=parameters, assets=['domaintools'], callback=decision_27, name="whois_src_Domain")    
    
    return

def decision_29(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def decision_13(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def reverse_src_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'reverse_src_Domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'reverse_src_Domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("reverse domain", parameters=parameters, callback=decision_29, name="reverse_src_Domain")    
    
    return

def decision_9(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_file(results):
        phantom.debug("Bad File - Take Action")        

    return

def decision_8(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_url(results):
        phantom.debug("Bad URL - Take Action")        

    return

def decision_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_url(results):
        phantom.debug("Bad URL - Take Action")        

    return

def decision_26(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def whois_dst_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'whois_dst_Domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_dst_Domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("whois domain", parameters=parameters, callback=decision_11, name="whois_dst_Domain")    
    
    return

def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

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
        phantom.act("file reputation", parameters=parameters, callback=decision_9, name="file_reputation_1")    
    
    return

def domain_dst_Reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'domain_dst_Reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_dst_Reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("domain reputation", parameters=parameters, callback=decision_25, name="domain_dst_Reputation")    
    
    return

def decision_20(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def domain_src_Reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'domain_src_Reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_src_Reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("domain reputation", parameters=parameters, callback=decision_20, name="domain_src_Reputation")    
    
    return

def lookup_dst_Domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'lookup_dst_Domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'lookup_dst_Domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                'type': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("lookup domain", parameters=parameters, callback=decision_10, name="lookup_dst_Domain")    
    
    return

def decision_25(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_domain(results):
        phantom.debug("Bad Domain - Take Action")        

    return

def decision_19(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_user(results):
        phantom.debug("Bad User - Take Action")        

    return

def decision_6(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_user(results):
        phantom.debug("Bad User - Take Action")        

    return

def decision_5(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_user(results):
        phantom.debug("Bad User - Take Action")        

    return

def decision_18(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_user(results):
        phantom.debug("Bad User - Take Action")        

    return

def geolocate_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'geolocate_dst_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'geolocate_dst_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("geolocate ip", parameters=parameters, callback=decision_17, name="geolocate_dst_ip")    
    
    return

def decision_21(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")        

    return

def decision_22(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")        

    return

def ip_dst_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'ip_dst_reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'ip_dst_reputation' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("ip reputation", parameters=parameters, callback=decision_16, name="ip_dst_reputation")    
    
    return

def decision_16(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")        

    return

def decision_15(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")        

    return

def whois_dst_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'whois_dst_ip' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationAddress', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_dst_ip' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'ip': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("whois ip", parameters=parameters, callback=decision_15, name="whois_dst_ip")    
    
    return

def decision_23(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")
        
    return

def get_dst_user_attr(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    # collect data for 'get_dst_user_attr' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.destinationUserName', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_dst_user_attr' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'username': container_item[0],
                'fields': "",
                'attribute': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    if parameters:
        phantom.act("get user attributes", parameters=parameters, callback=decision_18, name="get_dst_user_attr")    
    
    return

def decision_17(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None):

    if is_bad_ip(results):
        phantom.debug("Bad IP - Take Action")        

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
