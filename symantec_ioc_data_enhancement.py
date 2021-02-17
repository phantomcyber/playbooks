"""
This Playbook detonates a file in Symantec Content Analysis and enriches the indicators in the generated report with queries to a variety of external data sources. The results of those queries are then synthesized into a condensed view that is added to a ServiceNow Incident.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'filter_1' block
    filter_1(container=container)

    return

"""
Use the file hash of the submitted file to query VirusTotal for existing detections in a wide array of sandbox engines.
"""
def virustotal_file_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('virustotal_file_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'virustotal_file_reputation' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report:action_result.summary.vault_id', 'get_report:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'virustotal_file_reputation' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=virustotal_file_format, name="virustotal_file_reputation", parent_action=action)

    return

"""
Format the VirusTotal results for a summary to add to the ticket.
"""
def virustotal_file_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('virustotal_file_format() called')
    
    template = """Positives: {0}
Total Scans: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "virustotal_file_reputation:action_result.summary.positives",
        "virustotal_file_reputation:action_result.summary.total_scans",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="virustotal_file_format")

    join_synthesize_enrichment(container=container)

    return

"""
Format the ReversingLabs results for a summary to add to the ticket.
"""
def reversinglabs_file_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reversinglabs_file_format() called')
    
    template = """Positives: {0}
Total Scans: {1}"""

    # parameter list for template variable replacement
    parameters = [
        "reversinglabs_file_rep:action_result.summary.positives",
        "reversinglabs_file_rep:action_result.summary.total_scans",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="reversinglabs_file_format")

    join_synthesize_enrichment(container=container)

    return

"""
Format the OpenDNS results for a summary to add to the ticket.
"""
def opendns_domain_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('opendns_domain_format() called')
    
    domain_parameters = phantom.collect2(container=container, datapath=['domain_reputation_1:action_result.parameter.domain'], action_results=results)
    domain_statuses = phantom.collect2(container=container, datapath=['domain_reputation_1:action_result.summary.domain_status'], action_results=results)

    template = ""
    for index, domain in enumerate(domain_parameters):
        template += "Domain: {0}\nReputation: {1}\n\n".format(domain[0], domain_statuses[index][0])

    # parameter list for template variable replacement
    parameters = []

    phantom.format(container=container, template=template, parameters=parameters, name="opendns_domain_format")

    join_synthesize_enrichment(container=container)

    return

"""
Pull together the results of all the enrichment into one text block formatted to be added to ServiceNow as Work Notes.
"""
def synthesize_enrichment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('synthesize_enrichment() called')
    
    template = """All of the information below and further contextual actions are available in Phantom at {0}

---Initial File Virustotal Reputation---
{1}

---Initial File ReversingLabs Reputation---
{2}

---Symantec Deepsight Reputation of Detected C2 URL's---
{3}

---Google Safe Browsing Reputation of Detected  C2 URL's---
{4}

---Alexa Popularity Ranking of Detected Contacted URL's---
{5}

---OpenDNS Reputation of Detected Contacted Domains---
{6}

---ThreatStream Reputation of Detected Contacted IP Addresses---
{7}"""

    # parameter list for template variable replacement
    parameters = [
        "container:url",
        "virustotal_file_format:formatted_data",
        "reversinglabs_file_format:formatted_data",
        "deepsight_url_format:formatted_data",
        "google_url_format:formatted_data",
        "alexa_url_format:formatted_data",
        "opendns_domain_format:formatted_data",
        "threatstream_ip_format:formatted_data",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="synthesize_enrichment")

    create_servicenow_ticket(container=container)

    return

def join_synthesize_enrichment(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_synthesize_enrichment() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['lookup_url_1', 'virustotal_file_reputation', 'reversinglabs_file_rep', 'google_url_reputation', 'domain_reputation_1', 'ip_reputation', 'deepsight_url_reputation']):
        
        # call connected block "synthesize_enrichment"
        synthesize_enrichment(container=container, handle=handle)
    
    return

"""
Format the Alexa results for a summary to add to the ticket.
"""
def alexa_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('alexa_url_format() called')
    
    url_parameters = phantom.collect2(container=container, datapath=['lookup_url_1:action_result.parameter.url'], action_results=results)
    ranks = phantom.collect2(container=container, datapath=['lookup_url_1:action_result.summary.rank'], action_results=results)

    template = ""
    for index, url in enumerate(url_parameters):
        template += "URL: {0}\nRank: {1}\n\n".format(url[0], ranks[index][0])

    # parameter list for template variable replacement
    parameters = []

    phantom.format(container=container, template=template, parameters=parameters, name="alexa_url_format")

    join_synthesize_enrichment(container=container)

    return

"""
Format the Google Safe Browsing results for a summary to add to the ticket.
"""
def google_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('google_url_format() called')
    
    url_parameters = phantom.collect2(container=container, datapath=['google_url_reputation:action_result.parameter.url'], action_results=results)
    threat_types = phantom.collect2(container=container, datapath=['google_url_reputation:action_result.data.*.matches.*.threatType'], action_results=results)

    template = ""
    for index, url in enumerate(url_parameters):
        template += "URL: {0}\nThreat Type: {1}\n\n".format(url[0], threat_types[index][0])

    # parameter list for template variable replacement
    parameters = []

    phantom.format(container=container, template=template, parameters=parameters, name="google_url_format")

    join_synthesize_enrichment(container=container)

    return

"""
Format the DeepSight results for a summary to add to the ticket.
"""
def deepsight_url_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deepsight_url_format() called')

    url_parameters = phantom.collect2(container=container, datapath=['deepsight_url_reputation:action_result.parameter.url'], action_results=results)
    is_whitelisted = phantom.collect2(container=container, datapath=['deepsight_url_reputation:action_result.data.*.whitelisted'], action_results=results)
    behaviors = phantom.collect2(container=container, datapath=['deepsight_url_reputation:action_result.data.*.behaviours.*.description'], action_results=results)

    template = ""
    for index, url in enumerate(url_parameters):
        template += "URL: {0}\nWhitelisted: {1}\nBehavior: {2}\n\n".format(url[0], is_whitelisted[index][0], behaviors[index][0])

    phantom.format(container=container, template=template, parameters=[], name="deepsight_url_format")

    join_synthesize_enrichment(container=container)

    return

"""
Retrieve the full report from Symantec Content Analysis once detonation is complete.
"""
def get_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_report() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_report' call
    results_data_1 = phantom.collect2(container=container, datapath=['content_analysis_detonate:action_result.summary.task_id', 'content_analysis_detonate:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'get_report' call
    for results_item_1 in results_data_1:
        parameters.append({
            'task_id': results_item_1[0],
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': results_item_1[1]},
        })

    phantom.act(action="get report", parameters=parameters, assets=['mas'], callback=get_report_callback, name="get_report", parent_action=action)

    return

def get_report_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('get_report_callback() called')
    
    reversinglabs_file_rep(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    lookup_url_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    domain_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    ip_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    virustotal_file_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    google_url_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    deepsight_url_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Verify that there is a file in the Vault to detonate.
"""
def filter_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_1() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.vaultId", "!=", ""],
        ],
        name="filter_1:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        content_analysis_detonate(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Create a ticket in ServiceNow with the Work Notes displaying the enriched results collected in this playbook.
"""
def create_servicenow_ticket(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('create_servicenow_ticket() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'create_servicenow_ticket' call
    formatted_data_1 = json.dumps({"work_notes": phantom.get_format_data(name='synthesize_enrichment')})

    parameters = []
    
    # build parameters list for 'create_servicenow_ticket' call
    parameters.append({
        'short_description': "Phantom-enriched Symantec Content Analysis detonation results",
        'table': "incident",
        'vault_id': "",
        'description': "",
        'fields': formatted_data_1,
    })

    phantom.act("create ticket", parameters=parameters, assets=['servicenow'], name="create_servicenow_ticket")

    return

"""
Detonate the file in Symantec Content Analysis using the default IntelliVM environment to produce a full report of the process activity, filesystem changes, network connections, registry changes, and other system activity when the file is executed.
"""
def content_analysis_detonate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('content_analysis_detonate() called')

    # collect data for 'content_analysis_detonate' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'content_analysis_detonate' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'vault_id': container_item[0],
                'environment': "IntelliVM",
                'profile': "",
                'priority': "high",
                'source': "Phantom",
                'label': "",
                'description': "",
                'owner': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="detonate file", parameters=parameters, assets=['mas'], callback=get_report, name="content_analysis_detonate")

    return

"""
Query the Google Safe Browsing API to determine if the URL detected by Symantec Content Analysis is known to be malicious.
"""
def google_url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('google_url_reputation() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'google_url_reputation' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report:action_result.data.*.results.NET.*.NET_Url.url', 'get_report:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'google_url_reputation' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and 'http' in results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("url reputation", parameters=parameters, assets=['safe browsing'], callback=google_url_format, name="google_url_reputation", parent_action=action)

    return

"""
Query the reputation of the SHA1 file hash using ReversingLabs.
"""
def reversinglabs_file_rep(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('reversinglabs_file_rep() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'reversinglabs_file_rep' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report:action_result.summary.vault_id', 'get_report:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'reversinglabs_file_rep' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['reversinglabs'], callback=reversinglabs_file_format, name="reversinglabs_file_rep", parent_action=action)

    return

"""
Query Symantec DeepSight for threat intelligence related to the URL's requested during the file detonation.
"""
def deepsight_url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('deepsight_url_reputation() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'deepsight_url_reputation' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report:action_result.data.*.results.NET.*.NET_Url.url', 'get_report:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'deepsight_url_reputation' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and 'http' in results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("url reputation", parameters=parameters, assets=['deepsight'], callback=deepsight_url_format, name="deepsight_url_reputation", parent_action=action)

    return

"""
Query alexa.com for the traffic rank of the domain underlying each of the URL's requested during the file detonation. Domains without much traffic may be less legitimate.
"""
def lookup_url_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('lookup_url_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'lookup_url_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report:action_result.data.*.results.NET.*.NET_Url.url', 'get_report:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'lookup_url_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and 'http' in results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("lookup url", parameters=parameters, assets=['alexa'], callback=alexa_url_format, name="lookup_url_1", parent_action=action)

    return

"""
Query OpenDNS Investigate for intelligence about the domains that were resolved during file detonation.
"""
def domain_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('domain_reputation_1() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'domain_reputation_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report:action_result.data.*.results.NET.*.NET_Url.host', 'get_report:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'domain_reputation_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and not phantom.valid_ip(results_item_1[0]):
            parameters.append({
                'domain': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("domain reputation", parameters=parameters, assets=['opendns_investigate'], callback=opendns_domain_format, name="domain_reputation_1", parent_action=action)

    return

"""
Query Anomali ThreatStream for intelligence related to any IP addresses that were connected to during file detonation.
"""
def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation() called')
    
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_report:action_result.data.*.results.NET.*.NET_Url.host', 'get_report:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation' call
    for results_item_1 in results_data_1:
        if results_item_1[0] and phantom.valid_ip(results_item_1[0]):
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act("ip reputation", parameters=parameters, assets=['threatstream'], callback=threatstream_ip_format, name="ip_reputation", parent_action=action)

    return

"""
Format the ThreatStream results for a summary to add to the ticket.
"""
def threatstream_ip_format(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('threatstream_ip_format() called')

    ip_parameters = phantom.collect2(container=container, datapath=['ip_reputation:action_result.parameter.ip'], action_results=results)
    threat_scores = phantom.collect2(container=container, datapath=['ip_reputation:action_result.data.*.threatscore'], action_results=results)
    confidences = phantom.collect2(container=container, datapath=['ip_reputation:action_result.data.*.confidence'], action_results=results)
    threat_types = phantom.collect2(container=container, datapath=['ip_reputation:action_result.data.*.itype'], action_results=results)

    template = ""
    for index, ip_address in enumerate(ip_parameters):
        template += "IP Address: {0}\nThreat Score: {1}\nThreat Type: {2}\nConfidence: {3}\n\n".format(ip_address[0], threat_scores[index][0], threat_types[index][0], confidences[index][0])

    # parameter list for template variable replacement
    parameters = []

    phantom.format(container=container, template=template, parameters=parameters, name="threatstream_ip_format")
    join_synthesize_enrichment(container=container)

    return

def on_finish(container, summary):
    phantom.debug('on_finish() called')
    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    return