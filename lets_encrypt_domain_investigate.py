"""
Investigate domain names and URLs of a potentially malicious website. These domain names and URLs could come from anywhere, but this Playbook was designed to work with the Splunk Analytic Story called "Common Phishing Frameworks", which focuses on evilginx2 phishing techniques that harvest credentials from fake login sites. The full investigation is only completed if at least one of the TLS certificates of the domains matches the issuer distinguished name of Let's Encrypt, which is a free service that provides automatically issued TLS certificates. This Playbook gathers certificate information for the domains, queries whois for the domains, takes a screenshot of each of the URLs, and does a urlscan.io scan of each of the URLs. Finally, all the results are formatted together and posted to the event comments.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'format_censys_query' block
    format_censys_query(container=container)

    return

"""
Show a comment but don't continue the playbook if the certificate issuer's distinguished name does not match Let's Encrypt
"""
def not_lets_encrypt_cert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('not_lets_encrypt_cert() called')

    phantom.comment(container=container, comment="Not all of the censys.io results matched the issuer distinguished name of a Let's Encrypt certificate, so no further processing will be done")

    return

"""
Prevent the playbook from continuing if more than 50 results were found in Censys to avoid cluttering the investigation. Refine the Censys query if this happens too often.
"""
def too_many_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('too_many_results() called')

    phantom.comment(container=container, comment="More than 50 results were returned by censys.io, so the playbook will not proceed and the results need to be investigated manually")

    return

"""
Query the Censys certificate dataset for a list of TLS certificates used on the domains that are being investigated
"""
def censys_query_certificate(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('censys_query_certificate() called')

    # collect data for 'censys_query_certificate' call
    formatted_data_1 = phantom.get_format_data(name='format_censys_query__as_list')

    parameters = []
    
    # build parameters list for 'censys_query_certificate' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
        })

    phantom.act(action="query certificate", parameters=parameters, assets=['censys'], callback=match_against_lets_encrypt_issuer_dn, name="censys_query_certificate")

    return

"""
Check whether the results show the Let's Encrypt distinguished name as the issuer and how many results there are. Continue with the playbook if there are less than 50 results and they all match Let's Encrypt, otherwise add a comment explaining what happened and stop the playbook.
"""
def match_against_lets_encrypt_issuer_dn(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('match_against_lets_encrypt_issuer_dn() called')

    # check for 'if' condition 1
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["censys_query_certificate:action_result.data.*.parsed_issuer_dn", "==", "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3"],
            ["censys_query_certificate:action_result.summary.result_count", "<=", 50],
        ],
        logical_operator='and')

    # call connected blocks if condition 1 matched
    if matched:
        get_screenshot_of_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        scan_url_with_urlscanio(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        whois_domain(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # check for 'elif' condition 2
    matched = phantom.decision(
        container=container,
        action_results=results,
        conditions=[
            ["censys_query_certificate:action_result.data.*.parsed_issuer_dn", "==", "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3"],
            ["censys_query_certificate:action_result.summary.result_count", ">", 50],
        ],
        logical_operator='and')

    # call connected blocks if condition 2 matched
    if matched:
        too_many_results(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
        return

    # call connected blocks for 'else' condition 3
    not_lets_encrypt_cert(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Format the Censys SSL certificate query and Passivetotal whois results associated with the initial requested domains
"""
def format_associated_data(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_associated_data() called')
    
    template = """Censys SSL Cert Information:
Issuer DNs:{0}
Domains:{1}

PassiveTotal Whois Information:
Domain Organizations Registered: {2}
Domain Countries Registered:{3}"""

    # parameter list for template variable replacement
    parameters = [
        "censys_query_certificate:action_result.data.*.parsed_issuer_dn",
        "censys_query_certificate:action_result.data.*.parsed_subject_dn",
        "whois_domain:action_result.summary.organization",
        "whois_domain:action_result.summary.country",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_associated_data")

    display_results(container=container)

    return

"""
Display the formatted Censys and PassiveTotal results in the event comments
"""
def display_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('display_results() called')

    formatted_data_1 = phantom.get_format_data(name='format_associated_data')

    phantom.comment(container=container, comment=formatted_data_1)

    return

"""
Use Screenshot Machine to obtain a screenshot of the URLs in the container
"""
def get_screenshot_of_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_screenshot_of_url() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'get_screenshot_of_url' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_screenshot_of_url' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                'size': "Normal",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="get screenshot", parameters=parameters, assets=['screenshot machine'], name="get_screenshot_of_url")

    return

"""
Use urlscan.io to profile the behavior of the website identified by the URLs in the container
"""
def scan_url_with_urlscanio(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('scan_url_with_urlscanio() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'scan_url_with_urlscanio' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'scan_url_with_urlscanio' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'url': container_item[0],
                'private': True,
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="detonate url", parameters=parameters, assets=['urlscan'], name="scan_url_with_urlscanio")

    return

"""
Use PassiveTotal to collect registration information about the domains
"""
def whois_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('whois_domain() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'whois_domain' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.query', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'whois_domain' call
    for container_item in container_data:
        if container_item[0]:
            parameters.append({
                'domain': container_item[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': container_item[1]},
            })

    phantom.act(action="whois domain", parameters=parameters, assets=['passivetotal'], callback=format_associated_data, name="whois_domain")

    return

"""
Wrap the domain names in quotes so that the Censys query only returns exact matches
"""
def format_censys_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_censys_query() called')
    
    template = """%%
\"{0}\"
%%"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.query",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_censys_query")

    censys_query_certificate(container=container)

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