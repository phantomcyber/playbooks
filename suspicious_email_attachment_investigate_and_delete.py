"""
Investigate an email with a suspicious file attachment detected by Splunk Enterprise Security. Detonate the file attachment in a sandbox, gather network behavior from the sandbox results, and pivot on those network indicators with both external reputation queries and internal Splunk Common Information Model searches. After confirming the results with an analyst prompt, delete the email from the user's inbox, hopefully before they have opened it.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import socket

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'get_email_1' block
    get_email_1(container=container)

    return

"""
Check the response from the prompt.
"""
def prompt_response_filter(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('prompt_response_filter() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["suspicious_email_attachment_prompt:action_result.summary.responses.0", "==", "Yes"],
        ],
        name="prompt_response_filter:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        delete_email_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_recipient_email(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Delete the suspicious email from the user's inbox.
"""
def delete_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('delete_email_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'delete_email_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_email_1:action_result.parameter.id', 'get_email_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'delete_email_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'id': results_item_1[0],
                'email': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="delete email", parameters=parameters, assets=['exchange'], name="delete_email_1")

    return

"""
Send an email to the analyst for this event notifying them that the playbook is running and the prompt is waiting for a response.
"""
def send_analyst_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_analyst_email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_analyst_email' call
    formatted_data_1 = phantom.get_format_data(name='format_analyst_message')

    parameters = []
    
    # build parameters list for 'send_analyst_email' call
    parameters.append({
        'cc': "",
        'to': "charlie@corp.contoso.com",
        'bcc': "",
        'body': formatted_data_1,
        'from': "charlie@corp.contoso.com",
        'headers': "",
        'subject': "Splunk detected suspicious email",
        'attachments': "",
    })

    phantom.act(action="send email", parameters=parameters, assets=['exchange_smtp'], name="send_analyst_email")

    return

"""
Detonate the file attachment in a sandbox to determine its behavior.
"""
def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('detonate_file_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    extract_attachment_info__vault_id = json.loads(phantom.get_run_data(key='extract_attachment_info:vault_id'))
    extract_attachment_info__attachment_file_name = json.loads(phantom.get_run_data(key='extract_attachment_info:attachment_file_name'))
    # collect data for 'detonate_file_1' call

    parameters = []
    
    # build parameters list for 'detonate_file_1' call
    parameters.append({
        'vault_id': extract_attachment_info__vault_id,
        'file_name': extract_attachment_info__attachment_file_name,
    })

    phantom.act(action="detonate file", parameters=parameters, assets=['cuckoo'], callback=detonate_file_1_callback, name="detonate_file_1")

    return

def detonate_file_1_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('detonate_file_1_callback() called')
    
    url_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    ip_reputation(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Build the body of an email to the recipient explaining that a suspicious email was deleted.
"""
def format_recipient_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_recipient_email() called')
    
    template = """The security department has detected a malicious phishing email sent to this email address from {0} with the subject \"{1}\". The email has been deleted. Please contact the security department if you have any questions."""

    # parameter list for template variable replacement
    parameters = [
        "get_email_1:action_result.data.*.t_From.t_Mailbox.t_EmailAddress",
        "get_email_1:action_result.data.*.t_Subject",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_recipient_email")

    send_recipient_email(container=container)

    return

"""
Send an email to the recipient explaining that a suspicious email was deleted.
"""
def send_recipient_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('send_recipient_email() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'send_recipient_email' call
    results_data_1 = phantom.collect2(container=container, datapath=['get_email_1:action_result.data.*.t_ToRecipients.t_Mailbox.*.t_EmailAddress', 'get_email_1:action_result.parameter.context.artifact_id'], action_results=results)
    formatted_data_1 = phantom.get_format_data(name='format_recipient_email')

    parameters = []
    
    # build parameters list for 'send_recipient_email' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'cc': "",
                'to': results_item_1[0],
                'bcc': "",
                'body': formatted_data_1,
                'from': "phantom",
                'headers': "",
                'subject': "Phishing Email Deleted",
                'attachments': "",
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="send email", parameters=parameters, assets=['exchange_smtp'], name="send_recipient_email")

    return

"""
Wait for an analyst to decide whether or not to delete the email from the user's inbox.
"""
def suspicious_email_attachment_prompt(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('suspicious_email_attachment_prompt() called')
    
    # set user and message variables for phantom.prompt call
    user = "Administrator"
    message = """Please review the investigation and decide whether or not to delete the email from the user's inbox."""

    #responses:
    response_types = [
        {
            "prompt": "",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No",
                ]
            },
        },
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="suspicious_email_attachment_prompt", response_types=response_types, callback=prompt_response_filter)

    return

"""
Gather all the key pieces of information collected so far and format them for an email to the analyst.
"""
def format_analyst_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_analyst_message() called')
    
    template = """A Splunk correlation search discovered a suspicious email file attachment:

email sender: {0}
email recipient: {1}
email subject: {2}

attachment file name: {3}
attachment SHA1 file hash: {4}
Cuckoo summary score of detonated email attachment: {5}

{6}

{7}

Hostnames of endpoints that have communicated with suspicious URLs:
{8}

Hostnames of endpoints that have communicated with suspicious IP addresses:
{9}

See the full context and respond to the analyst prompt within Phantom:
{10}"""

    # parameter list for template variable replacement
    parameters = [
        "get_email_1:action_result.data.*.t_Sender.t_Mailbox.t_EmailAddress",
        "get_email_1:action_result.data.*.t_ToRecipients.t_Mailbox.*.t_EmailAddress",
        "get_email_1:action_result.data.*.t_Subject",
        "detonate_file_1:action_result.parameter.file_name",
        "detonate_file_1:action_result.parameter.vault_id",
        "detonate_file_1:action_result.data.*.report.info.score",
        "format_url_reputation:formatted_data",
        "format_ip_reputation:formatted_data",
        "run_web_search:action_result.data.*.host",
        "run_dns_search:action_result.data.*.host",
        "container:url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_analyst_message")

    send_analyst_email(container=container)
    suspicious_email_attachment_prompt(container=container)

    return

def join_format_analyst_message(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('join_format_analyst_message() called')

    # check if all connected incoming playbooks, actions, or custom functions are done i.e. have succeeded or failed
    if phantom.completed(action_names=['run_dns_search', 'run_web_search', 'url_reputation', 'ip_reputation']):
        
        # call connected block "format_analyst_message"
        format_analyst_message(container=container, handle=handle)
    
    return

"""
Use the IMAP message ID from the Splunk Common Information Model to fetch the whole email including headers and attachments.
"""
def get_email_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('get_email_1() called')

    # collect data for 'get_email_1' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.message_id', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'get_email_1' call
    for container_item in container_data:
        parameters.append({
            'id': container_item[0],
            'email': "",
            'vault_id': "",
            'container_id': "",
            'ingest_email': True,
            'use_current_container': True,
            # context (artifact id) is added to associate results with the artifact
            'context': {'artifact_id': container_item[1]},
        })

    phantom.act(action="get email", parameters=parameters, assets=['exchange'], callback=extract_attachment_info, name="get_email_1")

    return

"""
Extract the vault ID and attachment filename to use in "detonate file" and other blocks.
"""
def extract_attachment_info(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('extract_attachment_info() called')
    
    id_value = container.get('id', None)

    extract_attachment_info__vault_id = None
    extract_attachment_info__attachment_file_name = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.vaultId', 'artifact:*.cef.fileName', 'artifact:*.id'], scope='all')
    for container_item in container_data:
        if container_item[0]:
            phantom.debug("found file with vaultId: {}".format(container_item[0]))
            extract_attachment_info__vault_id = container_item[0]
            extract_attachment_info__attachment_file_name = container_item[1]

    phantom.debug("detonating file with vaultId: {}".format(extract_attachment_info__vault_id))

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='extract_attachment_info:vault_id', value=json.dumps(extract_attachment_info__vault_id))
    phantom.save_run_data(key='extract_attachment_info:attachment_file_name', value=json.dumps(extract_attachment_info__attachment_file_name))
    detonate_file_1(container=container)

    return

"""
Check the reputation of URLs requested by the file attachment when it executed in the sandbox.
"""
def url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('url_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'url_reputation' call
    results_data_1 = phantom.collect2(container=container, datapath=['detonate_file_1:action_result.data.*.report.network.http.*.uri', 'detonate_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'url_reputation' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'url': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="url reputation", parameters=parameters, assets=['virustotal'], callback=url_reputation_callback, name="url_reputation", parent_action=action)

    return

def url_reputation_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None):
    phantom.debug('url_reputation_callback() called')
    
    filter_virustotal_positives(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)
    defang_url(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function)

    return

"""
Check the reputation of IP addresses contacted by the file attachment when it executed in the sandbox.
"""
def ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('ip_reputation() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'ip_reputation' call
    results_data_1 = phantom.collect2(container=container, datapath=['detonate_file_1:action_result.data.*.report.network.dns.*.answers.*.data', 'detonate_file_1:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'ip_reputation' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'ip': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="ip reputation", parameters=parameters, assets=['symantec_deepsight'], callback=filter_deepsight_behaviours, name="ip_reputation", parent_action=action)

    return

"""
Only process the IP addresses that matched malicious categories.
"""
def filter_deepsight_behaviours(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_deepsight_behaviours() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["Malware", "in", "ip_reputation:action_result.data.*.behaviours.*.behaviour"],
            ["Phish_Host", "in", "ip_reputation:action_result.data.*.behaviours.*.behaviour"],
        ],
        logical_operator='or',
        name="filter_deepsight_behaviours:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_dns_search(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_behaviors(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Build a Splunk search to check for other systems receiving DNS answers matching the suspicious IP addresses.
"""
def format_dns_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_dns_search() called')
    
    template = """%%
| datamodel Network_Resolution search | search DNS.answer=\"{0}\"
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_deepsight_behaviours:condition_1:ip_reputation:action_result.parameter.ip",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_dns_search")

    run_dns_search(container=container)

    return

"""
Only do further processing on URLs that exceed a threshold of positive threat detections.
"""
def filter_virustotal_positives(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_virustotal_positives() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["url_reputation:action_result.data.*.positives", ">", 3],
        ],
        name="filter_virustotal_positives:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_web_search(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Build a Splunk search to check for HTTP requests to the potentially malicious URLs.
"""
def format_web_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_web_search() called')
    
    template = """%%
| datamodel Web search | search Web.url=\"{0}\"
%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_virustotal_positives:condition_1:url_reputation:action_result.parameter.url",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_web_search")

    run_web_search(container=container)

    return

"""
Run a Splunk search to check for HTTP requests to the potentially malicious URLs.
"""
def run_web_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_web_search() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_web_search' call
    formatted_data_1 = phantom.get_format_data(name='format_web_search__as_list')

    parameters = []
    
    # build parameters list for 'run_web_search' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "",
            'display': "",
            'parse_only': "",
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_format_analyst_message, name="run_web_search")

    return

"""
Run a Splunk search to check for other systems receiving DNS answers matching the suspicious IP addresses.
"""
def run_dns_search(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_dns_search() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_dns_search' call
    formatted_data_1 = phantom.get_format_data(name='format_dns_search__as_list')

    parameters = []
    
    # build parameters list for 'run_dns_search' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "",
            'display': "",
            'parse_only': "",
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=join_format_analyst_message, name="run_dns_search")

    return

"""
Gather the key results from the URL reputation  query into a formatted text block.
"""
def format_url_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_url_reputation() called')
    
    template = """VirusTotal scores of URLs detected in file detonation:

%%
URL: {0}
VirusTotal Analysis Permalink: {1}
Score: {2}
%%"""

    # parameter list for template variable replacement
    parameters = [
        "defang_url:custom_function:defanged_url",
        "url_reputation:action_result.data.*.permalink",
        "url_reputation:action_result.message",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_url_reputation")

    join_format_analyst_message(container=container)

    return

"""
Gather together the key fields from the results of the IP reputation query for any suspicious IP addresses.
"""
def format_ip_reputation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ip_reputation() called')
    
    template = """Symantec DeepSight analysis of IP addresses detected in file detonation:

%%
IP: {0}
Behaviors:
{1}

%%"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_deepsight_behaviours:condition_1:ip_reputation:action_result.data.*.ip",
        "format_behaviors:custom_function:behaviors",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ip_reputation")

    join_format_analyst_message(container=container)

    return

"""
Defang the URLs by substituting hXXp fot http and [.] for . to prevent notifications from showing the actual clickable URL (which could be malicious).
"""
def defang_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('defang_url() called')
    
    results_data_1 = phantom.collect2(container=container, datapath=['url_reputation:action_result.parameter.url'], action_results=results)
    results_item_1_0 = [item[0] for item in results_data_1]

    defang_url__defanged_url = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    defang_url__defanged_url = []
    
    phantom.debug("defanging URLs:")
    for url in results_item_1_0:
        defanged_url = url.replace("http", "hXXp").replace(".", "[.]")
        phantom.debug("defanged {} into {}".format(url, defanged_url))
        defang_url__defanged_url.append(defanged_url)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='defang_url:defanged_url', value=json.dumps(defang_url__defanged_url))
    format_url_reputation(container=container)

    return

"""
Collect and format the behavioral information from Deepsight relating to the queried IP addresses.
"""
def format_behaviors(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_behaviors() called')
    
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_deepsight_behaviours:condition_1:ip_reputation:action_result.data.*.behaviours'])
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    format_behaviors__behaviors = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    format_behaviors__behaviors = []
    for ip in filtered_results_item_1_0:
        behavior = ""
        lines = json.dumps(ip, indent=4).split('\n')
        for line in lines:
            # only use the lines with keys and values, not the json {} and [] characters
            if 1 not in [c in line for c in '{}[]']:
                behavior += line + '\n'
        format_behaviors__behaviors.append(behavior)
    
    phantom.debug('Symantec Deepsight behaviors:')
    phantom.debug(format_behaviors__behaviors)

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='format_behaviors:behaviors', value=json.dumps(format_behaviors__behaviors))
    format_ip_reputation(container=container)

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