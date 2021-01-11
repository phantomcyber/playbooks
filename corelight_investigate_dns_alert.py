"""
This playbook automates an analyst investigation when reviewing a Suricata event for a potentially malicious DNS query. Splunk queries are used to gather related information from Zeek metadata, and a VirusTotal query checks the reputation of any files that are extracted from the network stream by Corelight.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import re
import time
# For filter 10: If you want to error check further for false positives, you can use the DNS UID to look at sourcetype=corelight_conn and see if resp_bytes=0. This speculates that a device inline has blocked the query and can be check against.

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'timestamp_to_epoch' block
    timestamp_to_epoch(container=container)

    return

"""
Build a Splunk query to find the DNS log with the UID matching the Phantom event, which was triggered by a Suricata signature for a blocklisted DNS name.
"""
def format_DNS_alert_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_DNS_alert_query() called')
    
    template = """index=corelight sourcetype=corelight_dns {0} earliest={1} latest=now() | table uid answer id.orig_h"""

    # parameter list for template variable replacement
    parameters = [
        "artifact:*.cef.uid",
        "timestamp_to_epoch:custom_function_result.data.epoch_time",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_DNS_alert_query")

    run_DNS_alert_query(container=container)

    return

"""
Run the Splunk query built in the previous block.
"""
def run_DNS_alert_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_DNS_alert_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_DNS_alert_query' call
    formatted_data_1 = phantom.get_format_data(name='format_DNS_alert_query')

    parameters = []
    
    # build parameters list for 'run_DNS_alert_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=filter_DNS_answer, name="run_DNS_alert_query")

    return

"""
Run the Splunk query built in the previous block.
"""
def run_source_dest_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_source_dest_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    IP_regex_and_format_source_dest_query__query = json.loads(phantom.get_run_data(key='IP_regex_and_format_source_dest_query:query'))
    # collect data for 'run_source_dest_query' call

    parameters = []
    
    # build parameters list for 'run_source_dest_query' call
    parameters.append({
        'query': IP_regex_and_format_source_dest_query__query,
        'command': "search",
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=If_traffic_between_the_two_units, name="run_source_dest_query")

    return

"""
If any Splunk results showed traffic between the source and destination hosts, continue the investigation.
"""
def If_traffic_between_the_two_units(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('If_traffic_between_the_two_units() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["run_source_dest_query:action_result.data.*.count", "!=", 0],
            ["run_source_dest_query:action_result.data.*.count", "!=", ""],
        ],
        logical_operator='and',
        name="If_traffic_between_the_two_units:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_DNS_alert(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_connection_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Loop through each matching DNS alert from the previous Splunk query,  validate IPv4 and IPv6 addresses, and format another Splunk query to check for matching connection log entries between the same originating host and  the host in the DNS answer.
"""
def IP_regex_and_format_source_dest_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('IP_regex_and_format_source_dest_query() called')
    
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.id_orig_h', 'artifact:*.id'])
    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_DNS_answer:condition_1:run_DNS_alert_query:action_result.data.*.answer'])
    container_item_0 = [item[0] for item in container_data]
    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    IP_regex_and_format_source_dest_query__query = None
    IP_regex_and_format_source_dest_query__id_resp_h = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here..
    #phantom.debug(container_item_0)
    #This query loops through the Corelight Answers and checks if a valid IP4/IP6 address
    # it then creates a query to check if there was a conn log entry between the two IP address.
    id_orig_h = str(container_item_0[0])
    query_base = "index=corelight id.orig_h = " + id_orig_h + " AND id.resp_h = "
    IPregex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
    
    for results_item_1 in filtered_results_data_1:
        if results_item_1[0]:
            for item in results_item_1:
                id_resp_h = str(item)
                phantom.debug(id_resp_h)
                if (re.search(IPregex, id_resp_h)):
                    query = query_base + id_resp_h + " | stats count(id.orig_h) as count by id.resp_h uid"
                    phantom.debug(query)
                    IP_regex_and_format_source_dest_query__id_resp_h = id_resp_h
                    #phantom.debug(id_resp_h)
                    phantom.save_run_data(key='IP_regex_and_format_source_dest_query:query', value=json.dumps(query))
                    phantom.save_run_data(key='IP_regex_and_format_source_dest_query:id_resp_h', value=json.dumps(IP_regex_and_format_source_dest_query__id_resp_h))
                    run_source_dest_query(container=container)

    return

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key='IP_regex_and_format_source_dest_query:query', value=json.dumps(IP_regex_and_format_source_dest_query__query))
    phantom.save_run_data(key='IP_regex_and_format_source_dest_query:id_resp_h', value=json.dumps(IP_regex_and_format_source_dest_query__id_resp_h))
    run_source_dest_query(container=container)

    return

"""
Run the Splunk query built in the previous block.
"""
def query_connections(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('query_connections() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'query_connections' call
    formatted_data_1 = phantom.get_format_data(name='format_connection_query__as_list')

    parameters = []
    
    # build parameters list for 'query_connections' call
    for formatted_part_1 in formatted_data_1:
        parameters.append({
            'query': formatted_part_1,
            'command': "search",
            'display': "",
            'parse_only': False,
        })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=filter_nonzero_bytes, name="query_connections")

    return

"""
Filter out connections with zero bytes sent or received.
"""
def filter_nonzero_bytes(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_nonzero_bytes() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["query_connections:action_result.data.*.orig_bytes", "!=", 0],
            ["query_connections:action_result.data.*.resp_bytes", "!=", 0],
        ],
        logical_operator='or',
        name="filter_nonzero_bytes:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        filter_3(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_suricata_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        format_file_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Filter between plaintext HTTP and SSL/TLS.
"""
def filter_3(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_3() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_nonzero_bytes:condition_1:query_connections:action_result.data.*.service", "==", "http"],
        ],
        name="filter_3:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_HTTP_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    # collect filtered artifact ids for 'if' condition 2
    matched_artifacts_2, matched_results_2 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["filtered-data:filter_nonzero_bytes:condition_1:query_connections:action_result.data.*.service", "==", "ssl"],
        ],
        name="filter_3:condition_2")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_2 or matched_results_2:
        format_SSL_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_2, filtered_results=matched_results_2)

    return

"""
Format a detailed query to collect plaintext HTTP indicators to present to analysts.
"""
def format_HTTP_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_HTTP_query() called')
    
    template = """index=corelight sourcetype=corelight_http {0} | table ts uid host uri method referrer user_agent"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_1:query_connections:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_HTTP_query")

    run_HTTP_query(container=container)

    return

"""
Run the Splunk query built in the previous block.
"""
def run_HTTP_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_HTTP_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_HTTP_query' call
    formatted_data_1 = phantom.get_format_data(name='format_HTTP_query')

    parameters = []
    
    # build parameters list for 'run_HTTP_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=format_http_note, name="run_HTTP_query")

    return

"""
Format a query for Suricata alerts generated on the connection resulting from the malicious DNS lookup (by way of the linked UID).
"""
def format_suricata_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_suricata_query() called')
    
    template = """index=corelight sourcetype=corelight_suricata_corelight {0} | table uid alert.signature alert.signature_id alert.rev alert.category alert.severity alert.metadata metadata id.orig_h id.orig_p id.resp_h id.resp_p ts"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_nonzero_bytes:condition_1:query_connections:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_suricata_query")

    run_suricata_query(container=container)

    return

"""
Run the Splunk query built in the previous block.
"""
def run_suricata_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_suricata_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_suricata_query' call
    formatted_data_1 = phantom.get_format_data(name='format_suricata_query')

    parameters = []
    
    # build parameters list for 'run_suricata_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=filter_valid_suricata_alerts, name="run_suricata_query")

    return

"""
Format a detailed query to collect SSL/TLS indicators to present to analysts.
"""
def format_SSL_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_SSL_query() called')
    
    template = """index=corelight sourcetype=corelight_ssl {0} | table uid subject validation_status version ja3 ja3s"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_3:condition_2:query_connections:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_SSL_query")

    run_SSL_query(container=container)

    return

"""
Run the Splunk query built in the previous block.
"""
def run_file_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_file_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_file_query' call
    formatted_data_1 = phantom.get_format_data(name='format_file_query')

    parameters = []
    
    # build parameters list for 'run_file_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk'], callback=filter_valid_files, name="run_file_query")

    return

"""
Run the Splunk query built in the previous block.
"""
def run_SSL_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('run_SSL_query() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'run_SSL_query' call
    formatted_data_1 = phantom.get_format_data(name='format_SSL_query')

    parameters = []
    
    # build parameters list for 'run_SSL_query' call
    parameters.append({
        'query': formatted_data_1,
        'command': "search",
        'display': "",
        'parse_only': False,
    })

    phantom.act(action="run query", parameters=parameters, assets=['splunk','splunk'], callback=format_ssl_note, name="run_SSL_query")

    return

"""
Query Virustotal for threat information about any SHA1 hashes found in the corelight_files query.
"""
def file_reputation_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('file_reputation_1() called')
        
    #phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))
    
    # collect data for 'file_reputation_1' call
    results_data_1 = phantom.collect2(container=container, datapath=['run_file_query:action_result.data.*.sha1', 'run_file_query:action_result.parameter.context.artifact_id'], action_results=results)

    parameters = []
    
    # build parameters list for 'file_reputation_1' call
    for results_item_1 in results_data_1:
        if results_item_1[0]:
            parameters.append({
                'hash': results_item_1[0],
                # context (artifact id) is added to associate results with the artifact
                'context': {'artifact_id': results_item_1[1]},
            })

    phantom.act(action="file reputation", parameters=parameters, assets=['virustotal'], callback=filter_7, name="file_reputation_1")

    return

"""
Update the heads-up display with the DNS query.
"""
def pin_DNS_alert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_DNS_alert() called')

    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.query', 'artifact:*.id'])

    container_item_0 = [item[0] for item in container_data]

    phantom.pin(container=container, data=container_item_0, message="Connection to Alerted DNS Address", pin_type="card", pin_style="red", name=None)

    return

"""
Post the SHA1 hash to the heads-up display.
"""
def pin_virustotal_response(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_virustotal_response() called')

    filtered_results_data_1 = phantom.collect2(container=container, datapath=['filtered-data:filter_7:condition_1:file_reputation_1:action_result.data.*.sha1'])

    filtered_results_item_1_0 = [item[0] for item in filtered_results_data_1]

    phantom.pin(container=container, data=filtered_results_item_1_0, message="File Downloads VT Hit", pin_type="card", pin_style="", name=None)

    return

"""
Add a heads-up display pin for any suricata alerts that were found.
"""
def pin_suricata_alert(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('pin_suricata_alert() called')

    formatted_data_1 = phantom.get_format_data(name='format_suricata_pin')

    phantom.pin(container=container, data=formatted_data_1, message="Corelight UID with Surcata Alerts", name=None)

    return

"""
Create a note to display the HTTP URI.
"""
def add_HTTP_metadata_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_HTTP_metadata_note() called')

    formatted_data_1 = phantom.get_format_data(name='format_http_note')

    note_title = "URI the end point made requests to"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Add a note for the SSL metadata.
"""
def add_SSL_metadata_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('add_SSL_metadata_note() called')

    formatted_data_1 = phantom.get_format_data(name='format_ssl_note')

    note_title = "SSL Metadata"
    note_content = formatted_data_1
    note_format = "html"
    phantom.add_note(container=container, note_type="general", title=note_title, content=note_content, note_format=note_format)

    return

"""
Format a note for the SSL metadata.
"""
def format_ssl_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_ssl_note() called')
    
    template = """UID = {0}
JA3 = {1}
ja3s = {2}
subject = {3}
validation_status = {4}
version = {5}"""

    # parameter list for template variable replacement
    parameters = [
        "run_SSL_query:action_result.data.*.uid",
        "run_SSL_query:action_result.data.*.ja3",
        "run_SSL_query:action_result.data.*.ja3s",
        "run_SSL_query:action_result.data.*.subject",
        "run_SSL_query:action_result.data.*.validation_status",
        "run_SSL_query:action_result.data.*.version",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_ssl_note")

    add_SSL_metadata_note(container=container)

    return

"""
Proceed if there are one or more positive Virustotal matches.
"""
def filter_7(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_7() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation_1:action_result.data.*.positives", ">", 1],
        ],
        name="filter_7:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        pin_virustotal_response(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Format a heads-up display pin for any Suricata alerts that were found.
"""
def format_suricata_pin(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_suricata_pin() called')
    
    template = """URI = {1}
SURI_id = {0}
alert.signature ={2}"""

    # parameter list for template variable replacement
    parameters = [
        "run_suricata_query:action_result.data.*.suri_id",
        "run_suricata_query:action_result.data.*.uri",
        "run_suricata_query:action_result.data.*.alert.signature",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_suricata_pin")

    pin_suricata_alert(container=container)

    return

"""
Only proceed with valid Suricata alerts.
"""
def filter_valid_suricata_alerts(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_valid_suricata_alerts() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["run_suricata_query:action_result.data.*.suri_id", "!=", ""],
        ],
        name="filter_valid_suricata_alerts:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        format_suricata_pin(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Only proceed if files were found.
"""
def filter_valid_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_valid_files() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["run_file_query:action_result.data.*.sha1", "!=", ""],
        ],
        name="filter_valid_files:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation_1(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Only proceed if the DNS log matching our original malicious lookup returned a result where the DNS query was answered.
"""
def filter_DNS_answer(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('filter_DNS_answer() called')

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["run_DNS_alert_query:action_result.data.*.answer", "!=", ""],
        ],
        name="filter_DNS_answer:condition_1")

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        IP_regex_and_format_source_dest_query(action=action, success=success, container=container, results=results, handle=handle, custom_function=custom_function, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

"""
Convert the timestamp in the alert from ISO 8601 format to a unix epoch timestamp. 
"""
def timestamp_to_epoch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('timestamp_to_epoch() called')
    
    container_data_0 = phantom.collect2(container=container, datapath=['artifact:*.cef.ts', 'artifact:*.id'])
    literal_values_0 = [
        [
            -1,
        ],
    ]

    parameters = []

    for item0 in container_data_0:
        for item1 in literal_values_0:
            parameters.append({
                'input_datetime': item0[0],
                'amount_to_modify': item1[0],
                'modification_unit': None,
                'input_format_string': None,
                'output_format_string': None,
            })
    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################    

    # call custom function "community/datetime_modify", returns the custom_function_run_id
    phantom.custom_function(custom_function='community/datetime_modify', parameters=parameters, name='timestamp_to_epoch', callback=format_DNS_alert_query)

    return

"""
Format another Splunk query to use the UID from the previous query to list all matching corelight_conn log entries.
"""
def format_connection_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_connection_query() called')
    
    template = """%%
index=corelight sourcetype=corelight_conn {0} | table *
%%"""

    # parameter list for template variable replacement
    parameters = [
        "run_source_dest_query:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_connection_query")

    query_connections(container=container)

    return

"""
Format a query to look for the metadata of files detected in the connection stream by Corelight.
"""
def format_file_query(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_file_query() called')
    
    template = """index=corelight sourcetype=corelight_files {0} | table tx_hosts{{}} rx_hosts{{}} filename mime_type source sha1"""

    # parameter list for template variable replacement
    parameters = [
        "filtered-data:filter_nonzero_bytes:condition_1:query_connections:action_result.data.*.uid",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_file_query")

    run_file_query(container=container)

    return

"""
Format a note for the HTTP metadata.
"""
def format_http_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_http_note() called')
    
    template = """Timestamp = {0}
HTTP Host = {1}
URI = {2}
HTTP Method ={3}
HTTP Referrer = {4}
User-Agent = {5}"""

    # parameter list for template variable replacement
    parameters = [
        "run_HTTP_query:action_result.data.*.ts",
        "run_HTTP_query:action_result.data.*.host",
        "run_HTTP_query:action_result.data.*.uri",
        "run_HTTP_query:action_result.data.*.method",
        "run_HTTP_query:action_result.data.*.referrer",
        "run_HTTP_query:action_result.data.*.user_agent",
    ]

    phantom.format(container=container, template=template, parameters=parameters, name="format_http_note")

    add_HTTP_metadata_note(container=container)

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