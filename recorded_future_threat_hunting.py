"""
Starting with a single IP address, this playbook gathers a list of linked IP addresses, domain names, file hashes, urls, and vulnerability CVE&#39;s from Recorded Future. Then Splunk is used to build threat hunting lookup tables and search across multiple data sources for events containing the linked entities. Finally, IP addresses are blocked if approved by an analyst and an email is sent to notify a responder of the activity.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'ip_intelligence_1' block
    ip_intelligence_1(container=container)

    return

@phantom.playbook_block()
def ip_intelligence_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("ip_intelligence_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Query for the full context about the IP address and related entities from Recorded 
    # Future
    ################################################################################

    container_artifact_data = phantom.collect2(container=container, datapath=["artifact:*.cef.destinationAddress","artifact:*.id"])

    parameters = []

    # build parameters list for 'ip_intelligence_1' call
    for container_artifact_item in container_artifact_data:
        if container_artifact_item[0] is not None:
            parameters.append({
                "ip": container_artifact_item[0],
                "context": {'artifact_id': container_artifact_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("ip intelligence", parameters=parameters, name="ip_intelligence_1", assets=["recorded future "], callback=decision_1)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_1() called")

    ################################################################################
    # Proceed if the risk score is higher than a certain threshold
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ip_intelligence_1:action_result.data.*.risk.score", ">=", 90]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        format_linked_ip_lookup(action=action, success=success, container=container, results=results, handle=handle)
        format_linked_domain_lookup(action=action, success=success, container=container, results=results, handle=handle)
        format_linked_files_lookup(action=action, success=success, container=container, results=results, handle=handle)
        format_linked_vuln_lookup(action=action, success=success, container=container, results=results, handle=handle)
        format_linked_url_lookup(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def format_linked_ip_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_linked_ip_lookup() called")

    ################################################################################
    # Build a Splunk query to turn a list of linked entities from Recorded Future 
    # into a lookup table that can be used for threat hunting across any sourcetype 
    # or data model
    ################################################################################

    template = """| eval Name=\"{0}\" | makemv Name delim=\", \" | mvexpand Name | appendcols [| makeresults | eval RF_Risk_Score=\"{1}\" | makemv RF_Risk_Score delim=\", \" | mvexpand RF_Risk_Score ] | outputlookup huntip.csv"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.ip.*.name",
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.ip.*.score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_linked_ip_lookup")

    build_ip_lookup(container=container)

    return


@phantom.playbook_block()
def format_linked_domain_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_linked_domain_lookup() called")

    ################################################################################
    # Build a Splunk query to turn a list of linked entities from Recorded Future 
    # into a lookup table that can be used for threat hunting across any sourcetype 
    # or data model
    ################################################################################

    template = """| eval Name=\"{0}\" | makemv Name delim=\", \" | mvexpand Name | appendcols [| makeresults | eval RF_Risk_Score=\"{1}\" | makemv RF_Risk_Score delim=\", \" | mvexpand RF_Risk_Score ] | outputlookup huntdomain.csv"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.domain.*.name",
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.domain.*.score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_linked_domain_lookup")

    build_domain_lookup(container=container)

    return


@phantom.playbook_block()
def format_linked_files_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_linked_files_lookup() called")

    ################################################################################
    # Build a Splunk query to turn a list of linked entities from Recorded Future 
    # into a lookup table that can be used for threat hunting across any sourcetype 
    # or data model
    ################################################################################

    template = """| eval Name=\"{0}\" | makemv Name delim=\", \" | mvexpand Name | appendcols [| makeresults | eval RF_Risk_Score=\"{1}\" | makemv RF_Risk_Score delim=\", \" | mvexpand RF_Risk_Score ] | outputlookup huntfile.csv"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.file.*.name",
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.file.*.score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_linked_files_lookup")

    build_file_lookup(container=container)

    return


@phantom.playbook_block()
def format_linked_vuln_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_linked_vuln_lookup() called")

    ################################################################################
    # Build a Splunk query to turn a list of linked entities from Recorded Future 
    # into a lookup table that can be used for threat hunting across any sourcetype 
    # or data model
    ################################################################################

    template = """| eval Name=\"{0}\" | makemv Name delim=\", \" | mvexpand Name | appendcols [| makeresults | eval RF_Risk_Score=\"{1}\" | makemv RF_Risk_Score delim=\", \" | mvexpand RF_Risk_Score ] | outputlookup huntvuln.csv"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.vulnerability.*.name",
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.vulnerability.*.score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_linked_vuln_lookup")

    build_vuln_lookup(container=container)

    return


@phantom.playbook_block()
def format_linked_url_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_linked_url_lookup() called")

    ################################################################################
    # Build a Splunk query to turn a list of linked entities from Recorded Future 
    # into a lookup table that can be used for threat hunting across any sourcetype 
    # or data model
    ################################################################################

    template = """| eval Name=\"{0}\" | makemv Name delim=\", \" | mvexpand Name | appendcols [| makeresults | eval RF_Risk_Score=\"{1}\" | makemv RF_Risk_Score delim=\", \" | mvexpand RF_Risk_Score ] | outputlookup hunturl.csv"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.url.*.name",
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.url.*.score"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_linked_url_lookup")

    build_url_lookup(container=container)

    return


@phantom.playbook_block()
def build_ip_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_ip_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the Splunk query that creates the lookup file
    ################################################################################

    format_linked_ip_lookup = phantom.get_format_data(name="format_linked_ip_lookup")

    parameters = []

    if format_linked_ip_lookup is not None:
        parameters.append({
            "query": format_linked_ip_lookup,
            "command": "| makeresults",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="build_ip_lookup", assets=["splunk"], callback=search_splunk_for_ips)

    return


@phantom.playbook_block()
def build_domain_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_domain_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the Splunk query that creates the lookup file
    ################################################################################

    format_linked_domain_lookup = phantom.get_format_data(name="format_linked_domain_lookup")

    parameters = []

    if format_linked_domain_lookup is not None:
        parameters.append({
            "query": format_linked_domain_lookup,
            "command": "| makeresults",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="build_domain_lookup", assets=["splunk"], callback=search_splunk_for_domains)

    return


@phantom.playbook_block()
def build_file_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_file_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the Splunk query that creates the lookup file
    ################################################################################

    format_linked_files_lookup = phantom.get_format_data(name="format_linked_files_lookup")

    parameters = []

    if format_linked_files_lookup is not None:
        parameters.append({
            "query": format_linked_files_lookup,
            "command": "| makeresults",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="build_file_lookup", assets=["splunk"], callback=search_splunk_for_files)

    return


@phantom.playbook_block()
def build_vuln_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_vuln_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the Splunk query that creates the lookup file
    ################################################################################

    format_linked_vuln_lookup = phantom.get_format_data(name="format_linked_vuln_lookup")

    parameters = []

    if format_linked_vuln_lookup is not None:
        parameters.append({
            "query": format_linked_vuln_lookup,
            "command": "| makeresults",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="build_vuln_lookup", assets=["splunk"], callback=search_splunk_for_vulns)

    return


@phantom.playbook_block()
def build_url_lookup(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("build_url_lookup() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Run the Splunk query that creates the lookup file
    ################################################################################

    format_linked_url_lookup = phantom.get_format_data(name="format_linked_url_lookup")

    parameters = []

    if format_linked_url_lookup is not None:
        parameters.append({
            "query": format_linked_url_lookup,
            "command": "| makeresults",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="build_url_lookup", assets=["splunk"], callback=search_splunk_for_urls)

    return


@phantom.playbook_block()
def search_splunk_for_ips(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_splunk_for_ips() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search Palo Alto Networks firewall logs for any events with threat-related ip 
    # addresses in the dest_ip field
    ################################################################################

    parameters = []

    parameters.append({
        "query": "sourcetype=\"netscreen:firewall\" ((earliest=-24h latest=now)) |eval Name=dest_ip | lookup huntip.csv Name OUTPUT RF_Risk_Score | search RF_Risk_Score>24",
        "command": "search",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_splunk_for_ips", assets=["splunk"], callback=search_splunk_for_ips_callback)

    return


@phantom.playbook_block()
def search_splunk_for_ips_callback(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_splunk_for_ips_callback() called")

    
    recorded_future_threat_hunting_block_ip(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)
    join_format_email(action=action, success=success, container=container, results=results, handle=handle, filtered_artifacts=filtered_artifacts, filtered_results=filtered_results)


    return


@phantom.playbook_block()
def search_splunk_for_domains(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_splunk_for_domains() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search Palo Alto Networks threat logs for any events with threat-related domain 
    # names in the dest_hostname field
    ################################################################################

    parameters = []

    parameters.append({
        "query": "sourcetype=\"netscreen:firewall\" ((earliest=-24h latest=now)) |eval Name=dest_ip | lookup huntip.csv Name OUTPUT RF_Risk_Score | search RF_Risk_Score>24",
        "command": "search",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_splunk_for_domains", assets=["splunk"], callback=join_format_email)

    return


@phantom.playbook_block()
def search_splunk_for_files(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_splunk_for_files() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search Symantec Endpoint Protection logs for sightings of threat-related file 
    # hashes
    ################################################################################

    parameters = []

    parameters.append({
        "query": "index=main sourcetype=symantec:ep:risk:file ((earliest=-1d latest=now)) |eval Name=file_hash | lookup huntfile.csv Name OUTPUT RF_Risk_Score | search RF_Risk_Score>24",
        "command": "search",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_splunk_for_files", assets=["splunk"], callback=join_format_email)

    return


@phantom.playbook_block()
def search_splunk_for_vulns(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_splunk_for_vulns() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search Tenable vulnerability scanning logs for any vulnerabilities related to 
    # the initial IP addresses
    ################################################################################

    parameters = []

    parameters.append({
        "query": "index=main sourcetype=\"tenable:sc:vuln\" ((earliest=-7d latest=now)) |eval Name=cve | lookup huntvuln.csv Name OUTPUT RF_Risk_Score | search RF_Risk_Score>24",
        "command": "search",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_splunk_for_vulns", assets=["splunk"], callback=join_format_email)

    return


@phantom.playbook_block()
def search_splunk_for_urls(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("search_splunk_for_urls() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Search Squid Proxy logs for any URLs related to the initial IP addresses
    ################################################################################

    parameters = []

    parameters.append({
        "query": "index=main sourcetype=\"squid:access\" ((earliest=-24h latest=now)) |eval Name=url | lookup hunturl.csv Name OUTPUT RF_Risk_Score | search RF_Risk_Score>24",
        "command": "search",
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="search_splunk_for_urls", assets=["splunk"], callback=join_format_email)

    return


@phantom.playbook_block()
def recorded_future_threat_hunting_block_ip(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("recorded_future_threat_hunting_block_ip() called")

    ################################################################################
    # Ask an analyst whether the discovered related IP addresses should be blocked
    ################################################################################

    # set user and message variables for phantom.prompt call

    user = "admin"
    message = """Do you want to add the following IP(s) to the block IP block list:\n{0}"""

    # parameter list for template variable replacement
    parameters = [
        "search_splunk_for_ips:action_result.data.*.IP"
    ]

    # responses
    response_types = [
        {
            "prompt": "Block IPs?",
            "options": {
                "type": "list",
                "choices": [
                    "Yes",
                    "No"
                ],
            },
        }
    ]

    phantom.prompt2(container=container, user=user, message=message, respond_in_mins=30, name="recorded_future_threat_hunting_block_ip", parameters=parameters, response_types=response_types, callback=decision_2)

    return


@phantom.playbook_block()
def decision_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("decision_2() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["recorded_future_threat_hunting_block_ip:action_result.summary.responses.0", "==", "Yes"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        add_ip_to_block_list(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def add_ip_to_block_list(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("add_ip_to_block_list() called")

    ################################################################################
    # Add the IP address to a Phantom custom list, which can be tracked as a REST-accessible 
    # external block list by a firewall
    ################################################################################

    search_splunk_for_ips_result_data = phantom.collect2(container=container, datapath=["search_splunk_for_ips:action_result.data.*.Name"], action_results=results)

    search_splunk_for_ips_result_item_0 = [item[0] for item in search_splunk_for_ips_result_data]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.add_list(list_name="IP Block List", values=search_splunk_for_ips_result_item_0)

    return


@phantom.playbook_block()
def join_format_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("join_format_email() called")

    if phantom.completed(action_names=["search_splunk_for_ips", "search_splunk_for_domains", "search_splunk_for_files", "search_splunk_for_vulns", "search_splunk_for_urls"]):
        # call connected block "format_email"
        format_email(container=container, handle=handle)

    return


@phantom.playbook_block()
def format_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("format_email() called")

    ################################################################################
    # Include the intelligence context and Splunk results in the email and link to 
    # the event in Phantom for the rest of the detail
    ################################################################################

    template = """The potentially malicious destination IP {0} with a Risk Score of {1} was identified and processed by the Phantom playbook \"recorded_future_threat_hunting_conf\". \n\nThe IP is located in {11}, {12}, {13}\n\nAdditional searches performed against various logs showed that the following linked entities have been found in recent events:\n\nIP addresses: \n{2}\n\ndomain names: \n{3}\n\nfile hashes: \n{4}\n\nvulnerability identifiers: \n{5}\n\nRecorded Future Intelligence has also linked this IP to the following additional Entities:\n{7}\n\nMore details are available in Phantom: {6}\n\nMore details are available in Recorded Future: {10}"""

    # parameter list for template variable replacement
    parameters = [
        "ip_intelligence_1:action_result.parameter.ip",
        "ip_intelligence_1:action_result.data.*.risk.score",
        "search_splunk_for_ips:action_result.data.*.Name",
        "search_splunk_for_domains:action_result",
        "search_splunk_for_files:action_result.data.*.Name",
        "search_splunk_for_vulns:action_result.data.*.Name",
        "container:url",
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.other.*.name",
        "ip_intelligence_1:action_result.data.*.recordedfutureLinks.entities.ip.*.name",
        "ip_intelligence_1:action_result.data.*.relatedEntities.*.entities.*.entity.name",
        "ip_intelligence_1:action_result.data.*.intelCard",
        "ip_intelligence_1:action_result.data.*.location.location.city",
        "ip_intelligence_1:action_result.data.*.location.location.country",
        "ip_intelligence_1:action_result.data.*.location.location.continent"
    ]

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.format(container=container, template=template, parameters=parameters, name="format_email")

    send_email_if_related_entities_are_found(container=container)

    return


@phantom.playbook_block()
def send_email_if_related_entities_are_found(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email_if_related_entities_are_found() called")

    ################################################################################
    # If any of the Splunk searches had any results, send an email to an analyst
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="or",
        conditions=[
            ["search_splunk_for_ips:action_result.data.*.RF_Risk_Score", ">", 64],
            ["search_splunk_for_domains:action_result.data.*.RF_Risk_Score", ">", 64],
            ["search_splunk_for_files:action_result", ">", 64],
            ["search_splunk_for_vulns:action_result.data.*.RF_Risk_Score", ">", 64],
            ["search_splunk_for_urls:action_result.data.*.RF_Risk_Score", ">", 64]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        send_email(action=action, success=success, container=container, results=results, handle=handle)
        set_severity_add_note_2(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def send_email(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("send_email() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    ################################################################################
    # Send the formatted email to a hard-coded recipient
    ################################################################################

    format_email = phantom.get_format_data(name="format_email")

    parameters = []

    if format_email is not None:
        parameters.append({
            "subject": "Malicous IP with related entities found in Splunk",
            "body": format_email,
            "to": "placeholder",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("send email", parameters=parameters, name="send_email", assets=["email"])

    return


@phantom.playbook_block()
def set_severity_add_note_2(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("set_severity_add_note_2() called")

    format_email = phantom.get_format_data(name="format_email")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.set_severity(container=container, severity="high")
    phantom.add_note(container=container, content=format_email, note_format="markdown", note_type="general", title="Recorded Future Intelligence")

    container = phantom.get_container(container.get('id', None))

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # This function is called after all actions are completed.
    # summary of all the action and/or all details of actions
    # can be collected here.

    # summary_json = phantom.get_summary()
    # if 'result' in summary_json:
        # for action_result in summary_json['result']:
            # if 'action_run_id' in action_result:
                # action_results = phantom.get_action_results(action_run_id=action_result['action_run_id'], result_data=False, flatten=False)
                # phantom.debug(action_results)

    ################################################################################
    ## Custom Code End
    ################################################################################

    return