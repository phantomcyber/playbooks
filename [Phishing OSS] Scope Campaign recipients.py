"""
This playbook finds all recipients who received a phishing campaign email by searching Email logs in Splunk.
"""


import phantom.rules as phantom # type: ignore
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'format_spl' block
    format_spl(container=container)

    return

@phantom.playbook_block()
def run_query_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("run_query_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    format_spl__spl_for_run_query = json.loads(_ if (_ := phantom.get_run_data(key="format_spl:spl_for_run_query")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if format_spl__spl_for_run_query is not None:
        parameters.append({
            "query": format_spl__spl_for_run_query,
            "command": "search",
            "start_time": "-7d",
            "search_mode": "smart",
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("run query", parameters=parameters, name="run_query_1", assets=["splunk"], callback=decision_1)

    return


@phantom.playbook_block()
def extract_emails(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("extract_emails() called")

    run_query_1_result_data = phantom.collect2(container=container, datapath=["run_query_1:action_result.data"], action_results=results)

    run_query_1_result_item_0 = [item[0] for item in run_query_1_result_data]

    input_parameter_0 = ""

    extract_emails__email_list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    import re
    phantom.debug("run_query_1_result_item_0: ")
    phantom.debug(run_query_1_result_item_0)
    extract_emails__email_list = []
    
    if run_query_1_result_item_0[0] != []:
        event_data=run_query_1_result_item_0[0][0]
        phantom.debug(event_data)
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        extracted_emails = []
        #phantom.debug(event_data.get("email", []))
        for item in event_data.get("email", []):
            matches = re.findall(email_pattern, item)
            phantom.debug(matches)
            extracted_emails.extend(matches)
            
        phantom.debug("extracted_emails: ")    
        phantom.debug(extracted_emails)
        extract_emails__email_list=extracted_emails

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="extract_emails__inputs:0:run_query_1:action_result.data", value=json.dumps(run_query_1_result_item_0))

    phantom.save_block_result(key="extract_emails:email_list", value=json.dumps(extract_emails__email_list))

    phantom.save_block_result(key="extract_emails_called", value="True")

    return


@phantom.playbook_block()
def format_spl(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("format_spl() called")

    playbook_input_sender = phantom.collect2(container=container, datapath=["playbook_input:sender"])
    playbook_input_subject = phantom.collect2(container=container, datapath=["playbook_input:subject"])

    playbook_input_sender_values = [item[0] for item in playbook_input_sender]
    playbook_input_subject_values = [item[0] for item in playbook_input_subject]

    format_spl__spl_for_run_query = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    sender=playbook_input_sender_values[0]
    subject=playbook_input_subject_values[0]
    
    #spl="""
    #index=obs-gsuite sourcetype=gsuite:gmail:bigquery ((source.from_header_address="""+str(sender)+""" OR sender="""+str(sender)+""") AND subject=\""""+str(subject)+"""\") | eval source.from_header_address = lower(source.from_header_address) | bin _time span=5m | stats earliest(_time) as first_seen, values(sender) as sender, values(source.from_header_address) as header_src, values(source.from_header_displayname) as display_name, values(connection_info.client_ip) as client_ip, values(subject) as subject, values(connection_info.dkim_pass) as dkim_pass, values(connection_info.dmarc_pass) as dmarc_pass, values(attachment{}.file_extension_type) AS file_extension_type, values(connection_info.dmarc_published_domain) as dmarc_published_domain, values(attachment{}.malware_family) as malware_family, values(connection_info.ip_geo_city) as ip_geo_city, values(connection_info.ip_geo_country) as ip_geo_country, values(is_spam) as is_spam, values(link_domain{}) as link_domain, values(num_message_attachments) as num_attachments, values(payload_size) as payload_size, values(source.service) as src_service by rfc2822_message_id recipient | eval client_ip = mvfilter(NOT match(client_ip,"null")), dmarc_pass = mvfilter(NOT match(dmarc_pass,"null")), dmarc_published_domain = mvfilter(NOT match(dmarc_published_domain,"null")), ip_geo_country = mvfilter(NOT match(ip_geo_country,"null")), is_spam = mvfilter(NOT match(is_spam,"null")) | sort 0 first_seen | convert timeformat="%m/%d/%Y %H:%M:%S" ctime(first_seen) | eval email = first_seen." - ".recipient." -> ".subject | stats values(email) as email
    #"""
    
    #Added as a part of https://splunk.atlassian.net/browse/SOAR-2753
    new_spl="""
    index=obs-gsuite sourcetype=gsuite:gmail:bigquery ((gmail.message_info.source.from_header_address="""+str(sender)+""" AND gmail.message_info.subject=\""""+str(subject)+"""\")) | bin _time span=5m | rename gmail.message_info.* as * | rename destination{}.address AS dest, source.address AS sender, subject AS subject | fields sender, source.from_header_displayname, connection_info.client_ip, subject, connection_info.dkim_pass, connection_info.dmarc_pass, attachment{}.file_extension_type, connection_info.dmarc_published_domain, attachment{}.malware_family, connection_info.ip_geo_city, connection_info.ip_geo_country, is_spam, payload_size, source.service, rfc2822_message_id, dest | stats earliest(_time) as first_seen, values(source.from_header_displayname) as display_name, values(subject) as subject values(connection_info.client_ip) as client_ip, values(connection_info.dkim_pass) as dkim_pass, values(connection_info.dmarc_pass) as dmarc_pass, values(attachment{}.file_extension_type) AS file_extension_type, values(connection_info.dmarc_published_domain) as dmarc_published_domain, values(attachment{}.malware_family) as malware_family, values(connection_info.ip_geo_city) as ip_geo_city, values(connection_info.ip_geo_country) as ip_geo_country, values(is_spam) as is_spam, values(payload_size) as payload_size, values(source.service) as src_service by _time sender dest | eval client_ip = mvfilter(NOT match(client_ip,"null")), dmarc_pass = mvfilter(NOT match(dmarc_pass,"null")), dmarc_published_domain = mvfilter(NOT match(dmarc_published_domain,"null")), ip_geo_country = mvfilter(NOT match(ip_geo_country,"null")), is_spam = mvfilter(NOT match(is_spam,"null")) | convert timeformat="%m/%d/%Y %H:%M:%S" ctime(first_seen) | eval event_time = strftime(_time, "%m/%d/%y %H:%M:%S") | eval email = event_time." - " .sender." - ".dest." -> ".subject | stats values(email) as email dc(dest) by sender
    """
    
    format_spl__spl_for_run_query=new_spl

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="format_spl__inputs:0:playbook_input:sender", value=json.dumps(playbook_input_sender_values))
    phantom.save_block_result(key="format_spl__inputs:1:playbook_input:subject", value=json.dumps(playbook_input_subject_values))

    phantom.save_block_result(key="format_spl:spl_for_run_query", value=json.dumps(format_spl__spl_for_run_query))

    phantom.save_block_result(key="format_spl_called", value="True")

    run_query_1(container=container)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["run_query_1:action_result.summary.total_events", "!=", 0]
        ],
        conditions_dps=[
            ["run_query_1:action_result.summary.total_events", "!=", 0]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        extract_emails(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    extract_emails__email_list = json.loads(_ if (_ := phantom.get_run_data(key="extract_emails:email_list")) != "" else "null")  # pylint: disable=used-before-assignment

    output = {
        "emails_list": extract_emails__email_list,
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return