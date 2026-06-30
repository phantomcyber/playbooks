"""
This playbook detonates suspicious email attachments in Splunk Attack Analyzer (SAA) sandbox  and extracts indicators for downstream analysis.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'attached_email_vault_id' block
    attached_email_vault_id(container=container)

    return

@phantom.playbook_block()
def attached_email_vault_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("attached_email_vault_id() called")

    id_value = container.get("id", None)

    attached_email_vault_id__email_vault_id = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    success, message, info = phantom.vault_info(
        container_id=id_value
    )
    
    phantom.debug(info)
    
    for item in info:
        if item.get("name","") == "attached_email.eml" or item.get("name","") == "Forwarded Message.eml" or ".eml" in item.get("name","") and item.get("name","") != "email.eml":
            vault_info=item
            vault_id=item.get("vault_id")
            attached_email_vault_id__email_vault_id=vault_id
    
    phantom.debug(attached_email_vault_id__email_vault_id)
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="attached_email_vault_id__inputs:0:container:id", value=json.dumps(id_value))

    phantom.save_block_result(key="attached_email_vault_id:email_vault_id", value=json.dumps(attached_email_vault_id__email_vault_id))

    phantom.save_block_result(key="attached_email_vault_id_called", value="True")

    decision_1(container=container)

    return


@phantom.playbook_block()
def detonate_file_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("detonate_file_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    attached_email_vault_id__email_vault_id = json.loads(_ if (_ := phantom.get_run_data(key="attached_email_vault_id:email_vault_id")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    if attached_email_vault_id__email_vault_id is not None:
        parameters.append({
            "file": attached_email_vault_id__email_vault_id,
        })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("detonate file", parameters=parameters, name="detonate_file_1", assets=["splunk_saa"], callback=get_job_summary_1)

    return


@phantom.playbook_block()
def get_job_summary_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("get_job_summary_1() called")

    # phantom.debug('Action: {0} {1}'.format(action['name'], ('SUCCEEDED' if success else 'FAILED')))

    detonate_file_1_result_data = phantom.collect2(container=container, datapath=["detonate_file_1:action_result.data.*.JobID","detonate_file_1:action_result.parameter.context.artifact_id"], action_results=results)

    parameters = []

    # build parameters list for 'get_job_summary_1' call
    for detonate_file_1_result_item in detonate_file_1_result_data:
        if detonate_file_1_result_item[0] is not None:
            parameters.append({
                "job_id": detonate_file_1_result_item[0],
                "timeout": 5,
                "context": {'artifact_id': detonate_file_1_result_item[1]},
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.act("get job summary", parameters=parameters, name="get_job_summary_1", assets=["splunk_saa"], callback=data_validation)

    return


@phantom.playbook_block()
def data_validation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("data_validation() called")

    get_job_summary_1_result_data = phantom.collect2(container=container, datapath=["get_job_summary_1:action_result.data.*.Verdict"], action_results=results)

    get_job_summary_1_result_item_0 = [item[0] for item in get_job_summary_1_result_data]

    data_validation__verdict = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    phantom.debug(get_job_summary_1_result_item_0)
    if get_job_summary_1_result_item_0[0] is None:
        data_validation__verdict = "Verdict Not Available"
        

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="data_validation__inputs:0:get_job_summary_1:action_result.data.*.Verdict", value=json.dumps(get_job_summary_1_result_item_0))

    phantom.save_block_result(key="data_validation:verdict", value=json.dumps(data_validation__verdict))

    phantom.save_block_result(key="data_validation_called", value="True")

    parse_indicators(container=container)

    return


@phantom.playbook_block()
def decision_1(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("decision_1() called")

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["attached_email_vault_id:custom_function:email_vault_id", "!=", None]
        ],
        conditions_dps=[
            ["attached_email_vault_id:custom_function:email_vault_id", "!=", None]
        ],
        name="decision_1:condition_1",
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        detonate_file_1(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def parse_indicators(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("parse_indicators() called")

    get_job_summary_1_result_data = phantom.collect2(container=container, datapath=["get_job_summary_1:action_result.data"], action_results=results)

    get_job_summary_1_result_item_0 = [item[0] for item in get_job_summary_1_result_data]

    parse_indicators__indicator_artifact_dict = None
    parse_indicators__indicator_emails = None
    parse_indicators__indicator_domains = None
    parse_indicators__indicator_files = None
    parse_indicators__indicator_urls = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...
    # Add below to a list
    # ip , domains, urls, hashes, sender_emails 
    indicator_dict={}
    #add dummy data
    indicator_dict["ips"]=["8.8.8.8","1.1.1.1"]
    indicator_dict["domains"]=["google.com","splunk.com"]
    indicator_dict["hashes"]=["0f8b4b26a26210a1b11c46e840dbe7e45a972bc2","13addd05d2afd58ff5e6972291d8bad0","35ba7e6c6b88b5475059b82da8761711","626cf679c33683f70ac13b2eaaa2df2f","7888acb3101dc718625e7a69483510bd44a22bdf","8aecea335ef65c481f42f9be62b60c7ed35df926","c95e17a16fbda939c71c9bdf049a23e1f67fcda2c354b78234ba5acf032e0642","d74cb11f3dc21afa54ee32049fbd7dfb15b20bd70f26a0dba67885095702aa4f","e8b46c9daa94e265b33b7c4ffa67759de7a5faff73a1bde60baa9b39af438742"]
    indicator_dict["emails"]=["attacker@senderdomain.com","new@sample.com"]
    indicator_dict["urls"]=["example.com/job/fd789f0f-6816-44b4-8d3e-0bd2fd082ee1","sample.com/job/fd789f0f-6816-44b4-8d3e-0bd2fd082ee1"]
    phantom.debug(indicator_dict)
    job_summary=get_job_summary_1_result_item_0[0]
    
    
    import re
    import json
    from pathlib import Path
    from typing import Dict, List, Set, Any


    # Regex patterns
    PATTERNS = {
        'emails': r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
        'urls': r'https?://[^\s<>"\']+',
        'domains': r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'ipv4': r'(?<![.\d])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![.\d])',
    }


    def _collect_strings(data) -> List[str]:
        """Recursively collect all string values from a data structure."""
        strings = []
        
        def recurse(value):
            if isinstance(value, str):
                strings.append(value)
            elif isinstance(value, dict):
                for v in value.values():
                    recurse(v)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    recurse(item)
        
        recurse(data)
        return strings


    # Patterns to ignore for emails
    EMAIL_IGNORE_PATTERNS = [
        r'.*@splunk\.com$',
        r'.*@mail\.gmail\.com$',
    ]


    def _matches_email_ignore_pattern(email: str) -> bool:
        """Check if email matches any ignore pattern."""
        email_lower = email.lower()
        for pattern in EMAIL_IGNORE_PATTERNS:
            if re.match(pattern, email_lower):
                return True
        return False


    def extract_emails(data, ignorelist: Set[str] = None) -> List[str]:
        """
        Extract email addresses from data.
        
        Args:
            data: Input data (dict, list, or string)
            ignorelist: Set of emails to exclude. Pass an empty set to disable filtering.
        """
        if ignorelist is None:
            ignorelist = set()
        
        emails = set()
        for text in _collect_strings(data):
            emails.update(re.findall(PATTERNS['emails'], text))
        
        # Filter out ignored emails and patterns
        filtered = {
            e for e in emails 
            if e.lower() not in {i.lower() for i in ignorelist} 
            and not _matches_email_ignore_pattern(e)
        }
        return sorted(filtered)


        # Patterns to ignore for URLs
    URL_IGNORE_PATTERNS = [
        r'.*app\.twinwave\.io.*',
    ]


    def _matches_url_ignore_pattern(url: str) -> bool:
        """Check if URL matches any ignore pattern."""
        url_lower = url.lower()
        for pattern in URL_IGNORE_PATTERNS:
            if re.match(pattern, url_lower):
                return True
        return False


    def extract_urls(data, ignorelist: Set[str] = None) -> List[str]:
        """
        Extract URLs from data.
        
        Args:
            data: Input data (dict, list, or string)
            ignorelist: Set of URLs to exclude. Pass an empty set to disable filtering.
        """
        if ignorelist is None:
            ignorelist = set()
        
        urls = set()
        for text in _collect_strings(data):
            urls.update(re.findall(PATTERNS['urls'], text))
        
        # Filter out ignored URLs and patterns
        filtered = {
            u for u in urls 
            if u.lower() not in {i.lower() for i in ignorelist} 
            and not _matches_url_ignore_pattern(u)
        }
        return sorted(filtered)


    # Default domains to ignore (common benign domains)
    DEFAULT_DOMAIN_IGNORELIST = {
        'google.com',
        'gmail.com',
        'mail.google.com',
        'googleapis.com',
        'gstatic.com',
        'microsoft.com',
        'outlook.com',
        'office.com',
        'windows.net',
        'header.from',
        'org.apache.tika.parser.CompositeParser',
        'org.apache.tika.parser.image.ImageParser',
        'org.apache.tika.parser.ocr.TesseractOCRParser',
        'org.apache.tika.parser.pdf.PDFParser',
    }

    # Patterns to ignore (file extensions and subdomain wildcards)
    IGNORE_PATTERNS = [
        r'.*\.eml$',
        r'.*\.tgz$',
        r'.*\.json\.gz$',
        r'.*\.pdf$',
        r'.*\.png$',
        r'.*\.google\.com$',
        r'.*gmail\.com$',
        r'.*splunk\.com$',
        r'.*twinwave\.io$',
        r'.*smtp\.mailfrom.*',
    ]


    def _matches_ignore_pattern(domain: str) -> bool:
        """Check if domain matches any ignore pattern."""
        domain_lower = domain.lower()
        for pattern in IGNORE_PATTERNS:
            if re.match(pattern, domain_lower):
                return True
        return False


    def extract_domains(data, ignorelist: Set[str] = None) -> List[str]:
        """
        Extract domains from data.
        
        Args:
            data: Input data (dict, list, or string)
            ignorelist: Set of domains to exclude. If None, uses DEFAULT_DOMAIN_IGNORELIST.
                       Pass an empty set to disable filtering.
        """
        if ignorelist is None:
            ignorelist = DEFAULT_DOMAIN_IGNORELIST
        
        domains = set()
        for text in _collect_strings(data):
            domains.update(re.findall(PATTERNS['domains'], text))
        
        # Filter out ignored domains and patterns
        filtered = {
            d for d in domains 
            if d.lower() not in {i.lower() for i in ignorelist} 
            and not _matches_ignore_pattern(d)
        }
        return sorted(filtered)


    def extract_hashes(data) -> List[str]:
        """Extract file hashes (MD5, SHA1, SHA256) from data."""
        hashes = set()
        for text in _collect_strings(data):
            hashes.update(re.findall(PATTERNS['md5'], text))
            hashes.update(re.findall(PATTERNS['sha1'], text))
            hashes.update(re.findall(PATTERNS['sha256'], text))
        return sorted(hashes)

    
    # Default IPs to ignore
    DEFAULT_IP_IGNORELIST = {
        '8.8.8.8',
    }


    def extract_ips(data, ignorelist: Set[str] = None) -> List[str]:
        """
        Extract IPv4 addresses from data.
        
        Args:
            data: Input data (dict, list, or string)
            ignorelist: Set of IPs to exclude. If None, uses DEFAULT_IP_IGNORELIST.
                       Pass an empty set to disable filtering.
        """
        if ignorelist is None:
            ignorelist = DEFAULT_IP_IGNORELIST
        
        ips = set()
        for text in _collect_strings(data):
            ips.update(re.findall(PATTERNS['ipv4'], text))
        
        # Filter out ignored IPs
        filtered = {ip for ip in ips if ip not in ignorelist}
        return sorted(filtered)
    
    def extract_iocs(data) -> Dict[str, List[str]]:
        """
        Extract all IOCs (domains, email addresses, URLs, file hashes, IPs) from data.
        """
        return {
            'emails': extract_emails(data),
            'urls': extract_urls(data),
            'domains': extract_domains(data),
            'hashes': extract_hashes(data),
            'ips': extract_ips(data)
        }
    
    extracted = extract_iocs(job_summary)
    
    
    parse_indicators__indicator_artifact_dict=extracted#indicator_dict#
    phantom.debug(parse_indicators__indicator_artifact_dict)
    parse_indicators__indicator_emails = extracted.get("emails")
    parse_indicators__indicator_domains = extracted.get("domains")
    parse_indicators__indicator_files = extracted.get("hashes")
    parse_indicators__indicator_urls = extracted.get("urls")
    

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_block_result(key="parse_indicators__inputs:0:get_job_summary_1:action_result.data", value=json.dumps(get_job_summary_1_result_item_0))

    phantom.save_block_result(key="parse_indicators:indicator_artifact_dict", value=json.dumps(parse_indicators__indicator_artifact_dict))
    phantom.save_block_result(key="parse_indicators:indicator_emails", value=json.dumps(parse_indicators__indicator_emails))
    phantom.save_block_result(key="parse_indicators:indicator_domains", value=json.dumps(parse_indicators__indicator_domains))
    phantom.save_block_result(key="parse_indicators:indicator_files", value=json.dumps(parse_indicators__indicator_files))
    phantom.save_block_result(key="parse_indicators:indicator_urls", value=json.dumps(parse_indicators__indicator_urls))

    phantom.save_block_result(key="parse_indicators_called", value="True")

    create_indicator_artifact(container=container)

    return


@phantom.playbook_block()
def create_indicator_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("create_indicator_artifact() called")

    id_value = container.get("id", None)
    parse_indicators__indicator_artifact_dict = json.loads(_ if (_ := phantom.get_run_data(key="parse_indicators:indicator_artifact_dict")) != "" else "null")  # pylint: disable=used-before-assignment

    parameters = []

    parameters.append({
        "name": "SAA Indicators",
        "tags": None,
        "label": None,
        "severity": None,
        "cef_field": "indicators",
        "cef_value": parse_indicators__indicator_artifact_dict,
        "container": id_value,
        "input_json": parse_indicators__indicator_artifact_dict,
        "cef_data_type": None,
        "run_automation": None,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    # Write your custom code here...

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/artifact_create", parameters=parameters, name="create_indicator_artifact")

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    get_job_summary_1_result_data = phantom.collect2(container=container, datapath=["get_job_summary_1:action_result.summary.Score"])

    get_job_summary_1_summary_score = [item[0] for item in get_job_summary_1_result_data]

    output = {
        "saa_score": get_job_summary_1_summary_score,
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