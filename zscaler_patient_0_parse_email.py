"""
This utility playbook parses Patient 0 alert emails from zScaler to create another Phantom container and artifact for use in further automation.
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta
##############################
# Start - Global Code Block

import json
import base64
from datetime import datetime, timedelta
import re
import uuid

# End - Global Code block
##############################

def on_start(container):
    phantom.debug('on_start() called')
    
    # call 'parse_email_to_artifact' block
    parse_email_to_artifact(container=container)

    return

"""
Uses custom python to parse out the relevant fields from the Patient 0 alert email sent by zScaler. Creates a new container with the same name as the email subject and populates it with one zScaler Alert Artifact containing the parsed fields.
"""
def parse_email_to_artifact(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('parse_email_to_artifact() called')
    
    input_parameter_0 = ""

    ################################################################################
    ## Custom Code Start
    ################################################################################

    FIELD_TRANSLATOR = {
        'Cloud and Organization': 'environment',
        'File MD5 hash': 'fileHashMd5',
        'Threat Category': 'threatCategory',
        'Threat Name': 'threatName',
        'Transactions involving this content': 'eventLink'
    }
    
    # the full content of the email  is outside any artifact in the container['data'] field
    raw_data = phantom.get_raw_data(container)
    
    # build regular expressions to parse the Zscaler-specific email format
    allowed_re = re.compile(r"(?<=allowed )[0-9]+")
    quarantined_re = re.compile(r"(?<=quarantined )[0-9]+")
    blocked_re = re.compile(r"(?<=blocked )[0-9]+")
    
    cef={}
    raw={}
    
    # the content may or may not be base64 encoded so handle both
    base64index = raw_data.find('base64\\r\\n\\r\\n')
    phantom.debug(base64index)
    if base64index != -1:
        raw_data = raw_data[base64index+14:]
        raw_data = raw_data[:raw_data.find('\\r\\n\\r\\n')].replace('\\r\\n','\r\n')
    
        raw_data = base64.b64decode(raw_data)
    
        for line in raw_data.split('\n'):
            kv_pair = line.split(":")
            phantom.debug(str(kv_pair))
            if len(kv_pair) > 1:
                kv_pair[1] = ':'.join(kv_pair[1:])
                if kv_pair[0].strip() != 'First downloaded':
                    cef[FIELD_TRANSLATOR[kv_pair[0].strip()]] = kv_pair[1].strip()
                else:
                    kv_pair[1] = kv_pair[1].strip()
                    cef['startTime'] = kv_pair[1][:kv_pair[1].find('.')]
                    cef['timesAllowed'] = allowed_re.findall(kv_pair[1])[0]
                    cef['timesQuarantined'] = quarantined_re.findall(kv_pair[1])[0]
                    cef['timesBlocked'] = blocked_re.findall(kv_pair[1])[0]

    # if there is no base64, try to parse as plain text using regexes
    else:
        for field_label in FIELD_TRANSLATOR.keys():
            field_re = re.compile(r"{}:[ \\r\\n]+(.*?)\\r\\n".format(field_label))
            re_result = field_re.findall(raw_data)
            if re_result:
                field_value = re_result[0]
                cef[FIELD_TRANSLATOR[field_label]] = field_value

            re_result = re.findall(r"First downloaded: (.*?)\.", raw_data)
            if re_result and len(re_result[0]) < 200:
                cef['startTime'] = re_result[0]
            re_result = allowed_re.findall(raw_data)
            if re_result:
                cef['timesAllowed'] = re_result[0]
            re_result = quarantined_re.findall(raw_data)
            if re_result:
                cef['timesQuarantined'] = re_result[0]
            re_result = blocked_re.findall(raw_data)
            if re_result:
                cef['timesBlocked'] = re_result[0]

    success, message, container_id = phantom.create_container(name=container['name'], label='events')
    
    phantom.add_artifact(container=container_id, raw_data=raw, cef_data=cef, label='event', name='zScaler Alert Artifact', severity = 'medium', identifier=str(uuid.uuid4()), artifact_type='network')

    ################################################################################
    ## Custom Code End
    ################################################################################

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