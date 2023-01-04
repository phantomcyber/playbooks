"""
An alternative to the included playbook block that collects indicator type data from the container and routes it to available input playbooks based on provided criteria. It will pair indicator data with the playbook&#39;s inputs based on the data type.
"""


import phantom.rules as phantom
import json
from datetime import datetime, timedelta


@phantom.playbook_block()
def on_start(container):
    phantom.debug('on_start() called')

    # call 'check_valid_inputs' block
    check_valid_inputs(container=container)

    return

@phantom.playbook_block()
def find_matching_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("find_matching_playbooks() called")

    playbook_input_playbook_repo = phantom.collect2(container=container, datapath=["playbook_input:playbook_repo"])
    playbook_input_playbook_tags = phantom.collect2(container=container, datapath=["playbook_input:playbook_tags"])

    parameters = []

    # build parameters list for 'find_matching_playbooks' call
    for playbook_input_playbook_repo_item in playbook_input_playbook_repo:
        for playbook_input_playbook_tags_item in playbook_input_playbook_tags:
            parameters.append({
                "name": None,
                "repo": playbook_input_playbook_repo_item[0],
                "tags": playbook_input_playbook_tags_item[0],
                "category": None,
                "playbook_type": "input",
            })

    ################################################################################
    ## Custom Code Start
    ################################################################################
    # overwrite parameters
    parameters = []
    
    # Check valid playbook input for repo. Otherwise default to local.
    if not any(item[0] for item in playbook_input_playbook_repo):
        phantom.debug("No repo provided, defaulting to local")
        playbook_repo_list = ["local"]
    else:
        playbook_repo_list = [item[0] for item in playbook_input_playbook_repo if item[0]]
    
    # Control iteration through playbook inputs to match what custom function is expecting
    for repo in playbook_repo_list:
        parameters.append({
            "name": None,
            "repo": repo,
            "tags": ', '.join([item[0] for item in playbook_input_playbook_tags]),
            "category": None,
            "playbook_type": "input",
        })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/playbooks_list", parameters=parameters, name="find_matching_playbooks", callback=playbooks_decision)

    return


@phantom.playbook_block()
def playbooks_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("playbooks_decision() called")

    ################################################################################
    # Determines if any matching playbooks were found based in the playbook list utility.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["find_matching_playbooks:custom_function_result.data.*.full_name", "!=", ""]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        find_supported_indicator_types(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def dispatch_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("dispatch_playbooks() called")

    ################################################################################
    # Dynamically routes indicator types to playbook inputs based on  playbook input_spec 
    # and generates a list of playbook IDs and names to check downstream.
    ################################################################################

    find_matching_playbooks_data = phantom.collect2(container=container, datapath=["find_matching_playbooks:custom_function_result.data.*.full_name","find_matching_playbooks:custom_function_result.data.*.input_spec"])
    collect_indicator_data_all_indicators = phantom.collect2(container=container, datapath=["collect_indicator:custom_function_result.data.all_indicators.*.cef_value","collect_indicator:custom_function_result.data.all_indicators.*.data_types"])

    find_matching_playbooks_data___full_name = [item[0] for item in find_matching_playbooks_data]
    find_matching_playbooks_data___input_spec = [item[1] for item in find_matching_playbooks_data]
    collect_indicator_data_all_indicators___cef_value = [item[0] for item in collect_indicator_data_all_indicators]
    collect_indicator_data_all_indicators___data_types = [item[1] for item in collect_indicator_data_all_indicators]

    dispatch_playbooks__names = None
    dispatch_playbooks__ids = None

    ################################################################################
    ## Custom Code Start
    ################################################################################

    playbook_name = [item for item in find_matching_playbooks_data___full_name if item]
    playbook_spec = [item for item in find_matching_playbooks_data___input_spec if item]
    indicator_cef_value_list = collect_indicator_data_all_indicators___cef_value
    indicator_cef_type_list = collect_indicator_data_all_indicators___data_types

    playbook_launch_list = {}
    dispatch_playbooks__names = []
    dispatch_playbooks__ids = []


    for pb_name, spec_item in zip(playbook_name, playbook_spec):
        pb_inputs = {}
        for cef_value, cef_type in zip(indicator_cef_value_list, indicator_cef_type_list):
            for type_item in cef_type:
                # check if any of the requested playbook types have inputs that accept this data type
                for spec in spec_item:
                    for contains_type in spec['contains']:
                        if type_item == contains_type:
                            # build playbook inputs
                            if not pb_inputs or not pb_inputs.get(spec['name']):
                                pb_inputs[spec['name']] = [cef_value]
                            else:
                                if cef_value not in pb_inputs[spec['name']]:
                                    pb_inputs[spec['name']].append(cef_value)
        # only launch playbooks that have inputs
        if pb_inputs:
            playbook_launch_list[pb_name] = pb_inputs

    if playbook_launch_list:
        for k,v in playbook_launch_list.items():
            name = 'playbook_{}'.format(k.split('/')[1].replace(' ','_').lower())
            dispatch_playbooks__names.append(name)
            phantom.debug(f"Launching playbook '{k}' with inputs '{v}'")
            dispatch_playbooks__ids.append(phantom.playbook(playbook=k, container=container, inputs=v, name=name, callback=wait_for_playbooks))
            
    else:
        raise RuntimeError(f"""Unable to find any match between indicator types and playbook input types.
Ensure you have a input type playbook that handles at least one of the following data types from the event:
'{[item[0] for item in indicator_cef_type_list if item]}'""")
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="dispatch_playbooks:names", value=json.dumps(dispatch_playbooks__names))
    phantom.save_run_data(key="dispatch_playbooks:ids", value=json.dumps(dispatch_playbooks__ids))

    wait_for_playbooks(container=container)

    return


@phantom.playbook_block()
def wait_for_playbooks(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("wait_for_playbooks() called")

    ################################################################################
    # Waits for all of the playbooks from the preceding block to finish.
    ################################################################################

    dispatch_playbooks__names = json.loads(_ if (_ := phantom.get_run_data(key="dispatch_playbooks:names")) != "" else "null")  # pylint: disable=used-before-assignment

    ################################################################################
    ## Custom Code Start
    ################################################################################

    if phantom.completed(playbook_names=dispatch_playbooks__names):
        process_outputs(container=container)
    # return early to avoid moving to next block
    return    

    ################################################################################
    ## Custom Code End
    ################################################################################

    process_outputs(container=container)

    return


@phantom.playbook_block()
def indicator_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("indicator_decision() called")

    ################################################################################
    # Determines if the indicator types that are present in the container are also 
    # in the supported indicator types from the playbooks.
    ################################################################################

    # check for 'if' condition 1
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["collect_indicator:custom_function_result.data.all_indicators.*.data_types", "in", "find_supported_indicator_types:custom_function:list"]
        ])

    # call connected blocks if condition 1 matched
    if found_match_1:
        dispatch_playbooks(action=action, success=success, container=container, results=results, handle=handle)
        return

    return


@phantom.playbook_block()
def process_outputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("process_outputs() called")

    ################################################################################
    # Collects playbook outputs from the finished playbooks and merges them to a format 
    # that is compatible with the end block.
    ################################################################################

    dispatch_playbooks__ids = json.loads(_ if (_ := phantom.get_run_data(key="dispatch_playbooks:ids")) != "" else "null")  # pylint: disable=used-before-assignment

    process_outputs__data = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    process_outputs__data = {
        'playbook_run_id_list': [], 
        'playbook_id_list': [], 
        'playbook_name_list': [], 
        'verdict': [],
        'observable': [],
        'markdown_report': [],
        'note_content': [],
        'sub_playbook_outputs': [],
        'sub_playbook_inputs': []
    }
    
    # Iterate through playbook_ids, collecting outputs and merging them into this playbook's output key.
    for run_id in dispatch_playbooks__ids:
        # Get playbook run details
        playbook_run_json = phantom.requests.get(phantom.build_phantom_rest_url('playbook_run', run_id), verify=False).json()
        process_outputs__data['playbook_run_id_list'].append(playbook_run_json['id'])
        playbook_id = playbook_run_json['playbook']
        process_outputs__data['playbook_id_list'].append(playbook_id)
        # Get playbook name
        playbook_json = phantom.requests.get(phantom.build_phantom_rest_url('playbook', playbook_id), verify=False).json()
        playbook_name = playbook_json['name']
        process_outputs__data['playbook_name_list'].append(playbook_name)
        
        if playbook_run_json.get('outputs'):
            sub_playbook_output_dict = {'playbook_name': playbook_name}
            for output in playbook_run_json['outputs']:
                output_dict = json.loads(output)
                for k,v in output_dict.items():
                    # Populate basic outputs for certain keys
                    if k.lower() in ['verdict', 'note_content', 'observable', 'markdown_report']:
                        if isinstance(v, list):
                            process_outputs__data[k.lower()].extend(v)
                        else:
                            process_outputs__data[k.lower()].append(v)
                    # Populate sub_playbook outputs
                    sub_playbook_output_dict[k] = v
            process_outputs__data['sub_playbook_outputs'].append(sub_playbook_output_dict)
        
        if playbook_run_json.get('inputs'):
            sub_playbook_input_dict = {'playbook_name': playbook_name}
            for input_entry in playbook_run_json['inputs']:
                input_dict = json.loads(input_entry)
                for k,v in input_dict.items():
                    sub_playbook_input_dict[k] = v
            process_outputs__data['sub_playbook_inputs'].append(sub_playbook_input_dict)
                
                        
    phantom.debug(f"Final Output:\n{process_outputs__data}")                  
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="process_outputs:data", value=json.dumps(process_outputs__data))

    return


@phantom.playbook_block()
def find_supported_indicator_types(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("find_supported_indicator_types() called")

    ################################################################################
    # Generates a deduplicated list of supported indicator types from matching playbooks.
    ################################################################################

    find_matching_playbooks_data = phantom.collect2(container=container, datapath=["find_matching_playbooks:custom_function_result.data.*.input_spec"])

    find_matching_playbooks_data___input_spec = [item[0] for item in find_matching_playbooks_data]

    find_supported_indicator_types__list = None

    ################################################################################
    ## Custom Code Start
    ################################################################################
    find_supported_indicator_types__list = []
    
    for spec_item in find_matching_playbooks_data___input_spec:
        if spec_item:
            for spec in spec_item:
                for contains_type in spec['contains']:
                    find_supported_indicator_types__list.append(contains_type)
                    
    find_supported_indicator_types__list = list(set(find_supported_indicator_types__list))
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_run_data(key="find_supported_indicator_types:list", value=json.dumps(find_supported_indicator_types__list))

    collect_indicator(container=container)

    return


@phantom.playbook_block()
def collect_indicator(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("collect_indicator() called")

    id_value = container.get("id", None)
    playbook_input_artifact_ids_include = phantom.collect2(container=container, datapath=["playbook_input:artifact_ids_include"])
    playbook_input_indicator_tags_exclude = phantom.collect2(container=container, datapath=["playbook_input:indicator_tags_exclude"])
    playbook_input_indicator_tags_include = phantom.collect2(container=container, datapath=["playbook_input:indicator_tags_include"])
    find_supported_indicator_types__list = json.loads(_ if (_ := phantom.get_run_data(key="find_supported_indicator_types:list")) != "" else "null")  # pylint: disable=used-before-assignment

    playbook_input_artifact_ids_include_values = [item[0] for item in playbook_input_artifact_ids_include]
    playbook_input_indicator_tags_exclude_values = [item[0] for item in playbook_input_indicator_tags_exclude]
    playbook_input_indicator_tags_include_values = [item[0] for item in playbook_input_indicator_tags_include]

    parameters = []

    parameters.append({
        "container": id_value,
        "artifact_ids_include": playbook_input_artifact_ids_include_values,
        "indicator_tags_exclude": playbook_input_indicator_tags_exclude_values,
        "indicator_tags_include": playbook_input_indicator_tags_include_values,
        "indicator_types_exclude": None,
        "indicator_types_include": find_supported_indicator_types__list,
    })

    ################################################################################
    ## Custom Code Start
    ################################################################################

    from itertools import zip_longest

    # overwrite parameters
    parameters = []
    indicator_tags_include = []
    indicator_tags_exclude = []
    #itertools.zip_longest(playbook_input_indicator_types_include, playbook_input_indicator_types_exclude, playbook_input_indicator_tags_include, playbook_input_indicator_tags_exclude)
    for indicator_set in zip_longest(playbook_input_indicator_tags_include, playbook_input_indicator_tags_exclude):
        indicator_tags_include.append(indicator_set[0])
        indicator_tags_exclude.append(indicator_set[1]) 
    
    if playbook_input_artifact_ids_include_values and len(playbook_input_artifact_ids_include_values) > 0 and isinstance(playbook_input_artifact_ids_include_values[0], list):
        artifact_ids_include = [item[0] for item in playbook_input_artifact_ids_include_values if item]
    elif isinstance(playbook_input_artifact_ids_include_values, list):
        artifact_ids_include = [str(item) for item in playbook_input_artifact_ids_include_values if item]
    else:
        artifact_ids_include = []
    parameters.append({
        "container": id_value,
        "indicator_types_include": ', '.join([item for item in find_supported_indicator_types__list if item]),
        "indicator_types_exclude": None,
        "indicator_tags_include": ', '.join([item[0] for item in indicator_tags_include if item]),
        "indicator_tags_exclude": ', '.join([item[0] for item in indicator_tags_exclude if item]),
        "artifact_ids_include": ', '.join(artifact_ids_include),
    })

    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.custom_function(custom_function="community/indicator_collect", parameters=parameters, name="collect_indicator", callback=indicator_decision)

    return


@phantom.playbook_block()
def check_valid_inputs(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug("check_valid_inputs() called")

    ################################################################################
    # Check playbook inputs and produce associated errors
    ################################################################################

    playbook_input_playbook_repo = phantom.collect2(container=container, datapath=["playbook_input:playbook_repo"])
    playbook_input_playbook_tags = phantom.collect2(container=container, datapath=["playbook_input:playbook_tags"])

    playbook_input_playbook_repo_values = [item[0] for item in playbook_input_playbook_repo]
    playbook_input_playbook_tags_values = [item[0] for item in playbook_input_playbook_tags]

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # Checks for presence of "community" as one of the provided repos 
    # as launching input playbooks from "community" could lead to unintended behavior.
    if "community" in playbook_input_playbook_repo_values:
        raise ValueError(
            "Invalid value provided in playbook_input:playbook_repo: 'community'. "
            "Dispatching playbooks from the 'community' repo is not allowed."
        )
    
    # Check for at least 1 playbook_tag
    if not playbook_input_playbook_tags_values or not any(playbook_input_playbook_tags_values):
        raise ValueError("Must provide at least 1 playbook tag value to find available playbooks")
        
    ################################################################################
    ## Custom Code End
    ################################################################################

    find_matching_playbooks(container=container)

    return


@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    output = {
        "verdict": [],
        "sub_playbook_outputs": [],
        "sub_playbook_inputs": [],
        "playbook_run_id_list": [],
        "playbook_id_list": [],
        "playbook_name_list": [],
        "observable": [],
        "markdown_report": [],
    }

    ################################################################################
    ## Custom Code Start
    ################################################################################
    
    # If certain outputs should appear, put those into the End block, but do not 
    # populate them. The process_outputs block will handle passing those outputs 
    # forward if they exist in the child playbooks.
    
    # Overwrite output with outputs generated in process_outputs.
    process_outputs__data = phantom.get_run_data(key="process_outputs:data")
    
    if process_outputs__data: 
        output = json.loads(process_outputs__data)
    
    ################################################################################
    ## Custom Code End
    ################################################################################

    phantom.save_playbook_output_data(output=output)

    return