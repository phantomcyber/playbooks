def indicator_collect(container=None, artifact_ids_include=None, indicator_types_include=None, indicator_types_exclude=None, indicator_tags_include=None, indicator_tags_exclude=None, **kwargs):
    """
    Collect all indicators in a container and separate them by data type. Additional output data paths are created for each data type. Artifact scope is ignored.
    
    Args:
        container (CEF type: phantom container id): The current container
        artifact_ids_include (CEF type: phantom artifact id): Optional parameter to only look for indicator values that occur in the artifacts with these IDs. Must be one of: json serializable list, comma separated integers, or a single integer.
        indicator_types_include: Optional parameter to only include indicators with at least one of the provided types in the output. If left empty, all indicator types will be included except those that are explicitly excluded. Accepts a comma-separated list.
        indicator_types_exclude: Optional parameter to exclude indicators with any of the provided types from the output. Accepts a comma-separated list.
        indicator_tags_include: Optional parameter to only include indicators with at least one of the provided tags in the output. If left empty, tags will be ignored except when they are excluded. Accepts a comma-separated list.
        indicator_tags_exclude: Optional parameter to exclude indicators with any of the provided tags from the output. Accepts a comma-separated list.
    
    Returns a JSON-serializable object that implements the configured data paths:
        all_indicators.*.cef_key
        all_indicators.*.cef_value
        all_indicators.*.data_types
        all_indicators.*.artifact_id
        domain.*.cef_key
        domain.*.cef_value (CEF type: domain)
        domain.*.artifact_id
        file_name.*.cef_key (CEF type: file name)
        file_name.*.cef_value (CEF type: file name)
        file_name.*.artifact_id
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom

    outputs = {'all_indicators': []}
    def check_numeric_list(input_list):
        return (all(isinstance(x, int) for x in input_list) or all(x.isnumeric() for x in input_list))
    
    def include_exclude(indicator_types_include=None, 
                    indicator_types_exclude=None,
                    indicator_tags_include=None,
                    indicator_tags_exclude=None,
                    data_types=None,
                    tags=None):
        
        indicator_types_include = [] if not indicator_types_include else indicator_types_include
        indicator_types_exclude = [] if not indicator_types_exclude else indicator_types_exclude
        indicator_tags_include = [] if not indicator_tags_include else indicator_tags_include
        indicator_tags_exclude = [] if not indicator_tags_exclude else indicator_tags_exclude
        data_types = [] if not data_types else data_types
        tags = [] if not tags else tags

        # exclude indicators with any types in the excluded type list
        if indicator_types_exclude and any(item in indicator_types_exclude for item in data_types):
            return False
        
        # exclude indicators with any tags in the excluded tag list
        if indicator_tags_exclude and any(item in indicator_tags_exclude for item in tags):
            return False
        
        # ignore indicators that do not have any of the included types
        if indicator_types_include and not any(item in indicator_types_include for item in data_types):
            return False

        # ignore indicators that do not have any of the included tags
        if indicator_tags_include and not any(item in indicator_tags_include for item in tags):
            return False

        # use the indicator if all filters were passed
        return True

    # validate container and get ID
    if isinstance(container, dict) and container['id']:
        container_dict = container
        container_id = container['id']
    elif isinstance(container, int):
        rest_container = phantom.requests.get(uri=phantom.build_phantom_rest_url('container', container), verify=False).json()
        if 'id' not in rest_container:
            raise RuntimeError('Failed to find container with id {container}')
        container_dict = rest_container
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor a valid container id, so it cannot be used")

    if indicator_types_include:
        indicator_types_include = [item.strip() for item in indicator_types_include.split(',')]
    if indicator_types_exclude:
        indicator_types_exclude = [item.strip() for item in indicator_types_exclude.split(',')]
    if indicator_tags_include:
        indicator_tags_include = [item.strip() for item in indicator_tags_include.split(',')]
    if indicator_tags_exclude:
        indicator_tags_exclude = [item.strip() for item in indicator_tags_exclude.split(',')]
        
    global_cef_mapping = phantom.requests.get(uri=phantom.build_phantom_rest_url('cef_metadata'), verify=False).json()['cef']
    
    if artifact_ids_include:
        # Try to convert to a valid list
        if isinstance(artifact_ids_include, str) and artifact_ids_include.startswith('[') and artifact_ids_include.endswith('['):
            artifact_ids_include = json.loads(artifact_ids_include)
        elif isinstance(artifact_ids_include, str):
            artifact_ids_include = artifact_ids_include.replace(' ','').split(',')
        
        # Check validity of list
        if not isinstance(artifact_ids_include, list) and not isinstance(artifact_ids_include, int):
            raise TypeError(
                f"Invalid artifact_ids_include entered: '{artifact_ids_include}'. Must be one of: json seriablize, comma separated, or an integer."
            )
        elif isinstance(artifact_ids_include, list) and not check_numeric_list(artifact_ids_include):
            raise ValueError(
                f"Invalid artifact_ids_include entered: '{artifact_ids_include}'. Must be a list of integers."
            )
        
    
    # fetch all artifacts in the container
    artifacts = phantom.requests.get(uri=phantom.build_phantom_rest_url('container', container_id, 'artifacts'), params={'page_size': 0}, verify=False).json()['data']
    
    # build dictionary of cef values with the corresponding indicator data
    cef_dictionary = {}
    for artifact in artifacts:
        artifact_id = artifact['id']
        if (artifact_ids_include and artifact_id in artifact_ids_include) or not artifact_ids_include:

            for cef_key in artifact['cef']:
                cef_value = artifact['cef'][cef_key]
                if str(cef_value) not in cef_dictionary.keys():
                    params = {'indicator_value': cef_value, "_special_contains": True, 'page_size': 1}
                    indicator_data = phantom.requests.get(uri=phantom.build_phantom_rest_url('indicator_by_value'), params=params, verify=False)
                    if indicator_data.status_code == 200:
                        cef_dictionary[str(cef_value)] = indicator_data.json()

    for artifact in artifacts:
        artifact_id = artifact['id']
        if (artifact_ids_include and artifact_id in artifact_ids_include) or not artifact_ids_include:

            for cef_key in artifact['cef']:
                cef_value = artifact['cef'][cef_key]
                data_types = []
                tags = []

                # get all possible cef types from artifact, indicator, and global cef mapping

                if artifact['cef_types'].get(cef_key):
                    data_types += artifact['cef_types'][cef_key]
                if global_cef_mapping.get(cef_key):
                    data_types += global_cef_mapping[cef_key]['contains']
                if str(cef_value) in cef_dictionary and "_special_contains" in cef_dictionary[str(cef_value)]:
                    data_types += [item for item in cef_dictionary[str(cef_value)]["_special_contains"] if item]

                data_types = list(set(data_types))

                # get indicator tags
                if cef_dictionary.get(str(cef_value)):
                    tags = [item for item in cef_dictionary[str(cef_value)]['tags'] if item]

                if include_exclude(
                    indicator_types_include, 
                    indicator_types_exclude, 
                    indicator_tags_include, 
                    indicator_tags_exclude, 
                    data_types, 
                    tags
                ):
                    # store the value in all_indicators and a list of values for each data type
                    outputs['all_indicators'].append({
                        'cef_key': cef_key, 
                        'cef_value': cef_value, 
                        'artifact_id': artifact_id, 
                        'data_types': data_types, 
                        'tags': tags
                    })
                    for data_type in data_types:
                        # outputs will have underscores instead of spaces
                        data_type_escaped = data_type.replace(' ', '_') 
                        if data_type_escaped not in outputs:
                            outputs[data_type_escaped] = []
                        outputs[data_type_escaped].append(
                            {'cef_key': cef_key, 'cef_value': cef_value, 'artifact_id': artifact_id, 'tags': tags}
                        )

    # sort the all_indicators outputs to make them more consistent
    outputs['all_indicators'].sort(key=lambda indicator: str(indicator['cef_value']))

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
