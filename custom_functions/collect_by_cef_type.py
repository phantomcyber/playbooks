def collect_by_cef_type(container=None, data_types=None, tags=None, **kwargs):
    """
    Collect all artifact values that match the desired CEF data types, such as "ip", "url", "sha1", or "all". Optionally also filter for artifacts that have the specified tags. Custom CEF types are not supported.
    
    Args:
        container (CEF type: phantom container id): Container ID or container object.
        data_types: The CEF data type to collect values for. This could be a single string or a comma separated list such as "hash,filehash,file_hash". The special value "all" can also be used to collect all field values from all artifacts.
        tags: If tags are provided, only return fields from artifacts that have all of the provided tags. This could be an individual tag or a comma separated list.
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.artifact_value (CEF type: *): The value of the field with the matching CEF data type.
        *.artifact_id (CEF type: phantom artifact id): ID of the artifact that contains the value.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import traceback

    # these are the default field names for each CEF type
    DATA_TYPES_TO_FIELD_NAMES = {
        "ip": [
            "destinationAddress",
            "destinationTranslatedAddress",
            "deviceAddress",
            "deviceTranslatedAddress",
            "dst",
            "dvc",
            "sourceAddress",
            "sourceTranslatedAddress",
            "src"
        ],
        "domain": [
            "destinationDnsDomain",
            "deviceDnsDomain",
            "dntdom",
            "sntdom",
            "sourceDnsDomain"
        ],
        "host name": [
            "destinationHostName",
            "deviceHostname",
            "dhost",
            "dvchost",
            "shost",
            "sourceHostName"
        ],
        "mac address": [
            "destinationMacAddress",
            "deviceMacAddress",
            "dmac",
            "smac",
            "sourceMacAddress"
        ],
        "port": [
            "destinationPort",
            "destinationTranslatedPort",
            "dpt",
            "sourcePort",
            "sourceTranslatedPort",
            "spt"
        ],
        "process name": [
            "destinationProcessName",
            "destinationServiceName",
            "deviceProcessName",
            "dproc"
        ],
        "user name": [
            "destinationUserName",
            "duser",
            "sourceUserName",
            "suser"
        ],
        "hash": [
            "fileHash",
            "oldfileHash"
        ],
        "md5": [
            "fileHashMd5"
        ],
        "sha1": [
            "fileHashSha1"
        ],
        "sha256": [
            "fileHashSha256"
        ],
        "sha512": [
            "fileHashSha512"
        ],
        "file name": [
            "fileName",
            "fname",
            "oldfileName"
        ],
        "file path": [
            "filePath",
            "oldfilePath"
        ],
        "url": [
            "requestURL"
        ],
        "vault id": [
            "vaultId"
        ]
    }

    # validate container and get ID
    if isinstance(container, dict) and container['id']:
        container_id = container['id']
    elif isinstance(container, int):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # validate the data_types input
    if not data_types or not isinstance(data_types, str):
        raise ValueError("The input 'data_types' must exist and must be a string")
    # if data_types has a comma, split it and treat it as a list
    elif "," in data_types:
        data_types = [item.strip() for item in data_types.split(",")]
    # else it must be a single data type
    else:
        data_types = [data_types]
    
    # split tags if it contains commas or use as-is
    if not tags:
        tags = []
    # if tags has a comma, split it and treat it as a list
    elif tags and "," in tags:
        tags = [item.strip() for item in tags.split(",")]
    # if there is no comma, treat it as a single tag
    else:
        tags = [tags]

    # collect all the artifacts in the container
    artifacts = phantom.requests.get(uri=phantom.build_phantom_rest_url('container', container_id, 'artifacts'), params={'page_size': 0}, verify=False).json()['data']

    # find the cef field names associated with the cef data types we are looking for
    field_names = []
    for data_type in data_types:
        if data_type in DATA_TYPES_TO_FIELD_NAMES:
            field_names += DATA_TYPES_TO_FIELD_NAMES[data_type]

    # deduplicate field names
    field_names = list(set(field_names))

    outputs = []
    for artifact in artifacts:
        # if any tags are provided, make sure each provided tag is in the artifact's tags
        if tags:
            if not set(tags).issubset(set(artifact['tags'])):
                continue
        # "all" is a special value to collect every value from every artifact
        if data_types == ['all']:
            for cef_key in artifact['cef']:
                new_output = {'artifact_value': artifact['cef'][cef_key], 'artifact_id': artifact['id']}
                if new_output not in outputs:
                    outputs.append(new_output)
            continue
        
        
        # cef data types can also be explicitly included in artifact metadata, so also make a temporary lookup dictionary for each artifact and append the cef_types from that artifact
        artifact_field_names = field_names.copy()
        for field in artifact['cef_types']:
            for data_type in data_types:
                if data_type in artifact['cef_types'][field]:
                    artifact_field_names.append(field)
        for field_name in artifact_field_names:
            if field_name in artifact['cef']:
                new_output = {'artifact_value': artifact['cef'][field_name], 'artifact_id': artifact['id']}
                if new_output not in outputs:
                    outputs.append(new_output)

    phantom.debug("collect_by_cef_type output:\n{}".format(outputs))

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
