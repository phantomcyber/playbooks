def container_update(container_input=None, name=None, description=None, label=None, owner=None, sensitivity=None, severity=None, status=None, tags=None, input_json=None, **kwargs):
    """
    Allows updating various attributes of a container in a single custom function. Any attributes of a container not listed can be updated via the input_json parameter. 
    
    Args:
        container_input (CEF type: phantom container id): Supports a container id or container dictionary
        name: Optional parameter to change container name
        description: Optional parameter to change the container description
        label (CEF type: phantom container label): Optional parameter to change the container label
        owner: Optional parameter to change the container owner. Accepts a username or role name or keyword "current" to set the currently running playbook user as the owner.
        sensitivity: Optional parameter to change the container sensitivity. 
        severity: Optional parameter to change the container severity.
        status: Optional parameter to change the container status.
        tags: Optional parameter to change the container tags. Must be in the format of a comma separated list.
        input_json: Optional parameter to modify any extra attributes of a container. Input_json will be merged with other inputs. In the event of a conflict, input_json will take precedence.
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    update_dict = {}
    
    if isinstance(container_input, int):
        container = phantom.get_container(container_input)
    elif isinstance(container_input, dict):
        container = container_input
    else:
        raise TypeError("container_input is neither a int or a dictionary")
    
    if name:
        update_dict['name'] = name
    if description:
        update_dict['description'] = description
    if label:
        update_dict['label'] = label
    if owner:
        # If keyword 'current' entered then translate effective_user id to a username
        if owner.lower() == 'current':
            effective_user_id = phantom.get_effective_user()
            url = phantom.build_phantom_rest_url('ph_user', effective_user_id)
            owner = phantom.requests.get(url, verify=False).json().get('username')
        update_dict['owner_name'] = owner
    if sensitivity:
        update_dict['sensitivity'] = sensitivity
    if severity:
        update_dict['severity'] = severity
    if status:
        update_dict['status'] = status
    if tags:
        tags = tags.replace(" ", "").split(",")
        update_dict['tags'] = tags
    if input_json:
        json_dict = json.loads(input_json)
        # Merge dictionaries
        update_dict = {**update_dict, **json_dict}
    
    if update_dict:
        phantom.debug('Updating container {0} with the following information: "{1}"'.format(container['id'], update_dict))
        phantom.update(container, update_dict)
    else:
        phantom.debug("Valid container entered but no container changes provided.")
        
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
