def mark_evidence(container=None, input_object=None, content_type=None, **kwargs):
    """
    Mark an object as Evidence in a container
    
    Args:
        container (CEF type: phantom container id): Container ID or Container Object
        input_object (CEF type: *): The object to marked as evidence. This could be a vault_id, artifact_id, note_id, or if the previous playbook block is an action then "keyword_argument:results" can be used with the content_type "actionrun".
        content_type (CEF type: *): The content type of the object to add as evidence which must be one of the following:
                        
                        vault_id
                        artifact
                        actionrun
                        container_id
                        note
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.id (CEF type: *): ID of the evidence item
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    container_id = None
    data = []
    valid_types = ['vault_id','artifact','actionrun','container_id','note']
    
    # Ensure valid content_type: 
    if content_type.lower() not in valid_types:
        raise TypeError(f"The content_type '{content_type}' is not a valid content_type")
    
    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        container_id = container['id']
    elif isinstance(container, int):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # If content added is type 'action run',
    # then iterate through an input object that is a results object,
    # and append the action_run_id's to data
    if isinstance(input_object, list) and content_type.lower() == 'actionrun':
        for action_result in input_object:
            if action_result.get('action_run_id'):
                data.append({
                    "container_id": container_id,
                    "object_id": action_result['action_run_id'],
                    "content_type": content_type,
                })
        # If data is still an empty list after for loop, 
        # it indicates that the input_object was not a valid results object
        if not data:
            raise TypeError("The input for 'input_object' is not a valid integer or supported object.")
            
    # If vault_id was entered, check to see if user already entered a vault integer
    # else if user entered a hash vault_id, attempt to translate to a vault integer            
    elif input_object and content_type.lower() == 'vault_id':
        if isinstance(input_object, int):
            content_type = "containerattachment"
        else:
            success, message, info = phantom.vault_info(vault_id=input_object)
            if success == False:
                raise RuntimeError(f"Invalid vault_id: {message}")
            else:
                input_object = info[0]['id']    
                content_type = "containerattachment"
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": content_type,
            }]
    # If 'container_id' was entered, the content_type needs to be set to 'container'.
    # Phantom does not allow a literal input of 'container' so thus 'container_id is used.
    elif isinstance(input_object, int) and content_type.lower() == 'container_id':
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": 'container',
            }]  
    # If input_object is an integer, it is assumed that its a valid input_object
    elif isinstance(input_object, int):
        data = [{
            "container_id": container_id,
            "object_id": input_object,
            "content_type": content_type,
            }]    
    else:
        raise TypeError(f"The input_object is not a valid integer or supported object. Type '{type(input_object)}'")
    
    # Build url for evidence endpoint
    url = phantom.build_phantom_rest_url('evidence')
    
    # Post data to evidence endpoint
    for item in data:
        response = phantom.requests.post(uri=url, json=item, verify=False).json()

        # If successful add evidence id to outputs
        # elif evidence already exists print to debug
        # else error out 
        if response.get('success'):
            outputs.append({'id': response['id']})
        elif response.get('failed') and response.get('message') == 'Already added to Evidence.':
            phantom.debug(f"{content_type} \'{container_id}\' {response['message']}")
        else:
            raise RuntimeError(f"Unable to add evidence: {response}")

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
