def mark_evidence(container=None, object_id=None, content_type=None, **kwargs):
    """
    Mark an object as Evidence in a container
    
    Args:
        container (CEF type: phantom container id): Container ID or Container Object
        object_id (CEF type: *): Id of object to be added - artifact id, note id, etc.
        content_type (CEF type: *): The content type of the object to add as evidence which must be one of the following:
                        
                        containerattachment
                        artifact
                        actionrun
                        container
                        note
    
    Returns a JSON-serializable object that implements the configured data paths:
        id (CEF type: *): ID of the evidence item
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    container_id = None
    valid_types = ['containerattachment','artifact','actionrun','container','note']
    
    content_type = content_type.lower()
    
    # Ensure valid content_type: 
    if content_type not in valid_types:
        raise TypeError(f"The content_type '{content_type}' is not a valid content_type")
        
    # Ensure valid container input
    if isinstance(container, dict) and container.get('id'):
        container_id = container['id']
    elif isinstance(container, int):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor an int, so it cannot be used")
    
    # Build json dictionary for requests post
    data = {
        "container_id": container_id,
        "object_id": object_id,
        "content_type": content_type,
        }
    
    # Build url for evidence endpoint
    url = phantom.build_phantom_rest_url('evidence')
    
    # Post data to evidence endpoint
    response = phantom.requests.post(uri=url, json=data, verify=False).json()
    
    # If successful add evidence id to outputs
    # elif evidence already exists print to debug
    # else error out 
    if response.get('success'):
        outputs['id'] = response['id']
    elif response.get('failed') and response.get('message'):
        phantom.debug(f"{content_type} \'{container_id}\' {response['message']}")
    else:
        phantom.error(f"Unknown error in mark_evidence: {response}")
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
