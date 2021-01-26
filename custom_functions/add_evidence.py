def add_evidence(container_id=None, object_id=None, content_type=None, **kwargs):
    """
    Custom function implementation of REST API for Evidence
    
    Args:
        container_id (CEF type: phantom container id): Id of the container to which you are adding evidence.
        object_id (CEF type: *): Id of object to be added - artifact id, note id, etc.
        content_type (CEF type: *): The content type of the object to add as evidence. One of the types:
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
    # Ensure content_type is lowercase
    content_type = content_type.lower()
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
    if response.get('success') == 'true':
        outputs['id'] = response['id']
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
