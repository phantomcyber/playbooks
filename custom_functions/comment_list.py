def comment_list(container=None, **kwargs):
    """
    Lists all of the comments from a single container.  Defaults to current container if no container ID provided. There may be additional outputs not listed.
    
    Args:
        container (CEF type: phantom container id): (Optional) A container ID or container object. Defaults to current container if no container ID provided.
    
    Returns a JSON-serializable object that implements the configured data paths:
        id: Comment ID. E.g. 1
        comment: Comment text. E.g. "This is my comment"
        container: ID of container. E.g. 54
        time: A timestamp. E..g. "2023-09-13T13:52:39.009957Z"
        create_time: A timestamp when the comment was created. E.g. "2023-09-13T13:52:39.009957Z"
        user: User ID of the user that created comment. E.g. 3
        mentions: A list of mentions in the comment. E.g. [
            {
            "id": 1,
            "name": "Administrator",
            "type": "role",
            "indices": [
            13
            ],
            "display_name": "Administrator"
            }]
        mentions.id: ID of the person or role mentioned. E.g. 1
        mentions.name: Name of the person or role mentioned. E.g. "Administrator"
        mentions.type: Type of entity that was mentioned. E.g. "role" or "user"
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    # validate container and get ID
    if isinstance(container, dict) and container['id']:
        container_id = container['id']
    elif not container:
        container_id = phantom.get_current_container_id_()
    elif isinstance(container, int):
        container_id = container
    else:
        raise TypeError("The input 'container' is neither a container dictionary nor a valid container id, so it cannot be used")
    
    comment_url = phantom.build_phantom_rest_url('container', container_id, 'comments') + '?page_size=0'
    try:
        comment_resp_json = phantom.requests.get(comment_url, verify=False).json()
        if comment_resp_json.get('count', 0) > 0:
            outputs = comment_resp_json['data']
        else:
            phantom.debug("No comments found for the provided container.")
    except Exception as e:
        raise RuntimeError(f"Unable to retrieve container data for provided container {container_id}. Error: {e}") from None
        
        
    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
