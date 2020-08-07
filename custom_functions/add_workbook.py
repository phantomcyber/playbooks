def add_workbook(container_id=None, workbook=None, **kwargs):
    """
    Function to add a workbook to a container. Provide a container id and a workbook name or id
    
    Args:
        container_id (CEF type: phantom container id): A phantom container id
        workbook (CEF type: *): A workbook name or id
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    if isinstance(workbook,int):
        phantom.debug(phantom.add_workbook(container=container_id, workbook_id=workbook))
        
    elif isinstance(workbook, basestring):
        url = phantom.build_phantom_rest_url('workbook_template') + '?_filter_name="{}"'.format(workbook)
        phantom.debug(url)
        response = phantom.requests.get(url, verify=False).json()
        if response['count'] > 1:
            phantom.debug('Unable to add workbook - more than one ID matches workbook name')
        elif response['data'][0]['id']:
            workbook_id = response['data'][0]['id']
            phantom.debug(phantom.add_workbook(container=container_id, workbook_id=workbook_id))
    
    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
