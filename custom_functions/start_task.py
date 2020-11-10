def start_task(container_id=None, task_name=None, **kwargs):
    """
    Marks a workbook task as in_progress based on workbook name
    
    Args:
        container_id (CEF type: phantom container id): Phantom Container ID
        task_name (CEF type: *): Name of a Workbook Task
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    if task_name:
        task_list = phantom.get_tasks(container_id)
        task_count = 0
        for task in task_list:
            if task_name == task['data']['name']:
                task_id = task['data']['id']
            
    url = phantom.build_phantom_rest_url('workflow_task') + '/{}'.format(task_id)
    data = {'status': 2}
    if phantom.requests.post(url, data=json.dumps(data), verify=False).json()['success']:
        phantom.debug('Task set to "In Progress"')
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
