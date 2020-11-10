def update_workbook_task(task_name=None, note_title=None, note_content=None, status=None, owner=None, container_id=None, **kwargs):
    """
    Update a workbook task by task name
    
    Args:
        task_name (CEF type: *): Name of a workbook task (Required)
        note_title (CEF type: *): Note title goes here (Optional)
        note_content (CEF type: *): Body of note goes here (Optional)
        status (CEF type: *): One of: incomplete, in progress, complete (Optional)
        owner (CEF type: *): Owner to assign task to  (Optional)
        container_id (CEF type: phantom container id): ID of Phantom Container (Required)
    
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
                task_is_note_required = task['data']['is_note_required']
                task_count += 1
                task_status = task['data']['status']
                task_notes = task['data']['notes']
                task_owner = task['data']['owner']
                
        if task_count > 1:
            phantom.error('Unable to update workbook task - multiple tasks match criteria: {}'.format(task_count))
        
        elif task_count == 1:
            if task_is_note_required and not note_content and status == 'complete' and len(task_notes) == 0:
                phantom.error('Unable to update workbook task - this task requires a closing note and note_content has "0" as parameter and no notes present')          
            else:
                # Add Note
                if note_content:
                    if note_title:
                        phantom.debug(phantom.add_note(container=container_id, note_type='task', task_id=task_id, title=note_title, content=note_content, note_format='markdown'))
                    else:
                        phantom.debug(phantom.add_note(container=container_id, note_type='task', task_id=task_id, content=note_content, note_format='markdown')[1]) 
                elif note_content:
                    phantom.debug('No note added')

                # Set owner
                if owner:
                    url = phantom.build_phantom_rest_url('workflow_task') + '/{}'.format(task_id)
                    data = {'owner': owner}
                    if phantom.requests.post(url, data=json.dumps(data), verify=False).json()['success']:
                        phantom.debug('Owner set to {}'.format(owner))

                # Set Status
                if status:
                    url = phantom.build_phantom_rest_url('workflow_task') + '/{}'.format(task_id)
                    if status == 'complete' and task_status == 0:
                        data = {'status': 2}
                        # Move to in progress
                        if phantom.requests.post(url, data=json.dumps(data), verify=False).json()['success']:
                            # Then move to close
                            data = {'status': 1}
                            if phantom.requests.post(url, data=json.dumps(data), verify=False).json()['success']:
                                phantom.debug('Task set to "Complete"')
                    elif status == 'in progress' and task_status != 2:
                        data = {'status': 2}
                        # Move to in progress
                        if phantom.requests.post(url, data=json.dumps(data), verify=False).json()['success']:
                            phantom.debug('Task set to "In Progress"')
                    elif status == 'incomplete' and task_status != 0:
                        data = {'status': 0}
                        # Move to incomplete
                        if phantom.requests.post(url, data=json.dumps(data), verify=False).json()['success']:
                            phantom.debug('Task set to "Incomplete"')
                    elif status == 'complete' and task_status != 1:
                        data = {'status': 1}
                        # Move to complete
                        if phantom.requests.post(url, data=json.dumps(data), verify=False).json()['success']:
                            phantom.debug('Task set to "Complete"')
                    else:
                        phantom.debug('Task status unchanged')
        
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
