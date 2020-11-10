def add_workbook(container_id=None, workbook=None, check_for_existing_workbook=None, start_workbook=None, **kwargs):
    """
    Function to add a workbook to a container. Provide a container id and a workbook name or id
    
    Args:
        container_id (CEF type: phantom container id): A phantom container id
        workbook (CEF type: *): A workbook name or id
        check_for_existing_workbook (CEF type: *): Check to see if workbook already exists in container before adding.
        start_workbook (CEF type: *): Have automation mark the workbook's first phase as the current phase
    
    Returns a JSON-serializable object that implements the configured data paths:
        
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    existing_templates = []
    
    if check_for_existing_workbook.lower() == 'true':
        phantom.debug('Checking for existing workbook')
        url = phantom.build_phantom_rest_url('container', container_id, 'phases')
        container_data = phantom.requests.get(url, verify=False).json()
        if container_data['count'] > 0:
            phase_names = set([phase_id['name'] for phase_id in container_data['data']])
            existing_templates = []
            for name in phase_names:
                url = phantom.build_phantom_rest_url('workbook_phase_template') + '?_filter_name="{}"'.format(name)
                phase_template_response = phantom.requests.get(url, verify=False).json()
                if phase_template_response['count'] > 0:
                    for phase in phase_template_response['data']:
                        existing_templates.append(phase['template'])
            existing_templates = set(existing_templates)
            
    if isinstance(workbook,int):
        if workbook in existing_templates:
                phantom.debug("Workbook already added to container. Skipping")
        else:
            phantom.debug(phantom.add_workbook(container=container_id, workbook_id=workbook))
            
        if start_workbook.lower() == 'true':
            url = phantom.build_phantom_rest_url('workbook_phase_template') + '?_filter_template="{}"'.format(workbook)
            first_phase = phantom.requests.get(url, verify=False).json()['data'][0]['id']
            phantom.debug(phantom.set_phase(container=container_id, phase=first_phase, trace=False))
        
    elif isinstance(workbook, basestring):
        url = phantom.build_phantom_rest_url('workbook_template') + '?_filter_name="{}"'.format(workbook)
        response = phantom.requests.get(url, verify=False).json()
        if response['count'] > 1:
            phantom.error('Unable to add workbook - more than one ID matches workbook name')
        elif response['data'][0]['id']:
            workbook_id = response['data'][0]['id']
            
            if workbook_id in existing_templates:
                phantom.debug("Workbook already added to container. Skipping")
            else:
                phantom.debug(phantom.add_workbook(container=container_id, workbook_id=workbook_id))
                    
            if start_workbook.lower() == 'true':
                url = phantom.build_phantom_rest_url('workbook_phase_template') + '?_filter_template="{}"'.format(workbook_id)
                phantom.debug(url)
                first_phase = phantom.requests.get(url, verify=False).json()['data'][0]['name']
                url = phantom.build_phantom_rest_url('container', container_id, 'phases') + '?_filter_name="{}"'.format(first_phase)
                existing_phases = phantom.requests.get(url, verify=False).json()
                if existing_phases['count'] > 1:
                    phantom.debug('Cannot set current phase - duplicate phase names exist in container')
                else:
                    phantom.debug(phantom.set_phase(container=container_id, phase=existing_phases['data'][0]['id'], trace=False))

    
    # Write your custom code here...
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
