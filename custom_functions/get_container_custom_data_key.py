def get_container_custom_data_key(container_id=None, custom_key=None, **kwargs):
    """
    This custom function retrieves a specific key-value pair from a container's custom_fields
    
    Args:
        container_id: Container ID
        custom_key: The name of the custom field to retrieve
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.custom_key_value: Returns [{"custom_key_value": "<value>"}]
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    custom_key_value = None
    container = None
    
    container=phantom.get_container(container_id)
    
    phantom.debug(custom_key)
    custom_fields = container.get("custom_fields", None)
    phantom.debug("custom fields in container")
    phantom.debug(custom_fields)
    
    if custom_fields:
        custom_key_value = custom_fields.get(custom_key, None)
        phantom.debug("key is {}, value is {}".format(custom_key,custom_key_value))
    else:
        phantom.error("Container Data field is not intialized")
    
    if custom_key_value:
        outputs = [{"custom_key_value":custom_key_value}]
    else:
        phantom.error("The field:{} has not been intialized in Container {}".format(custom_key, container_id))
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
