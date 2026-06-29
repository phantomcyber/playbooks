def set_container_custom_data_dey_value(container_id=None, custom_key=None, custom_value=None, **kwargs):
    """
    This custom function sets/updates a key-value pair in a container's custom_fields.
    
    Args:
        container_id: Container ID
        custom_key: The name of the custom field to set
        custom_value: The value to store
    
    Returns a JSON-serializable object that implements the configured data paths:
        custom_key: Returns
            {
              "<custom_key>": "<custom_value>",
              "Container_Id": "<container_id>"
            }
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    phantom.debug(custom_value)
    phantom.debug(custom_key)
    container=phantom.get_container(container_id)
    #phantom.debug(container)
    container_data = container.get('custom_fields',{})
    container_data[custom_key] = custom_value
    
    phantom.debug(container_data)
    success, message = phantom.update(container, { "custom_fields": container_data})
    
    outputs={custom_key:custom_value,"Container_Id":container_id}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
