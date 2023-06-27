def vault_list(container_id=None, vault_id=None, file_name=None, **kwargs):
    """
    List all of the vault items based on the provided criteria such as a vault id, container id, and file name. If no inputs provided, it will default to current container. Returns a list of items. May return more variables than listed in outputs.
    
    Args:
        container_id (CEF type: phantom container id): Optional parameter to filter vault items from this specific container. Defaults to current container if no inputs provided.
        vault_id (CEF type: vault id): Optional parameter to filter vault items matching this vault ID. Defaults to None.
        file_name (CEF type: *): Optional parameter to filter vault items matching this file name. Defaults to None.
    
    Returns a JSON-serializable object that implements the configured data paths:
        container_name: Name of a container
        file_name: Name of the file
        aka: Aliases for the file name
        metadata: Information about the file such as sha256 and contains type
        metadata.contains: File type
        container_id: ID of a container
        create_time: When the file was created on the system
        vault_id: The ID of the vault item
        path: The path on the SOAR disk where the file resides
        size: Size of the file in bytes
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    # Input checking section 
    if not container_id and not vault_id and not file_name:
        container_id = phantom.get_current_container_id_()
    if vault_id and not isinstance(vault_id, str):
        raise TypeError(f"vault_id must be a string. A {type(vault_id)} was provided.")
    if container_id:
        if isinstance(container_id, str):
            try:
                container_id = int(container_id)
            except ValueError:
                raise ValueError(f"container_id must be an integer or integer-type string. A non-integer string was provided.") from None
        if not isinstance(container_id, int):
            raise TypeError(f"container_id must be an integer or integer-type string. A {type(container_id)} was provided.")
    if file_name and not isinstance(file_name, str):
        raise TypeError(f"file_name must be a string. A {type(file_name)} was provided.")
    # End input checking section
    
    success, message, info = phantom.vault_info(container_id=container_id, vault_id=vault_id, file_name=file_name)
    if success:
        for item in info:
            item['container_name'] = item.pop('container')
            item['file_name'] = item.pop('name')
            outputs.append(item)
    else:
        phantom.debug("No vault items found for criteria provided")
        
    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
