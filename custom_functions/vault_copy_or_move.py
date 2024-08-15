def vault_copy_or_move(source_container_id=None, target_container_id=None, vault_id_list=None, move=None, **kwargs):
    """
    Copies or moves one vault item from one container to another
    
    Args:
        source_container_id (CEF type: phantom container id): Optional variable to specify the source container ID. By default, it will use the container from the running playbook.
        target_container_id (CEF type: phantom container id): Required variable to specify where the vault item should be transferred.
        vault_id_list (CEF type: vault id): A list of vault items to copy to a target container.
        move: Optional variable to specify if the file should be moved or copied. If Move is set to true, the file will be deleted from the source_container_id after copied. Defaults to False. (If ran by an automation user, requires the automation user to have delete container privileges.)
    
    Returns a JSON-serializable object that implements the configured data paths:
        vault_id: The vault ID that was operated on.
        status: One of: 'failed,' 'copied,' or 'moved.'
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = []
    
    # Input checking section 
    if not source_container_id:
        source_container_id = phantom.get_current_container_id_()
    if isinstance(source_container_id, str):
        try:
            source_container_id = int(source_container_id)
        except ValueError:
            raise ValueError(f"source_container_id must be an integer or integer-type string.") from None
    if isinstance(target_container_id, str):
        try:
            target_container_id = int(target_container_id)
        except ValueError:
            raise ValueError(f"target_container_id must be an integer or integer-type string.") from None
    if not target_container_id:
        raise RuntimeError("Must provide a target_container_id")
    if not vault_id_list:
        raise RuntimeError("Must provide a vault_id_list")
    if isinstance(move, str):
        if move.lower().strip() == 'false':
            move = False
        if move.lower().strip() == 'true':
            move = True
    if not move:
        move = False
    # end Input checking
    
    for vault_id in vault_id_list:
        success, message_info, vault_info = phantom.vault_info(container_id=source_container_id, vault_id=vault_id)
        temp_dict = {'vault_id': vault_id}
        if success:
            vault_path = vault_info[0]['path']
            vault_name = vault_info[0]['name']
            vault_add_success, message_add, _ = phantom.vault_add(container=target_container_id, file_location=vault_path, file_name=vault_name)
            if vault_add_success:
                phantom.debug(f"Successfully ccopied {vault_id} to {target_container_id}")
                temp_dict['status'] = 'copied'
                if move:
                    vault_del_success, message_del, _ = phantom.vault_delete(vault_id=vault_id, container_id=source_container_id)
                    if vault_del_success:
                        phantom.debug(f"Successfully deleted {vault_id} from {source_container_id}")
                        temp_dict['status'] = 'moved'
                    else:
                        phantom.debug(f"Failed to delete {vault_id} from {source_container_id}: '{message_del}'")
            else:
                phantom.debug(f"Failed to copy {vault_id} to {target_container_id}: '{message_add}'")
        else:
            phantom.debug(f"Failed to find {vault_id}: '{message_info}'")
            temp_dict['status'] = 'failed'
        outputs.append(temp_dict)
                

    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
