def extract_email_attachments(vault_id=None, container_id=None, name=None, label=None, severity=None, run_automation=None, extract_rfc822=None, extract_other_attachments=None, **kwargs):
    """
    This function extracts and processes 'message/rfc822' attachments from an email. It stores these attachments in a vault and generates artifacts containing the corresponding vault IDs and file names. This capability is essential for extracting attached emails, file attachments, and ensuring that critical email data is accurately stored and referenced for future use. 
    
    Args:
        vault_id (CEF type: vault id): The ID of the vault containing the email.
        container_id (CEF type: phantom container id): The identifier of the container to which the artifacts will be added.
        name: The name of the new artifact. This parameter is optional and defaults to "Vault Artifact".
        label: The label assigned to the new artifact. This parameter is optional and defaults to "artifact".
        severity: The severity level of the new artifact. This parameter is optional and defaults to "Medium". Acceptable values are "High", "Medium", or "Low".
        run_automation: A boolean value ("true" or "false") indicating whether the new artifact should trigger the execution of any active playbooks associated with the container label. This parameter is optional and defaults to "false".
        extract_rfc822: A boolean value ("true" or "false") indicating whether to extract 'message/rfc822' attachments. This parameter is optional and defaults to "true".
        extract_other_attachments: A boolean value ("true" or "false") indicates whether to extract other types of attachments. This parameter is optional and defaults to "true".
    
    Returns a JSON-serializable object that implements the configured data paths:
        new_vault_id (CEF type: vault id): The unique identifier for the newly created vault item. Each new_vault_id corresponds to an attachment extracted from the email and stored in the vault. 
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import tempfile
    import re
    from email import policy
    from email.parser import BytesParser

    # Input validation
    if not isinstance(vault_id, str):
        raise TypeError("Expected vault_id to be a string")
    if container_id is not None and not isinstance(container_id, int):
        raise TypeError("Expected container_id to be an integer")
    if name is not None and not isinstance(name, str):
        raise TypeError("Expected name to be a string")
    if label is not None and not isinstance(label, str):
        raise TypeError("Expected label to be a string")
    if severity is not None and severity not in {"High", "Medium", "Low"}:
        raise ValueError("Expected severity to be 'High', 'Medium', or 'Low'")
    if run_automation is not None and run_automation.lower() not in {"true", "false"}:
        raise ValueError("Expected run_automation to be 'true' or 'false'")
    if extract_rfc822 is not None and extract_rfc822.lower() not in {"true", "false"}:
        raise ValueError("Expected extract_rfc822 to be 'true' or 'false'")
    if extract_other_attachments is not None and extract_other_attachments.lower() not in {"true", "false"}:
        raise ValueError("Expected extract_other_attachments to be 'true' or 'false'")

    # Convert boolean-like strings to actual boolean values
    def str_to_bool(value, default=False):
        if isinstance(value, str):
            return value.lower() == 'true'
        return default
    
    run_automation = str_to_bool(run_automation, False)
    extract_rfc822 = str_to_bool(extract_rfc822, True)
    extract_other_attachments = str_to_bool(extract_other_attachments, True)
    
    # Set default values for optional string parameters
    name = name or "Vault Artifact"
    label = label or "artifact"
    severity = severity or "Medium"
    
    outputs = []  # Ensure outputs is a list

    phantom.debug("vault_id is {}".format(vault_id))

    # Get vault info
    success, message, vault_info = phantom.vault_info(vault_id=vault_id)
    if not success:
        raise RuntimeError("Failed to get vault info: {}".format(message))

    # Get the first vault info entry
    if not vault_info:
        raise ValueError("No vault information returned for vault_id: {}".format(vault_id))

    vault_info = list(vault_info)[0]
    phantom.debug("vault_info: {}".format(vault_info))

    vault_path = vault_info.get('path')
    phantom.debug("vault_path: {}".format(vault_path))

    if not vault_path:
        raise ValueError("No vault path returned for vault_id: {}, message: {}".format(vault_id, message))

    try:
        phantom.debug("Attempting to open vault file at: {}".format(vault_path))
        with open(vault_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
            phantom.debug("Email message parsed successfully")
        
        # Check if there are any attachments
        attachments = list(msg.iter_attachments())
        if not attachments:
            phantom.debug("No attachments found in the email.")
            outputs.append({"new_vault_id": None})
            return outputs
        
        processed_attachments = False

        # Extract 'message/rfc822' attachments if enabled
        if extract_rfc822:
            for part in attachments:
                if part.get_content_type() == 'message/rfc822':
                    phantom.debug("Processing attachment of type 'message/rfc822'")
                    attached_email = part.get_payload(0)
                    headers = attached_email.as_string()
                    subject_match = re.search(r'Subject: (.*?)\r?\n(?!\s)', headers, re.IGNORECASE | re.DOTALL)
                
                    if subject_match:
                        subject = subject_match.group(1).strip()
                    else:
                        subject = "no_subject"
                        
                    attached_email_name = subject + ".eml"
                    phantom.debug("Subject: {}".format(subject))
                
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                        if isinstance(attached_email, str):
                            phantom.debug("Data is a String")
                            f.write(attached_email.encode('utf-8'))
                        else:
                            phantom.debug("Data is Binary")
                            f.write(attached_email.as_bytes())
                    
                        temp_file_path = f.name
                        phantom.debug("Temporary file created at: {}".format(temp_file_path))
                    
                        success, message, new_vault_id = phantom.vault_add(file_location=temp_file_path, file_name=attached_email_name)
                        if not success:
                            raise RuntimeError("Failed to add file to vault: {}".format(message))
                        
                        phantom.debug("New vault_id: {}".format(new_vault_id))

                        # Retrieve metadata for the new vault item
                        success, message, new_vault_info = phantom.vault_info(vault_id=new_vault_id)
                        if not success:
                            raise RuntimeError("Failed to get vault info for new vault item: {}".format(message))
                        new_metadata = new_vault_info[0].get('metadata', {})
                        cef = {
                            "vaultId": new_vault_id,
                            "file_name": attached_email_name,
                            "fileHashSha256": new_metadata.get('sha256'),
                            "fileHashMd5": new_metadata.get('md5'),
                            "fileHashSha1": new_metadata.get('sha1'),
                            "name": new_vault_info[0].get('name'),
                            "size": new_vault_info[0].get('size'),
                            "path": new_vault_info[0].get('path'),
                            "container": new_vault_info[0].get('container'),
                            "create_time": new_vault_info[0].get('create_time'),
                            "user": new_vault_info[0].get('user')
                        }
                        outputs.append({"new_vault_id": new_vault_id})
                        success, message, artifact_id = phantom.add_artifact(container=container_id, raw_data={}, cef_data=cef, label=label, name=name, severity=severity, run_automation=run_automation)
                        if not success:
                            raise RuntimeError("Failed to add artifact: {}".format(message))

                        phantom.debug("Artifact creation message: {}".format(message))
                        processed_attachments = True
            
        # Extract other attachments if enabled
        if extract_other_attachments:
            for part in attachments:
                if part.get_content_type() != 'message/rfc822':
                    content_type = part.get_content_type()
                    filename = part.get_filename() or 'attachment'
                    phantom.debug(f"Processing attachment of type '{content_type}' with filename '{filename}'")
                    
                    with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
                        f.write(part.get_payload(decode=True))
                        temp_file_path = f.name
                    
                    success, message, new_vault_id = phantom.vault_add(file_location=temp_file_path, file_name=filename)
                    if not success:
                        raise RuntimeError("Failed to add file to vault: {}".format(message))
                    
                    phantom.debug("New vault_id: {}".format(new_vault_id))

                    # Retrieve metadata for the new vault item
                    success, message, new_vault_info = phantom.vault_info(vault_id=new_vault_id)
                    if not success:
                        raise RuntimeError("Failed to get vault info for new vault item: {}".format(message))
                    new_metadata = new_vault_info[0].get('metadata', {})
                    cef = {
                        "vaultId": new_vault_id,
                        "file_name": filename,
                        "fileHashSha256": new_metadata.get('sha256'),
                        "fileHashMd5": new_metadata.get('md5'),
                        "fileHashSha1": new_metadata.get('sha1'),
                        "name": new_vault_info[0].get('name'),
                        "size": new_vault_info[0].get('size'),
                        "path": new_vault_info[0].get('path'),
                        "container": new_vault_info[0].get('container'),
                        "create_time": new_vault_info[0].get('create_time'),
                        "user": new_vault_info[0].get('user')
                    }
                    outputs.append({"new_vault_id": new_vault_id})
                    success, message, artifact_id = phantom.add_artifact(container=container_id, raw_data={}, cef_data=cef, label=label, name=name, severity=severity, run_automation=run_automation)
                    if not success:
                        raise RuntimeError("Failed to add artifact: {}".format(message))

                    phantom.debug("Artifact creation message: {}".format(message))
                    processed_attachments = True

        if not processed_attachments:
            phantom.debug("No applicable attachments processed.")
            outputs.append({"new_vault_id": None})

    except Exception as e:
        phantom.error("Error in email_extract_attachments: {}".format(e))
        raise  # Re-raise the exception after logging it

    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs