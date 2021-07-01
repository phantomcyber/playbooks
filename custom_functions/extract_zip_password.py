def extract_zip_password(vault_id=None, container_id=None, pwd=None, **kwargs):
    """
    Args:
        vault_id (CEF type: vault id): Vault ID
        container_id (CEF type: *)
        pwd
    
    Returns a JSON-serializable object that implements the configured data paths:
        info
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import os
    
    import zipfile
    outputs = {}
    success, message, info = phantom.vault_info(
        vault_id=vault_id,
        container_id=container_id
    )
    
    extract_path = "/opt/phantom/vault/tmp/{}".format(vault_id)
    if not os.path.exists(extract_path):
        os.makedirs(extract_path)


    with zipfile.ZipFile(info[0]["path"]) as file:
        file.extractall(extract_path, pwd=pwd)

    for f in os.listdir(extract_path):
            if "." in f:
                phantom.vault_add(container=container_id, file_location=extract_path + "/" + f)


    # Write your custom code here...
    outputs["info"] = info
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
