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
    from pathlib import Path
    import zipfile
    
    outputs = {}
    success, message, info = phantom.vault_info(
        vault_id=vault_id,
        container_id=container_id
    )
    
    if not success:
        raise Exception("Could not find file in vault")
    
    extract_path = Path("/opt/phantom/vault/tmp/") / vault_id
    extract_path.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(info[0]["path"]) as f_zip:
        f_zip.extractall(str(extract_path), pwd=pwd.encode())

    for p in extract_path.rglob("*"):
        if p.is_file():
            phantom.vault_add(container=container_id, file_location=str(p), file_name=p.name)

    # Write your custom code here...
    outputs["info"] = info
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
