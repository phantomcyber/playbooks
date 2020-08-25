def extract_email(origEmail=None, **kwargs):
    """
    Written by @stboch
    Provide Any email in either format `Name' <email@address.com> or <email@address.com>
    
    Args:
        origEmail (CEF type: email): Provide Any email in either format `Name' <email@address.com> or <email@address.com>
    
    Returns a JSON-serializable object that implements the configured data paths:
        email (CEF type: email): Extracted Email
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    import re
    regex = "([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,4})"
    
    m = re.search(regex,origEmail)
    if m:
        outputs["email"] = m.group(1).strip()
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
