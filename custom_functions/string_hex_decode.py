def string_hex_decode(input_string=None, **kwargs):
    """
    Decodes an hexadecimal string into it's ASCII text representation.
    
    Args:
        input_string: The hexadecimal string to decode
    
    Returns a JSON-serializable object that implements the configured data paths:
        decoded_string: The decoded string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    if not input_string and not isinstance(input_string, str):
        raise ValueError("input_string must be a string")
        
    try:
        cleaned = input_string.strip().replace(" ", "")
        if cleaned.lower().startswith("0x"):
            cleaned = cleaned[2:]
        if len(cleaned) % 2 != 0:
            cleaned = "0" + cleaned
        b = bytes.fromhex(cleaned)
        outputs = {'decoded_string': b.decode("utf-8", errors="replace")}
    except Exception as e:
        raise ValueError(f"Could not decode string {input_string}: {e}")
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
