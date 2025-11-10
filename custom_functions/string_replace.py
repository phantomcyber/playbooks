def string_replace(input_string=None, regex=None, substitution=None, **kwargs):
    """
    Replaces a string characters matched by a regex with a replacement string, similarly to the Splunk replace eval function.
    
    Args:
        input_string: The string to modify
        regex: The regex used to match what to replace
        substitution: The string to use as a replacement for matched characters
    
    Returns a JSON-serializable object that implements the configured data paths:
        output_string: The result of the input_string with matches replaced by the substitution string.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = {}
    
    try:
        output_string = re.sub(rf"{regex}", substitution if substitution is not None else "", input_string)
        #phantom.debug(f"Replaced {regex} with \"{substitution}\" in {input_string}, result: {output_string}")
    except Exception as e:
        raise ValueError(f"An error occured trying to replace a string: {e}")
    
    outputs = {"output_string": output_string}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
