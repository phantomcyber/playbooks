def regex_match(input_string=None, regex=None, **kwargs):
    """
    Use a regular expression with capture group(s) to extract strings from the input_string.
    
    
    Args:
        input_string (CEF type: *): The input string to filter using regex
        regex: The regular expression with capture group
    
    Returns a JSON-serializable object that implements the configured data paths:
        *.capture1: Regex capture group 1
        *.capture2: Regex capture group 2
        *.capture3: Regex capture group 3
        *.capture4: Regex capture group 4
        *.capture5: Regex capture group 5
        *.capture6: Regex capture group 6
        *.capture7: Regex capture group 7
        *.capture8: Regex capture group 8
        *.capture9: Regex capture group 9
        *.capture10: Regex capture group 10
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re
    
    outputs = []
    
    if regex and input_string:
        regex = str(regex)
        if '(' in regex and ')' in regex:
            for index, value in enumerate(re.match(regex, input_string).groups()):
                outputs.append({f"capture{index + 1}": f"{value}"})
        else:
            raise ValueError("missing a capture group in regex")
    else:
        raise ValueError("missing a required value for regex or input_string")
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
