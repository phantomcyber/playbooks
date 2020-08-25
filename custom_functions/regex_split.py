def regex_split(regex=None, origData=None, **kwargs):
    """
    Split using regex, for multiple sets of data regex and string expected to be paired.
    
    Args:
        regex: Enter regex to split by
        origData: String to Split
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: List of Strings
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    # Write your custom code here...
    import re
    
    regex.replace('\\\\','\\')
    rex = re.split(regex,origData)
    phantom.debug("Split Results: {}".format(rex))
    
    outputs["result"] = rex
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
