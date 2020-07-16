def list_filter_by_regex(input_list=None, input_regex=None, input_action=None, **kwargs):
    """
    Filter values in a list against a regex and drop/keep matches, depending on the action parameter.

    Args:
        input_list (CEF type: *): A list of items to filter
        input_regex (CEF type: *): A regex to use to filter items out
        input_action (CEF type: *): Determines whether matched items are dropped or kept

    Returns a JSON-serializable object that implements the configured data paths:
        *.item (CEF type: *): a return item for each value that did not need to be filtered out
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re

    # this only works on lists, so print a warning and return None if the input is not a list
    if not isinstance(input_list, list):
        phantom.debug("unable to process because the input is not a list")
        return

    if input_action not in ("drop","keep"):
        phantom.debug("unable to process because the input action is not 'drop' or 'keep'")
        return

    # iterate through the items in the list and append each non-falsy one as its own dictionary
    outputs = []
    for item in input_list:
        if item:
            if re.match(str(input_regex), str(item)):
                if input_action == "keep":
                    outputs.append({"item": item})
            else:
                if input_action == "drop":
                    outputs.append({"item": item})

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
