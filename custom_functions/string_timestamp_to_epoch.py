def string_timestamp_to_epoch(input_string=None, time_format=None, **kwargs):
    """
    Converts an arbitrary string to an epoch value using the specified format to parse the string (in a similar way to strptime)
    
    Args:
        input_string: The date/time value to convert to epoch
        time_format: The time format (strptime style) to use in parsing the input_string value supplied
    
    Returns a JSON-serializable object that implements the configured data paths:
        output_epoch: The converted input_string in epoch format
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    from datetime import datetime, timezone

    def parse_to_epoch(date_str: str, fmt: str) -> float:
        """
        Parse a datetime string with a format into an epoch time (UTC).
        - If no timezone is in the string, assume UTC.
        """
        try:
            dt = datetime.strptime(date_str, fmt)
        except ValueError as e:
            raise ValueError(f"Could not parse datetime: {e}")

        # If parsed datetime has no tzinfo, assume UTC
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt.timestamp()

    if not isinstance(input_string, str) or not input_string.strip():
        raise ValueError("input_string must be a non-empty string")
    if not isinstance(time_format, str) or not time_format.strip():
        raise ValueError("time_format must be a non-empty string")
    
    output_epoch = parse_to_epoch(input_string, time_format)
    outputs = {"output_epoch": output_epoch}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
