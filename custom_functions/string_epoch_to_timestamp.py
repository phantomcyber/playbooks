def string_epoch_to_timestamp(input_epoch=None, **kwargs):
    """
    Convert an epoch time to various human readable formats.  This custom function only supports epoch values without a fractional part.
    
    Args:
        input_epoch: The epoch value to convert
    
    Returns a JSON-serializable object that implements the configured data paths:
        output_iso8601
        output_rfc2822
        output_readable
        output_date
        output_time
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    from datetime import datetime, timezone
    
    if not input_epoch and (not isinstance(input_epoch, int) and not isinstance(input_epoch, str)):
        raise ValueError("input_string must be a str or int")
    
    try:
        int_epoch = int(input_epoch)
    except Exception as e:
        raise ValueError(f"Could not convert string {input_epoch} to integer")
        
    dt_utc = datetime.fromtimestamp(int_epoch, tz=timezone.utc)
    phantom.debug(dt_utc)
    
    # 1. ISO-8601 (standardized, includes timezone)
    iso8601 = dt_utc.isoformat()

    # 2. RFC 2822 (email-style)
    rfc2822 = dt_utc.strftime("%a, %d %b %Y %H:%M:%S %z")

    # 3. Human readable date and time
    readable = dt_utc.strftime("%Y-%m-%d %H:%M:%S")

    # 4. Just date
    just_date = dt_utc.strftime("%Y-%m-%d")

    # 5. Just time
    just_time = dt_utc.strftime("%H:%M:%S")

    outputs = {"output_iso8601": iso8601, "output_rfc2822": rfc2822, "output_readable": readable, "output_date": just_date, "output_time": just_time}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
