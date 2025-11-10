def string_luhn(input_string=None, **kwargs):
    """
    The Luhn algorithm is a simple checksum formula used to validate various identification numbers, primarily to detect accidental errors like single-digit mistakes or transposed digits during manual data entry. It can be used to determine if a string (numbers) can be potentially represent credit card numbers, IMEI numbers, and other numerical identifiers. 
    
    Args:
        input_string: The string (number) to evaluate with the Luhn algorithm
    
    Returns a JSON-serializable object that implements the configured data paths:
        is_luhn_compliant: The verdict of applying the Luhn algorithm against input_string
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    def is_luhn_valid(number: str) -> bool:
        # Ensure input is only digits
        if not number.isdigit():
            return False
    
        total = 0
        reverse_digits = number[::-1]
    
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            # Double every second digit
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
    
        # Valid if total is divisible by 10
        return total % 10 == 0
    
    try:
        is_luhn_compliant = is_luhn_valid(input_string)
        outputs = {"is_luhn_compliant": is_luhn_compliant}
    except TypeError:
        raise ValueError('input_string must be a string or bytes')
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
