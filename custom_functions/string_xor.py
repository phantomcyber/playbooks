def string_xor(input_data=None, key=None, **kwargs):
    """
    Applies XOR operation on a string or bytes object using the given key.
    
    Args:
        input_data: The input data to encode or decode.
        key: The XOR key. Must be a single byte (0–255) or one-character string.
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: The XORed result, matching the input type.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    
    def xor_data(data, key):
        """
        Applies XOR operation on a string or bytes object using the given key.

        Args:
            data (str | bytes): The input data to encode or decode.
            key (int | bytes | str): The XOR key. Must be a single byte (0–255) or one-character string.

        Returns:
            str | bytes: The XORed result, matching the input type.

        Raises:
            TypeError: If inputs are of invalid types.
            ValueError: If the key is out of range or not a single byte.
        """

        # --- Validate key ---
        if isinstance(key, str):
            if len(key) != 1:
                raise ValueError("Key must be a single character string.")
            key = ord(key)
        elif isinstance(key, bytes):
            if len(key) != 1:
                raise ValueError("Key must be a single byte.")
            key = key[0]
        elif isinstance(key, int):
            if not (0 <= key <= 255):
                raise ValueError("Integer key must be between 0 and 255.")
        else:
            raise TypeError("Key must be of type int, str, or bytes.")

        # --- Handle data types ---
        if isinstance(data, str):
            result = ''.join(chr(ord(ch) ^ key) for ch in data)
        elif isinstance(data, bytes):
            result = bytes([b ^ key for b in data])
        else:
            raise TypeError("Data must be of type str or bytes.")

        return result
        
    result = xor_data(input_data, key)
    outputs = {'result': result}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
