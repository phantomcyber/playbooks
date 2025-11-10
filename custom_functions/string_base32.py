def string_base32(input_data=None, mode=None, **kwargs):
    """
    Encodes or decodes data using Base32.
    
    Args:
        input_data: Input data to encode or decode.
        mode: The mode of operation to use
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: Encoded or decoded result
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    import base64
    
    def base32_transform(data, mode='encode'):
        """
        Encodes or decodes data using Base32. Works with both str and bytes.

        Args:
           data (str | bytes): Input data to encode or decode.
            mode (str): 'encode' or 'decode'.

        Returns:
            str | bytes: Encoded or decoded result (same type as input).

        Raises:
            TypeError: If input types are invalid.
            ValueError: If mode is not 'encode' or 'decode', or if decoding fails.
        """

        if not isinstance(data, (str, bytes)):
            raise TypeError("Data must be of type str or bytes.")

        if mode not in ('encode', 'decode'):
            raise ValueError("Mode must be either 'encode' or 'decode'.")

        try:
            if mode == 'encode':
                # Convert string to bytes for encoding
                raw_bytes = input_data.encode('utf-8') if isinstance(input_data, str) else input_data
                encoded = base64.b32encode(raw_bytes)
                return encoded.decode('utf-8') if isinstance(input_data, str) else encoded

            else:  # decode mode
                raw_bytes = input_data.encode('utf-8') if isinstance(input_data, str) else data
                decoded = base64.b32decode(raw_bytes)
                return decoded.decode('utf-8') if isinstance(input_data, str) else decoded

        except Exception as e:
            raise ValueError(f"Base32 {mode} failed: {e}")
        
    result = base32_transform(input_data, mode)
    outputs = {'result': result}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
