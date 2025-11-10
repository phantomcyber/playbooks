def string_unix_to_unix(input_data=None, mode=None, **kwargs):
    """
    Encodes or decodes data using UUEncode. Works with both str and bytes.
    
    Args:
        input_data: Input data to encode or decode
        mode: The mode of operation wanted - 'encode' or 'decode'
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: Encoded or decoded result, matching input type
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    import binascii

    def uu_transform(data, mode='encode'):
        """
        UUEncode/UUDecode that supports arbitrary length data.

        Args:
            data (str | bytes): Input to encode or decode.
            mode (str): 'encode' or 'decode'.

        Returns:
            str | bytes: Result with the same type as the input.

        Raises:
            TypeError: For invalid input types.
            ValueError: For invalid mode or decode/encode errors.
        """
        if not isinstance(data, (str, bytes)):
            raise TypeError("Data must be of type str or bytes.")
        if mode not in ('encode', 'decode'):
            raise ValueError("Mode must be 'encode' or 'decode'.")

        is_str = isinstance(data, str)

        if mode == 'encode':
            # Normalize to bytes
            raw = data.encode('utf-8') if is_str else data

            # UU lines are limited to 45 bytes of payload each
            lines = []
            for i in range(0, len(raw), 45):
                chunk = raw[i:i+45]
                # b2a_uu appends a newline; keep it for decode friendliness
                lines.append(binascii.b2a_uu(chunk))

            encoded = b''.join(lines)
            return encoded.decode('ascii') if is_str else encoded

        else:  # decode
            # Split into lines as text or bytes, then decode each UU line
            if is_str:
                lines = data.splitlines()
                decoded_parts = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        decoded_parts.append(binascii.a2b_uu(line.encode('ascii')))
                    except Exception as e:
                        raise ValueError(f"UU decode failed on line '{line}': {e}")
                out = b''.join(decoded_parts)
                # Return same type as input; for str we assume UTF-8 text
                try:
                    return out.decode('utf-8')
                except UnicodeDecodeError as e:
                    raise ValueError(
                        "Decoded bytes are not valid UTF-8. "
                        "Pass bytes to uu_transform to get raw bytes."
                    ) from e
            else:
                lines = data.splitlines()
                decoded_parts = []
                for line in lines:
                    if not line.strip():
                        continue
                    try:
                        decoded_parts.append(binascii.a2b_uu(line))
                    except Exception as e:
                        # Provide context but keep raw exception details
                        raise ValueError(f"UU decode failed on a line: {e}")
                return b''.join(decoded_parts)

    result = uu_transform(input_data, mode)
    outputs = {'result': result}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
