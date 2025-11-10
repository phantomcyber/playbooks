def string_caesar_shift(input_string=None, shift=None, mode=None, alphabet=None, **kwargs):
    """
    Encrypts or decrypts text or bytes using a Caesar shift cipher.
    
    Args:
        input_string: The input to process
        shift: The shift amount (positive or negative)
        mode: The operation to perform
        alphabet: Custom alphabet. Defaults to A–Z + a–z. For example, to use the Cyrillic Alphabet, that would be: АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ
    
    Returns a JSON-serializable object that implements the configured data paths:
        result: The encoded/decoded value
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    # Write your custom code here...
    def caesar_cipher(data, shift=3, mode='encode', alphabet=None):
        """
        Encodes or decodes text or bytes using a Caesar shift cipher.
        Supports custom alphabets and arbitrary Unicode characters.

        Args:
            data (str | bytes): Input data to encode or decode.
            shift (int): Shift amount (positive or negative).
            mode (str): 'encode' or 'decode'.
            alphabet (str, optional): Custom alphabet. Defaults to A–Z + a–z.

        Returns:
            str | bytes: Result matching the input type.

        Raises:
            TypeError: For invalid data types.
            ValueError: For invalid mode or empty alphabet.
        """
        if not isinstance(data, (str, bytes)):
            raise TypeError("Data must be of type str or bytes.")
        if not isinstance(shift, int):
            raise TypeError("Shift must be an integer.")
        if mode not in ('encode', 'decode'):
            raise ValueError("Mode must be 'encode' or 'decode'.")

        # Default alphabet: English uppercase + lowercase letters
        if alphabet is None:
            alphabet = (
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
            )

        if not isinstance(alphabet, str) or len(alphabet) == 0:
            raise ValueError("Alphabet must be a non-empty string.")

        is_str = isinstance(data, str)
        text = data if is_str else data.decode('latin1')

        # Handle mode (reverse shift for decode)
        shift = shift % len(alphabet)
        if mode == 'decode':
            shift = -shift

        # Build translation map
        shifted = alphabet[shift:] + alphabet[:shift]
        trans_table = str.maketrans(alphabet, shifted)

        # Apply shift, leaving characters not in alphabet unchanged
        result = text.translate(trans_table)

        return result if is_str else result.encode('latin1')

    result = caesar_cipher(input_string, shift, mode)
    outputs = {"result": result}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
