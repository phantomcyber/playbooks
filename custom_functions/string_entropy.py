def string_entropy(input_string=None, **kwargs):
    """
    Calculates the entropy of a string using Shannon Entropy and provides a normalized score (0.0 - 1.0).
    
    Args:
        input_string: The string to evaluate
    
    Returns a JSON-serializable object that implements the configured data paths:
        shannon_entropy: The score calculated using Shannon Entropy
        normalized_entropy: The score normalized entropy score (0.0 - 1.0)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    import math
    from collections import Counter
    
    def shannon_entropy(input_string: str) -> float:
        if not input_string:
            return 0.0
        counts = Counter(input_string)
        length = len(input_string)
        probs = [count / length for count in counts.values()]
        return -sum(p * math.log2(p) for p in probs)
    
    def normalized_entropy(input_string: str) -> float:
        if not input_string:
            return 0.0
        h = shannon_entropy(input_string)
        max_entropy = math.log2(len(set(input_string)))
        return h / max_entropy if max_entropy > 0 else 0.0
    
    outputs = {"shannon_entropy": shannon_entropy(input_string), "normalized_entropy": normalized_entropy(input_string)}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
