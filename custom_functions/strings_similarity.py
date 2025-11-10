def strings_similarity(input_string1=None, input_string2=None, **kwargs):
    """
    Computes the similarity between two strings using Levenshtein distance.
    
    Args:
        input_string1: The first string to compare
        input_string2: The second string to compare
    
    Returns a JSON-serializable object that implements the configured data paths:
        levenshtein_distance: The Levenshtein distance score calculated between input_string1 and input_string2
        similarity_score: The similarity score calculated between input_string1 and input_string2 (0.0 - 1.0)
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    
    outputs = {}
    
    def levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            s1, s2 = s2, s1  # ensure s1 is the longer string

        previous = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1, 1):
            current = [i]
            for j, c2 in enumerate(s2, 1):
                insertions = previous[j] + 1
                deletions = current[j - 1] + 1
                substitutions = previous[j - 1] + (c1 != c2)
                current.append(min(insertions, deletions, substitutions))
            previous = current
        return previous[-1]

    def levenshtein_similarity(s1: str, s2: str) -> float:
        """Return similarity between 0.0 and 1.0"""
        dist = levenshtein_distance(s1, s2)
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        return 1 - dist / max_len
    
    outputs = {"levenshtein_distance": levenshtein_distance(input_string1, input_string2), "similarity_score": levenshtein_similarity(input_string1, input_string2)}
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
