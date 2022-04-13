def keyword_search(liste_name=None, string_searched=None, **kwargs):
    """
    this CF uses a custom list and searches in a string for the elements from the list.
    
    Args:
        liste_name: Enter the list name here.
        string_searched: the data path to the string. e.g. emailBody, subject, requestURL etc.
    
    Returns a JSON-serializable object that implements the configured data paths:
        match_count: Indicates the number of hits
        miss_count: Specifies the number for "no hits
        match_keyword_list: returns the list of keywords found in the string
        match_count_result: returns True | False as soon as a match is found
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    import re

    
    outputs = {}
    
    # Write your custom code here...
    matches = []
    misses = []  
    matches_keyword_list = []
    
    success, message, c_keywoards = phantom.get_list(list_name=liste_name)
    # phantom.debug('phantom.get_list results: success: {}, message: {}, execs: {}'.format(success, message, c_keywoards))
    keywoard_list = [item for sublist in c_keywoards for item in sublist]
    
    phantom.debug('Keywoard list: {}'.format(keywoard_list))
    phantom.debug('String: {}'.format(string_searched))
    
    for item in keywoard_list:
        result = re.findall(item, string_searched, re.IGNORECASE)    
        phantom.debug('Result of the regex: {}'.format(result))
        for x in result:
            if result != -1:
                matches.append({"match": x})
                matches_keyword_list.append(item)
            else:
                misses.append({"miss": x})

    # Calculate the hits
    match_count = len(matches)
    miss_count = len(misses)    
    
    if match_count > 0:
        match_count_result = True
    else:
        match_count_result = False    
    
    phantom.debug('match_count : {}'.format(match_count))
    phantom.debug('miss_count : {}'.format(miss_count))
    phantom.debug('matches_keyword_list : {}'.format(matches_keyword_list))
    phantom.debug('match_count_result : {}'.format(match_count_result))    

    outputs = {
        'match_count': match_count,
        'miss_count': miss_count,
        'match_keyword_list' : matches_keyword_list,
        'match_count_result' : match_count_result
        
    }    
    
    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
