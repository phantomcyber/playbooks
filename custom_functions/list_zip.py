def list_zip(zip_type=None, pad_values=None, input_1=None, input_2=None, input_3=None, input_4=None, input_5=None, input_6=None, input_7=None, input_8=None, **kwargs):
    """
    This function zips two or more lists together to create a list of equal length. This can be useful when multiple upstream blocks are used for a single downstream block with multiple inputs. A maximum of 8 lists can be zipped together. The input lists are intended to be flat lists of strings, not nested lists or dictionaries.
    
    Args:
        zip_type: (Optional) 'longest' OR 'shortest'. Defaults to 'shortest'. Determines how to treat lists of unequal size. Longest will pad the merged list to the longest of all of the lists. Shortest will truncate the merged list to the shortest of all of the lists.
        pad_values: (Optional) True OR False. Defaults to True. Determines if an input with a single value should be duplicated in the zipped list.
        input_1
        input_2
        input_3
        input_4
        input_5
        input_6
        input_7
        input_8
    
    Returns a JSON-serializable object that implements the configured data paths:
        input_1
        input_2
        input_3
        input_4
        input_5
        input_6
        input_7
        input_8
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import phantom.rules as phantom
    from itertools import zip_longest
    
    outputs = []
    

    def bool_check(input_item):
        if isinstance(input_item, str) and input_item.lower() == 'true':
            return True
        elif isinstance(input_item, str) and input_item.lower() == 'false':
            return False
        elif isinstance(input_item, bool):
            return input_item
        elif input_item is None:
            return True
        else:
            raise TypeError(f"'pad_values' is invalid. '{input_item}' is not 'true' or 'false' or bool")

    def check_and_merge_inputs(*args):
        temp_dict = {}
        for idx, item in enumerate(args, start=1):
            # attempt to convert lists as string to lists
            if isinstance(item, str) and item.startswith("[") and item.endswith("]"):    
                temp_dict[f'input_{idx}'] = [i.strip() for i in item.lstrip('[').rstrip(']').split(',')]
            elif isinstance(item, list) and len(item) == 1 and item[0].startswith("[") and item[0].endswith("]"):
                temp_dict[f'input_{idx}'] = [i.strip() for i in item[0].lstrip('[').rstrip(']').split(',')]
            # elif raise error on unsupported items
            elif not isinstance(item, list) and not item is None :
                raise TypeError(f"input_{idx} is not None or list type, it is {type(item)}.")
            # else pass as-is
            elif item:
                temp_dict[f'input_{idx}'] = item
        return temp_dict

    merged_dict = check_and_merge_inputs(input_1, input_2, input_3, input_4, input_5, input_6, input_7, input_8)
    pad_values = bool_check(pad_values)
    values_to_pad = {}

    if pad_values:
        for k, v in merged_dict.copy().items():
            if len(v) == 1:
                values_to_pad[k] = merged_dict.pop(k)[0]

    keys = merged_dict.keys()

    if isinstance(zip_type, str) and zip_type.lower() == 'longest':
        values = zip_longest(*merged_dict.values())
    else:
        values = zip(*merged_dict.values())

    outputs = [dict(zip(keys, v)) for v in values]

    if pad_values:
        for item in outputs:
            for k in values_to_pad:
                item[k] = values_to_pad[k]
    
    # Return a JSON-serializable object
    assert isinstance(outputs, list)  # Will raise an exception if the :outputs: object is not a list
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
