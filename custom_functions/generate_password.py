def generate_password(length=None, uppercase=None, lowercase=None, numbers=None, symbols=None, exclude_ambiguous=None, **kwargs):
    """
    Generate a cryptographically secure random password using the secrets module.
    Supports configurable character sets and optional exclusion of ambiguous characters (0, O, l, 1, I).
    At least one character from each enabled character set is guaranteed to appear in the output.

    Args:
        length: Length of the generated password. Defaults to 16. Minimum is 4.
        uppercase: Include uppercase letters (A-Z). Defaults to True.
        lowercase: Include lowercase letters (a-z). Defaults to True.
        numbers: Include digits (0-9). Defaults to True.
        symbols: Include symbols (!@#$%^&*). Defaults to False.
        exclude_ambiguous: Exclude visually ambiguous characters (0, O, l, 1, I). Defaults to False.

    Returns a JSON-serializable object that implements the configured data paths:
        password (CEF type: password): The generated password.
        length: The length of the generated password.
        character_sets_used: List of character sets included in the password.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import secrets
    import phantom.rules as phantom

    outputs = {}

    # Resolve inputs with sensible defaults
    try:
        pwd_length = max(4, int(length)) if length is not None else 16
    except (ValueError, TypeError):
        raise ValueError("length must be a positive integer")

    def _is_true(val, default=True):
        if val is None:
            return default
        if isinstance(val, bool):
            return val
        return str(val).strip().lower() in ('true', '1', 'yes')

    use_uppercase = _is_true(uppercase, default=True)
    use_lowercase = _is_true(lowercase, default=True)
    use_numbers   = _is_true(numbers,   default=True)
    use_symbols   = _is_true(symbols,   default=False)
    excl_ambig    = _is_true(exclude_ambiguous, default=False)

    AMBIGUOUS = set('0Ol1I')

    def _build_charset(chars):
        if excl_ambig:
            return ''.join(c for c in chars if c not in AMBIGUOUS)
        return chars

    charsets = {}
    if use_uppercase:
        charsets['uppercase'] = _build_charset('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
    if use_lowercase:
        charsets['lowercase'] = _build_charset('abcdefghijklmnopqrstuvwxyz')
    if use_numbers:
        charsets['numbers']   = _build_charset('0123456789')
    if use_symbols:
        charsets['symbols']   = _build_charset('!@#$%^&*()_+-=[]{}|;:,.<>?')

    # Validate at least one character set is enabled and non-empty after filtering
    charsets = {k: v for k, v in charsets.items() if v}
    if not charsets:
        raise ValueError("No characters available — all character sets are empty or disabled.")

    if pwd_length < len(charsets):
        raise ValueError(f"Password length ({pwd_length}) is too short to include one character from each of the {len(charsets)} enabled character sets.")

    # Guarantee at least one character from each enabled set
    pool = ''.join(charsets.values())
    password_chars = [secrets.choice(chars) for chars in charsets.values()]

    # Fill remaining length from the full pool
    password_chars += [secrets.choice(pool) for _ in range(pwd_length - len(password_chars))]

    # Shuffle using secrets for cryptographic randomness
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    outputs = {
        'password': ''.join(password_chars),
        'length': pwd_length,
        'character_sets_used': list(charsets.keys())
    }

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
