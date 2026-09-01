def dual_signal_containment_gate(context=None, generator_id=None, classification=None, eve_threat_confidence=None, **kwargs):
    """
    Gate/Prove containment: decide whether auto-contain (block ip) is allowed.

    Machine-learning confidence is not a classic signature true positive.
    SnortML GID 411, is_ml_only, and EVE-high without a classic signature must
    not auto-contain. Signature-high and signature+ML corroboration may contain
    (callers can still add HITL). Unknown context fails closed.

    Args:
        context (CEF type: *): Incident/notable title, description, and related text.
        generator_id: Snort / Cisco Secure Firewall GeneratorID (411 = SnortML).
        classification: Classic Snort classification (e.g. attempted-admin).
        eve_threat_confidence: Encrypted Visibility Engine threat confidence 0-100.

    Returns a JSON-serializable object that implements the configured data paths:
        disposition: One of 'ml_only', 'signature', 'corroborated', or 'unknown'.
        allow_auto_contain: 'true' or 'false' for playbook filters before block ip.
        require_hitl: 'true' or 'false'. True for ml_only and unknown.
        reason: Why auto-contain was allowed or denied.
        never_equate_ml_to_signature: Always 'true'.
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    import re
    import phantom.rules as phantom

    ML_MARKERS = (
        "gid 411",
        "gid:411",
        "gid=411",
        "generator id 411",
        "generatorid=411",
        "generatorid:411",
        "snortml",
        "snort ml",
        "is_ml_only",
        "ml-only",
        "ml_only",
        "dual-signal:ml-only",
        "dual_signal:ml_only",
    )
    CORR_MARKERS = (
        "is_corroborated",
        "dual-signal:corroborated",
        "dual_signal:corroborated",
        "signature and ml",
        "signature + ml",
        "signature plus eve",
        "signature plus ml",
    )
    HIGH_PRIORITY_CLASSIFICATIONS = (
        "attempted-admin",
        "attempted-user",
        "successful-admin",
        "successful-user",
        "shellcode-detect",
        "trojan-activity",
        "web-application-attack",
        "policy-violation",
        "misc-attack",
        "denial-of-service",
        "attempted-dos",
        "successful-dos",
        "successful-recon-largescale",
        "successful-recon-limited",
        "attempted-recon",
    )

    def _flatten(value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple)):
            return " ".join(_flatten(item) for item in value if item is not None)
        return str(value)

    def _parse_gid(value):
        text = _flatten(value).strip()
        if not text:
            return None
        match = re.search(r"(\d+)", text)
        if not match:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

    def _parse_eve(value):
        text = _flatten(value).strip()
        if not text:
            return None
        match = re.search(r"(\d+(?:\.\d+)?)", text)
        if not match:
            return None
        try:
            return float(match.group(1))
        except ValueError:
            return None

    context_text = _flatten(context).lower()
    classification_text = _flatten(classification).lower()
    blob = " ".join(
        part for part in (context_text, classification_text, _flatten(generator_id).lower()) if part
    )

    gid = _parse_gid(generator_id)
    if gid is None:
        gid_from_text = re.search(r"\b(?:gid|generator\s*id|generatorid)\s*[:=]?\s*(\d+)", blob)
        if gid_from_text:
            gid = int(gid_from_text.group(1))

    eve = _parse_eve(eve_threat_confidence)
    if eve is None:
        eve_from_text = re.search(r"\beve(?:_threat)?(?:_confidence)?(?:pct)?\s*[:=]?\s*(\d+(?:\.\d+)?)", blob)
        if eve_from_text:
            eve = float(eve_from_text.group(1))

    ml_from_gid = gid == 411
    ml_from_text = any(marker in blob for marker in ML_MARKERS)
    eve_high = eve is not None and eve >= 80
    has_ml = ml_from_gid or ml_from_text or eve_high

    # GID 411 events may still carry a class_desc; that is not a classic signature TP.
    has_classic = (
        (gid is not None and gid != 411)
        or (gid != 411 and any(item in classification_text for item in HIGH_PRIORITY_CLASSIFICATIONS))
        or bool(
            re.search(r"\b(?:classic signature|ids signature)\b", blob)
            or re.search(r"\b(?:gid|generator\s*id|generatorid)\s*[:=]?\s*1\b", blob)
        )
    )

    is_corr = any(marker in blob for marker in CORR_MARKERS) or (has_ml and has_classic)

    if is_corr:
        disposition = "corroborated"
        allow_auto_contain = "true"
        require_hitl = "false"
        reason = (
            "Dual-signal corroboration (classic signature and ML/EVE). "
            "Auto-contain is allowed; HITL remains optional."
        )
    elif has_ml and not has_classic:
        disposition = "ml_only"
        allow_auto_contain = "false"
        require_hitl = "true"
        reason = (
            "ML-only path (SnortML GID 411, is_ml_only, and/or EVE-high without a classic signature). "
            "Do not equate ML confidence to a signature true positive. Deny auto-contain; escalate / HITL."
        )
    elif has_classic:
        disposition = "signature"
        allow_auto_contain = "true"
        require_hitl = "false"
        reason = (
            "Classic signature / high-priority classification without an ML-only path. "
            "Auto-contain is allowed."
        )
    else:
        disposition = "unknown"
        allow_auto_contain = "false"
        require_hitl = "true"
        reason = (
            "Insufficient dual-signal context to justify auto-contain. Fail closed; require HITL."
        )

    outputs = {
        "disposition": disposition,
        "allow_auto_contain": allow_auto_contain,
        "require_hitl": require_hitl,
        "reason": reason,
        "never_equate_ml_to_signature": "true",
    }

    phantom.debug("dual_signal_containment_gate: {}".format(outputs))

    assert json.dumps(outputs)
    return outputs
