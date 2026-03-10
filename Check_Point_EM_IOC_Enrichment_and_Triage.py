"""
Check Point EM IOC Enrichment and Triage

Accepts IOCs (IP, domain, hash, URL) from SIEM/SOAR alerts and enriches them using
Check Point EM threat intelligence APIs. Provides verdict, telemetry, malware family,
actor attribution, first seen, and confidence data. Applies decision logic to
escalate malicious indicators or suppress benign ones.

Check Point EM API Endpoints:
- GET /api/v1/file/sha256 - File hash enrichment
- GET /api/v1/file/domain - Domain enrichment
- GET /api/v1/file/ipv4 - IP address enrichment
- GET /api/v1/file/url - URL enrichment
"""

import phantom.rules as phantom
import json
from datetime import datetime, timedelta


def on_start(container):
    phantom.debug('on_start() called')

    # Call route_ioc_by_type to categorize indicators
    route_ioc_by_type(container=container)

    return


def route_ioc_by_type(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('route_ioc_by_type() called')

    import re

    playbook_input_indicator_value = phantom.collect2(container=container, datapath=['playbook_input:indicator_value'])
    playbook_input_indicator_type = phantom.collect2(container=container, datapath=['playbook_input:indicator_type'])

    route_ioc_by_type__sha256_indicators = []
    route_ioc_by_type__domain_indicators = []
    route_ioc_by_type__ipv4_indicators = []
    route_ioc_by_type__url_indicators = []

    indicator_values = [i[0] for i in playbook_input_indicator_value] if playbook_input_indicator_value else []
    indicator_types = [i[0] for i in playbook_input_indicator_type] if playbook_input_indicator_type else []

    # Pad indicator_types if shorter than indicator_values
    while len(indicator_types) < len(indicator_values):
        indicator_types.append('auto')

    for value, ioc_type in zip(indicator_values, indicator_types):
        if not value:
            continue

        ioc_type_lower = (ioc_type or '').lower()

        # Auto-detect type if not provided
        if not ioc_type_lower or ioc_type_lower == 'auto':
            if re.match(r'^[a-fA-F0-9]{64}$', value):
                ioc_type_lower = 'sha256'
            elif re.match(r'^[a-fA-F0-9]{32}$', value):
                ioc_type_lower = 'md5'
            elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                ioc_type_lower = 'ip'
            elif re.match(r'^https?://', value):
                ioc_type_lower = 'url'
            else:
                ioc_type_lower = 'domain'

        if ioc_type_lower in ['sha256', 'hash', 'md5', 'sha1']:
            route_ioc_by_type__sha256_indicators.append(value)
        elif ioc_type_lower == 'domain':
            route_ioc_by_type__domain_indicators.append(value)
        elif ioc_type_lower in ['ip', 'ipv4', 'ip address']:
            route_ioc_by_type__ipv4_indicators.append(value)
        elif ioc_type_lower == 'url':
            route_ioc_by_type__url_indicators.append(value)

    phantom.save_run_data(key='route_ioc_by_type:sha256_indicators', value=json.dumps(route_ioc_by_type__sha256_indicators))
    phantom.save_run_data(key='route_ioc_by_type:domain_indicators', value=json.dumps(route_ioc_by_type__domain_indicators))
    phantom.save_run_data(key='route_ioc_by_type:ipv4_indicators', value=json.dumps(route_ioc_by_type__ipv4_indicators))
    phantom.save_run_data(key='route_ioc_by_type:url_indicators', value=json.dumps(route_ioc_by_type__url_indicators))

    phantom.debug(f"Routed IOCs - SHA256: {len(route_ioc_by_type__sha256_indicators)}, Domain: {len(route_ioc_by_type__domain_indicators)}, IPv4: {len(route_ioc_by_type__ipv4_indicators)}, URL: {len(route_ioc_by_type__url_indicators)}")

    # Launch enrichment actions in parallel
    if route_ioc_by_type__sha256_indicators:
        enrich_sha256(container=container)
    if route_ioc_by_type__domain_indicators:
        enrich_domain(container=container)
    if route_ioc_by_type__ipv4_indicators:
        enrich_ipv4(container=container)
    if route_ioc_by_type__url_indicators:
        enrich_url(container=container)

    # If no indicators, go directly to normalize
    if not any([route_ioc_by_type__sha256_indicators, route_ioc_by_type__domain_indicators,
                route_ioc_by_type__ipv4_indicators, route_ioc_by_type__url_indicators]):
        normalize_check_point_em_results(container=container)

    return


def enrich_sha256(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('enrich_sha256() called')

    sha256_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:sha256_indicators') or '[]')

    parameters = []
    for hash_value in sha256_indicators:
        parameters.append({
            'SHA256': hash_value,
        })

    phantom.act(action='ioc - get file reputation', parameters=parameters, assets=['cyberint'], callback=normalize_check_point_em_results, name='enrich_sha256')

    return


def enrich_domain(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('enrich_domain() called')

    domain_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:domain_indicators') or '[]')

    parameters = []
    for domain in domain_indicators:
        parameters.append({
            'Domain': domain,
        })

    phantom.act(action='ioc - get domain reputation', parameters=parameters, assets=['cyberint'], callback=normalize_check_point_em_results, name='enrich_domain')

    return


def enrich_ipv4(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('enrich_ipv4() called')

    ipv4_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:ipv4_indicators') or '[]')

    parameters = []
    for ip in ipv4_indicators:
        parameters.append({
            'IP': ip,
        })

    phantom.act(action='ioc - get ip reputation', parameters=parameters, assets=['cyberint'], callback=normalize_check_point_em_results, name='enrich_ipv4')

    return


def enrich_url(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('enrich_url() called')

    url_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:url_indicators') or '[]')

    parameters = []
    for url in url_indicators:
        parameters.append({
            'URL': url,
        })

    phantom.act(action='ioc - get url reputation', parameters=parameters, assets=['cyberint'], callback=normalize_check_point_em_results, name='enrich_url')

    return


def normalize_check_point_em_results(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('normalize_check_point_em_results() called')

    # Check if all enrichment actions are complete
    sha256_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:sha256_indicators') or '[]')
    domain_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:domain_indicators') or '[]')
    ipv4_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:ipv4_indicators') or '[]')
    url_indicators = json.loads(phantom.get_run_data(key='route_ioc_by_type:url_indicators') or '[]')

    actions_to_check = []
    if sha256_indicators:
        actions_to_check.append('enrich_sha256')
    if domain_indicators:
        actions_to_check.append('enrich_domain')
    if ipv4_indicators:
        actions_to_check.append('enrich_ipv4')
    if url_indicators:
        actions_to_check.append('enrich_url')

    if actions_to_check and not phantom.completed(action_names=actions_to_check):
        return

    normalize_check_point_em_results__enriched_indicators = []
    normalize_check_point_em_results__malicious_count = 0
    normalize_check_point_em_results__benign_count = 0
    normalize_check_point_em_results__unknown_count = 0

    def process_enrichment(action_name, indicator_type):
        results = []
        malicious = 0
        benign = 0
        unknown = 0

        action_results = phantom.collect2(container=container, datapath=[
            f'{action_name}:action_result.data',
            f'{action_name}:action_result.parameter.*'
        ])

        if not action_results:
            return results, malicious, benign, unknown

        for result in action_results:
            data = result[0] if result[0] else {}
            indicator = result[1] if len(result) > 1 else ''

            if not data:
                continue

            # Handle list of data items
            if isinstance(data, list):
                data = data[0] if data else {}

            enrichment = {
                'indicator': indicator,
                'type': indicator_type,
                'verdict': data.get('verdict', 'unknown'),
                'confidence': data.get('confidence', 0),
                'malware_family': data.get('malware_family', []),
                'actor_attribution': data.get('actor_attribution', []),
                'first_seen': data.get('first_seen', ''),
                'last_seen': data.get('last_seen', ''),
                'telemetry': data.get('telemetry', {}),
                'tags': data.get('tags', []),
                'source': 'Check Point EM'
            }

            verdict_lower = str(enrichment['verdict']).lower()
            if verdict_lower in ['malicious', 'high', 'critical']:
                malicious += 1
                enrichment['score_id'] = 10
                enrichment['score'] = 'Malicious'
            elif verdict_lower in ['suspicious', 'medium']:
                malicious += 1
                enrichment['score_id'] = 7
                enrichment['score'] = 'Suspicious'
            elif verdict_lower in ['benign', 'safe', 'clean', 'low']:
                benign += 1
                enrichment['score_id'] = 1
                enrichment['score'] = 'Benign'
            else:
                unknown += 1
                enrichment['score_id'] = 5
                enrichment['score'] = 'Unknown'

            results.append(enrichment)

        return results, malicious, benign, unknown

    # Process each type
    for action_name, indicator_type in [('enrich_sha256', 'sha256'), ('enrich_domain', 'domain'),
                                         ('enrich_ipv4', 'ipv4'), ('enrich_url', 'url')]:
        type_results, type_mal, type_ben, type_unk = process_enrichment(action_name, indicator_type)
        normalize_check_point_em_results__enriched_indicators.extend(type_results)
        normalize_check_point_em_results__malicious_count += type_mal
        normalize_check_point_em_results__benign_count += type_ben
        normalize_check_point_em_results__unknown_count += type_unk

    phantom.save_run_data(key='normalize_check_point_em_results:enriched_indicators', value=json.dumps(normalize_check_point_em_results__enriched_indicators))
    phantom.save_run_data(key='normalize_check_point_em_results:malicious_count', value=json.dumps(normalize_check_point_em_results__malicious_count))
    phantom.save_run_data(key='normalize_check_point_em_results:benign_count', value=json.dumps(normalize_check_point_em_results__benign_count))
    phantom.save_run_data(key='normalize_check_point_em_results:unknown_count', value=json.dumps(normalize_check_point_em_results__unknown_count))

    phantom.debug(f"Enrichment complete - Malicious: {normalize_check_point_em_results__malicious_count}, Benign: {normalize_check_point_em_results__benign_count}, Unknown: {normalize_check_point_em_results__unknown_count}")

    # Branch based on malicious count
    if normalize_check_point_em_results__malicious_count > 0:
        escalate_malicious(container=container)
    else:
        suppress_benign(container=container)

    return


def escalate_malicious(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('escalate_malicious() called')

    enriched_indicators = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:enriched_indicators') or '[]')
    malicious_count = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:malicious_count') or '0')

    malicious_indicators = [i for i in enriched_indicators if i.get('score_id', 0) >= 7]

    note_content = f"## Check Point EM IOC Enrichment - MALICIOUS INDICATORS DETECTED\n\n"
    note_content += f"**Total Malicious Indicators:** {malicious_count}\n\n"
    note_content += "| Indicator | Type | Verdict | Confidence | Malware Family | Actor Attribution |\n"
    note_content += "|-----------|------|---------|------------|----------------|-------------------|\n"

    for indicator in malicious_indicators:
        malware_fam = ', '.join(indicator.get('malware_family', [])) or 'N/A'
        actor_attr = ', '.join(indicator.get('actor_attribution', [])) or 'N/A'
        note_content += f"| `{indicator['indicator']}` | {indicator['type']} | {indicator['verdict']} | {indicator.get('confidence', 'N/A')} | {malware_fam} | {actor_attr} |\n"

    note_content += f"\n**Recommendation:** Escalate for immediate investigation and potential containment.\n"

    phantom.set_severity(container=container, severity="high")
    phantom.add_note(container=container, content=note_content, note_format="markdown", note_type="general", title="Check Point EM IOC Enrichment - Malicious Indicators")

    phantom.debug("Escalated container due to malicious indicators")

    build_observable_output(container=container)

    return


def suppress_benign(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('suppress_benign() called')

    enriched_indicators = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:enriched_indicators') or '[]')
    benign_count = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:benign_count') or '0')
    unknown_count = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:unknown_count') or '0')

    note_content = f"## Check Point EM IOC Enrichment - No Malicious Indicators\n\n"
    note_content += f"**Benign Indicators:** {benign_count}\n"
    note_content += f"**Unknown Indicators:** {unknown_count}\n\n"

    if enriched_indicators:
        note_content += "| Indicator | Type | Verdict | Confidence |\n"
        note_content += "|-----------|------|---------|------------|\n"

        for indicator in enriched_indicators:
            note_content += f"| `{indicator['indicator']}` | {indicator['type']} | {indicator['verdict']} | {indicator.get('confidence', 'N/A')} |\n"

    note_content += f"\n**Recommendation:** No immediate action required. Consider closing as false positive if no other indicators present.\n"

    phantom.add_note(container=container, content=note_content, note_format="markdown", note_type="general", title="Check Point EM IOC Enrichment - Benign/Unknown")

    phantom.debug("No malicious indicators found - added informational note")

    build_observable_output(container=container)

    return


def build_observable_output(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('build_observable_output() called')

    enriched_indicators = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:enriched_indicators') or '[]')

    build_observable_output__observable_array = []

    for indicator in enriched_indicators:
        observable = {
            "value": indicator['indicator'],
            "type": indicator['type'],
            "reputation": {
                "score_id": indicator.get('score_id', 5),
                "score": indicator.get('score', 'Unknown'),
                "confidence": indicator.get('confidence', 0)
            },
            "enrichment": {
                "verdict": indicator.get('verdict', 'unknown'),
                "malware_family": indicator.get('malware_family', []),
                "actor_attribution": indicator.get('actor_attribution', []),
                "first_seen": indicator.get('first_seen', ''),
                "last_seen": indicator.get('last_seen', ''),
                "tags": indicator.get('tags', [])
            },
            "source": "Check Point EM",
            "source_link": "https://app.checkpoint.com/em"
        }
        build_observable_output__observable_array.append(observable)

    phantom.save_run_data(key='build_observable_output:observable_array', value=json.dumps(build_observable_output__observable_array))

    phantom.debug(f"Built {len(build_observable_output__observable_array)} observables for output")

    format_enrichment_report(container=container)

    return


def format_enrichment_report(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, **kwargs):
    phantom.debug('format_enrichment_report() called')

    enriched_indicators = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:enriched_indicators') or '[]')
    malicious_count = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:malicious_count') or '0')
    benign_count = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:benign_count') or '0')
    unknown_count = json.loads(phantom.get_run_data(key='normalize_check_point_em_results:unknown_count') or '0')

    total_count = len(enriched_indicators)

    template = f"""# Check Point EM IOC Enrichment Report

**Summary:**
- Total Indicators Analyzed: {total_count}
- Malicious: {malicious_count}
- Benign: {benign_count}
- Unknown: {unknown_count}

**Source:** Check Point EM Threat Intelligence Platform

---

This playbook enriched IOCs using Check Point EM APIs:
- `/api/v1/file/sha256` - File hash enrichment
- `/api/v1/file/domain` - Domain enrichment
- `/api/v1/file/ipv4` - IP address enrichment
- `/api/v1/file/url` - URL enrichment
"""

    phantom.save_run_data(key='format_enrichment_report:formatted_data', value=template)

    return


def on_finish(container, summary):
    phantom.debug('on_finish() called')

    observable_array = json.loads(phantom.get_run_data(key='build_observable_output:observable_array') or '[]')
    report = phantom.get_run_data(key='format_enrichment_report:formatted_data') or ''

    output = {
        'observable': observable_array,
        'report': report
    }

    phantom.save_playbook_output_data(output=output)

    return
