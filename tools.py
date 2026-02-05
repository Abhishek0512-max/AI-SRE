"""
Deterministic tools for incident investigation.
Tools operate on in-memory data and return JSON-serializable results.
"""

from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Any, Optional
from data_loader import parse_ts

DATA: Dict[str, Any] = {}


def set_data(data: Dict[str, Any]):
    """Initialize the data store."""
    global DATA
    DATA = data


def get_active_alerts(
    severity_min: str = "low",
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None
) -> Dict[str, Any]:
    """Get alerts filtered by minimum severity and time range."""
    severity_order = ['low', 'medium', 'high', 'critical']
    min_level = severity_order.index(severity_min)
    
    filtered = []
    for alert in DATA['alerts']:
        if severity_order.index(alert['severity']) < min_level:
            continue
        
        alert_ts = parse_ts(alert['timestamp'])
        if start_ts and alert_ts < parse_ts(start_ts):
            continue
        if end_ts and alert_ts > parse_ts(end_ts):
            continue
        
        filtered.append(alert)
    
    return {'count': len(filtered), 'alerts': filtered}


def recent_changes(service: str, start_ts: str, end_ts: str) -> Dict[str, Any]:
    """Get deployments and config changes for a service in time range."""
    start, end = parse_ts(start_ts), parse_ts(end_ts)
    
    filtered = [
        c for c in DATA['changes']
        if c['service'] == service and start <= parse_ts(c['timestamp']) <= end
    ]
    
    return {'count': len(filtered), 'changes': filtered}


def query_metrics(
    service: str,
    metric_names: List[str],
    start_ts: str,
    end_ts: str,
    agg: str = "latest"
) -> Dict[str, Any]:
    """Query metrics for a service with aggregation (latest/avg/min/max)."""
    start, end = parse_ts(start_ts), parse_ts(end_ts)
    result = {'service': service, 'metrics': {}}
    
    for name in metric_names:
        values = []
        unit = None
        
        for m in DATA['metrics']:
            if m['service'] != service or m['metric_name'] != name:
                continue
            if start <= parse_ts(m['timestamp']) <= end:
                values.append(m['value'])
                unit = unit or m['unit']
        
        if values:
            agg_funcs = {'latest': lambda v: v[-1], 'avg': lambda v: sum(v)/len(v), 
                         'min': min, 'max': max}
            agg_value = agg_funcs.get(agg, lambda v: v[-1])(values)
            
            result['metrics'][name] = {
                'value': round(agg_value, 2),
                'unit': unit,
                'aggregation': agg,
                'data_points': len(values)
            }
    
    return result


def search_logs(
    service: str,
    start_ts: str,
    end_ts: str,
    level_min: str = "INFO",
    contains: str = "",
    limit: int = 50
) -> Dict[str, Any]:
    """Search logs by service, time range, level, and keyword."""
    level_order = ['DEBUG', 'INFO', 'WARN', 'ERROR']
    min_idx = level_order.index(level_min)
    start, end = parse_ts(start_ts), parse_ts(end_ts)
    
    filtered = []
    for log in DATA['logs']:
        if log['service'] != service:
            continue
        if level_order.index(log['level']) < min_idx:
            continue
        if not (start <= parse_ts(log['timestamp']) <= end):
            continue
        if contains and contains.lower() not in log['message'].lower():
            continue
        
        filtered.append(log)
        if len(filtered) >= limit:
            break
    
    return {'count': len(filtered), 'logs': filtered}


def group_count_logs(logs: List[Dict], by: List[str]) -> Dict[str, Any]:
    """Group and count logs by specified fields."""
    counts = defaultdict(int)
    
    for log in logs:
        key_parts = []
        for field in by:
            val = log.get(field) or log.get('metadata', {}).get(field, 'unknown')
            key_parts.append(str(val))
        counts[' | '.join(key_parts)] += 1
    
    return {'grouped': dict(counts), 'total': len(logs), 'groups': len(counts)}


def expand_topology(service: str, direction: str = "upstream", depth: int = 1) -> Dict[str, Any]:
    """Get service dependencies (upstream) or dependents (downstream)."""
    if service not in DATA['service_map']:
        return {'error': f'Service {service} not found'}
    
    info = DATA['service_map'][service]
    key = 'dependencies' if direction == "upstream" else 'dependents'
    related = info.get(key, [])
    
    if depth > 1:
        all_related = set(related)
        for svc in related:
            if svc in DATA['service_map']:
                deeper = expand_topology(svc, direction, depth - 1)
                all_related.update(deeper.get(key, []))
        related = list(all_related)
    
    return {'service': service, key: related}


def correlate_timeline(
    events_a: List[Dict],
    events_b: List[Dict],
    max_lag_minutes: int = 15
) -> Dict[str, Any]:
    """Find events from two lists that occurred within max_lag_minutes of each other."""
    max_lag = timedelta(minutes=max_lag_minutes)
    correlations = []
    
    for a in events_a:
        ts_a = parse_ts(a['timestamp'])
        for b in events_b:
            lag = abs(parse_ts(b['timestamp']) - ts_a)
            if lag <= max_lag:
                correlations.append({
                    'event_a': a, 'event_b': b,
                    'lag_seconds': lag.total_seconds(),
                    'lag_minutes': round(lag.total_seconds() / 60, 2)
                })
    
    return {'correlations': correlations, 'count': len(correlations)}


def summarize_evidence(evidence_items: List[Dict]) -> Dict[str, Any]:
    """Summarize evidence items by source and relevance."""
    sources = set()
    by_relevance = defaultdict(int)
    
    for item in evidence_items:
        sources.add(item.get('source', 'unknown'))
        by_relevance[item.get('relevance', 'neutral')] += 1
    
    return {
        'total_items': len(evidence_items),
        'sources': sorted(sources),
        'by_relevance': dict(by_relevance)
    }
