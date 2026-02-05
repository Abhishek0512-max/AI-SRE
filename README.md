# AI-SRE: Multi-Agent Incident Investigation

Agentic system that investigates production incidents using logs, alerts, metrics, and change events. Produces structured Root Cause Analysis (RCA) with ranked hypotheses.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    AGENTIC LLM SYSTEM                          │
│                                                                │
│  ┌──────────┐    ┌──────────────┐    ┌───────────┐             │
│  │ PLANNER  │───>│ INVESTIGATOR │───>│ REFLECTOR │             │
│  │          │    │              │    │           │             │
│  │ Creates  │    │ Executes     │    │ Analyzes  │             │
│  │ plan     │    │ tools        │    │ evidence  │             │
│  └──────────┘    └──────┬───────┘    └─────┬─────┘             │
│                         │                  │                   │
│                         v                  v                   │
│                  ┌────────────┐     ┌────────────┐             │
│                  │  8 TOOLS   │     │ FINAL RCA  │             │
│                  │            │     │   JSON     │             │
│                  └────────────┘     └────────────┘             │
└────────────────────────────────────────────────────────────────┘
```

## Dataset

Synthetic incident data representing:
- Deploy to payment-api introduces config change (db_pool_size: 50 → 20)
- DB pool exhaustion → latency spikes → 5xx errors
- Failures propagate to checkout-service
- Rollback restores health

| File | Records | Description |
|------|---------|-------------|
| alerts.json | 3 | Firing alerts (latency, error_rate, connectivity) |
| changes.json | 5 | Deployments, config changes, rollback |
| metrics.json | 7 | Error rate, latency, pool usage |
| logs.jsonl | 65 | Application logs (baseline → incident → recovery) |
| service_map.json | 4 | Service dependency graph |

## Tools

| Category | Tool | Purpose |
|----------|------|---------|
| Retrieval | `get_active_alerts` | Filter alerts by severity/time |
| Retrieval | `recent_changes` | Get deploys, configs, rollbacks |
| Retrieval | `query_metrics` | Query metrics with aggregation |
| Retrieval | `search_logs` | Search logs by level/keyword |
| Aggregation | `group_count_logs` | Count logs by error_type |
| Context | `expand_topology` | Get service dependencies |
| Validation | `correlate_timeline` | Find temporal correlations |
| Explanation | `summarize_evidence` | Organize findings |

## Output Format

```json
{
  "incident_id": "rca-20240115-alert-001",
  "incident_summary": "payment-api experienced latency issues...",
  "top_hypotheses": [
    {
      "rank": 1,
      "hypothesis": "Config change (db_pool_size: 50 -> 20) caused exhaustion",
      "confidence": 0.85,
      "category": "configuration",
      "supporting_evidence": ["..."],
      "contradicting_evidence": []
    }
  ],
  "most_likely_root_cause": {...},
  "evidence": [...],
  "timeline": [...],
  "recommended_actions": [...],
  "verification_steps": [...],
  "missing_data": [...]
}
```

## Usage

```bash
pip install -r requirements.txt
export OPENAI_API_KEY='sk-...'
python agent_real.py
```

## Files

| File | Purpose |
|------|---------|
| agent_real.py | 3-agent system: Planner → Investigator → Reflector |
| tools.py | 8 deterministic investigation tools |
| data_loader.py | Loads dataset into memory |
| data/ | Synthetic incident data |
