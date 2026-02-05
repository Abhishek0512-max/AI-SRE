"""
Multi-agent incident investigation system using AutoGen.

Architecture:
- Planner: Creates investigation plan with tool calls
- Investigator: Executes tools and gathers evidence
- Reflector: Validates evidence, can request more data or finalize RCA
"""

import os
import json
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from pathlib import Path
from dataclasses import dataclass, field

from dotenv import load_dotenv
from autogen_agentchat.agents import AssistantAgent
from autogen_agentchat.teams import RoundRobinGroupChat
from autogen_agentchat.conditions import TextMentionTermination, MaxMessageTermination
from autogen_agentchat.base import TaskResult
from autogen_ext.models.openai import OpenAIChatCompletionClient
from autogen_core.tools import FunctionTool

import data_loader
import tools


# Load environment
env_path = Path(__file__).parent.parent / '.env'
if env_path.exists():
    load_dotenv(env_path)

API_KEY = os.getenv("OPENAI_API_KEY")
if not API_KEY:
    raise RuntimeError("OPENAI_API_KEY not set")

DATA = data_loader.load_all("data")
tools.set_data(DATA)


@dataclass
class InvestigationMemory:
    """Tracks investigation state across agent interactions."""
    alert: Dict = field(default_factory=dict)
    evidence: List[Dict] = field(default_factory=list)
    hypotheses: List[Dict] = field(default_factory=list)
    tools_called: List[str] = field(default_factory=list)
    iteration: int = 0
    max_iterations: int = 3
    
    def add_evidence(self, source: str, finding: str, relevance: str = "supports"):
        self.evidence.append({
            "source": source,
            "finding": finding,
            "relevance": relevance,
            "timestamp": datetime.now().isoformat()
        })
    
    def add_hypothesis(self, hypothesis: str, confidence: float, category: str):
        self.hypotheses.append({
            "hypothesis": hypothesis,
            "confidence": confidence,
            "category": category
        })
    
    def should_continue(self) -> bool:
        return self.iteration < self.max_iterations


def create_tools() -> List[FunctionTool]:
    return [
        FunctionTool(tools.get_active_alerts, description="Get alerts by severity and time range"),
        FunctionTool(tools.recent_changes, description="Get deployments/config changes for a service"),
        FunctionTool(tools.query_metrics, description="Query service metrics with aggregation"),
        FunctionTool(tools.search_logs, description="Search logs by service, level, keyword"),
        FunctionTool(tools.group_count_logs, description="Group and count logs by fields"),
        FunctionTool(tools.expand_topology, description="Get service dependencies from topology"),
        FunctionTool(tools.correlate_timeline, description="Find temporal correlations between events"),
        FunctionTool(tools.summarize_evidence, description="Summarize evidence items"),
    ]


PLANNER_PROMPT = """You are an SRE incident planner. Given an alert, create an investigation plan.

Your job is to decide which tools to call and in what order. Output a structured plan.

AVAILABLE TOOLS:
1. get_active_alerts - Check for related alerts
2. recent_changes - Find deployments, config changes, rollbacks
3. query_metrics - Get error_rate, latency_p99, db_pool_usage
4. search_logs - Find error logs and patterns
5. group_count_logs - Aggregate log patterns by error_type
6. expand_topology - Check service dependencies
7. correlate_timeline - Find temporal correlations
8. summarize_evidence - Organize findings

OUTPUT FORMAT:
{
  "plan_id": "plan-001",
  "investigation_steps": [
    {"step": 1, "tool": "get_active_alerts", "reason": "Check for related alerts"},
    {"step": 2, "tool": "recent_changes", "reason": "Look for recent deployments or config changes"},
    ...
  ],
  "initial_hypotheses": [
    "Configuration change may have caused the issue",
    "Recent deployment may have introduced a bug"
  ]
}

After outputting the plan, say "PLAN_COMPLETE"."""


def build_investigator_prompt(alert: Dict, start_ts: str, end_ts: str) -> str:
    return f"""You are an SRE investigator. Execute the investigation plan by calling tools.

INCIDENT:
- Alert: {alert['alert_id']}
- Service: {alert['service']}  
- Severity: {alert['severity']}
- Type: {alert['alert_type']}
- Message: {alert['message']}
- Time: {alert['timestamp']}

TIME WINDOW: {start_ts} to {end_ts}

TASK:
1. Follow the plan from Planner
2. Call each tool with appropriate parameters
3. Record key findings from each tool
4. After gathering evidence, summarize findings

When done, output:
EVIDENCE_SUMMARY:
- Finding 1: [source] description
- Finding 2: [source] description
...

Then say "EVIDENCE_COMPLETE"."""


REFLECTOR_PROMPT = """You are an incident analyst. Review evidence and produce root cause analysis.

TASK:
1. Review all evidence from the Investigator
2. Identify multiple hypotheses (rank by confidence)
3. Determine if evidence is sufficient
4. If more data needed, say "NEED_MORE_DATA: [what's missing]"
5. If sufficient, produce final RCA

OUTPUT FORMAT (strict JSON):
{
  "incident_id": "rca-YYYYMMDD-NNN",
  "timestamp": "ISO8601",
  "incident_summary": "Brief description of what happened",
  "top_hypotheses": [
    {
      "rank": 1,
      "hypothesis": "Root cause statement",
      "confidence": 0.85,
      "category": "configuration|deployment|capacity|dependency|external",
      "supporting_evidence": ["evidence item 1", "evidence item 2"],
      "contradicting_evidence": []
    },
    {
      "rank": 2,
      "hypothesis": "Alternative hypothesis",
      "confidence": 0.4,
      "category": "deployment",
      "supporting_evidence": ["evidence"],
      "contradicting_evidence": ["counter evidence"]
    }
  ],
  "most_likely_root_cause": {
    "hypothesis": "The primary root cause",
    "category": "configuration",
    "confidence": 0.85,
    "affected_services": ["payment-api"]
  },
  "evidence": [
    {"source": "tool_name", "observation": "what was found", "relevance": "supports|contradicts|neutral"}
  ],
  "timeline": [
    {"time": "HH:MM", "event": "description"}
  ],
  "recommended_actions": [
    {"action": "specific action", "priority": "immediate|short-term|long-term", "owner": "team"}
  ],
  "verification_steps": [
    "Step to verify the root cause",
    "Step to confirm fix worked"
  ],
  "missing_data": [
    "Data that would strengthen analysis"
  ]
}

Say "INVESTIGATION_COMPLETE" after the JSON."""


def extract_rca(messages, alert: Dict) -> Dict:
    """Extract structured RCA from agent messages."""
    for msg in reversed(messages):
        content = str(msg.content) if hasattr(msg, 'content') else str(msg)
        
        if '{' in content and '}' in content:
            try:
                start = content.find('{')
                end = content.rfind('}') + 1
                rca = json.loads(content[start:end])
                if 'most_likely_root_cause' in rca or 'top_hypotheses' in rca:
                    return rca
            except json.JSONDecodeError:
                continue
    
    return build_fallback_rca(alert)


def build_fallback_rca(alert: Dict) -> Dict:
    """Build fallback RCA if extraction fails."""
    return {
        "incident_id": f"rca-{alert['alert_id']}",
        "timestamp": datetime.now().isoformat(),
        "incident_summary": f"Investigation of {alert['service']} {alert['alert_type']} incident",
        "top_hypotheses": [],
        "most_likely_root_cause": {
            "hypothesis": "Unable to determine - review investigation logs",
            "category": "unknown",
            "confidence": 0.0,
            "affected_services": [alert['service']]
        },
        "evidence": [],
        "timeline": [],
        "recommended_actions": [
            {"action": "Manual investigation required", "priority": "immediate", "owner": "sre-team"}
        ],
        "verification_steps": ["Review raw investigation output"],
        "missing_data": ["Structured analysis could not be extracted"]
    }


def print_trace(msg):
    """Print conversation trace."""
    source = getattr(msg, 'source', 'unknown')
    msg_type = type(msg).__name__
    
    if 'ToolCall' in msg_type:
        print(f"\n[TOOL CALL] {source}")
        if hasattr(msg, 'content') and msg.content:
            calls = msg.content if isinstance(msg.content, list) else [msg.content]
            for call in calls:
                if hasattr(call, 'name'):
                    args = getattr(call, 'arguments', '')
                    if isinstance(args, dict):
                        args = json.dumps(args)
                    print(f"  -> {call.name}({args[:100]}...)" if len(str(args)) > 100 else f"  -> {call.name}({args})")
    
    elif 'Result' in msg_type:
        print(f"[TOOL RESULT]")
        if hasattr(msg, 'content') and msg.content:
            results = msg.content if isinstance(msg.content, list) else [msg.content]
            for r in results:
                content = str(getattr(r, 'content', r))[:150]
                print(f"  <- {content}...")
    
    elif msg_type in ('TextMessage', 'AssistantMessage', 'Response'):
        print(f"\n{'='*60}")
        print(f"[{source.upper()}]")
        print("-"*60)
        content = str(msg.content) if hasattr(msg, 'content') else str(msg)
        print(content[:1000] + "..." if len(content) > 1000 else content)


async def run_investigation(alert: Dict[str, Any], verbose: bool = True) -> Dict[str, Any]:
    """Execute multi-agent investigation with Planner -> Investigator -> Reflector loop."""
    
    memory = InvestigationMemory(alert=alert)
    
    print("\n" + "="*60)
    print("INCIDENT INVESTIGATION")
    print("="*60)
    print(f"Alert: {alert['alert_id']}")
    print(f"Service: {alert['service']}")
    print(f"Severity: {alert['severity']}")
    print(f"Message: {alert['message']}")
    print("="*60)
    
    model_client = OpenAIChatCompletionClient(
        model="gpt-4o-mini",
        api_key=API_KEY,
    )
    
    alert_time = data_loader.parse_ts(alert['timestamp'])
    start_ts = (alert_time - timedelta(minutes=60)).isoformat().replace('+00:00', 'Z')
    end_ts = (alert_time + timedelta(minutes=30)).isoformat().replace('+00:00', 'Z')
    
    # Create agents
    planner = AssistantAgent(
        name="Planner",
        model_client=model_client,
        system_message=PLANNER_PROMPT,
    )
    
    investigator = AssistantAgent(
        name="Investigator",
        model_client=model_client,
        tools=create_tools(),
        system_message=build_investigator_prompt(alert, start_ts, end_ts),
    )
    
    reflector = AssistantAgent(
        name="Reflector",
        model_client=model_client,
        system_message=REFLECTOR_PROMPT,
    )
    
    termination = (
        TextMentionTermination("INVESTIGATION_COMPLETE") | 
        TextMentionTermination("NEED_MORE_DATA") |
        MaxMessageTermination(20)
    )
    
    team = RoundRobinGroupChat(
        [planner, investigator, reflector],
        termination_condition=termination,
    )
    
    task = f"""Investigate this incident:
Alert ID: {alert['alert_id']}
Service: {alert['service']}
Severity: {alert['severity']}
Message: {alert['message']}
Time: {alert['timestamp']}

Planner: Create an investigation plan.
Investigator: Execute the plan using tools.
Reflector: Analyze evidence and produce RCA."""
    
    all_messages = []
    
    try:
        if verbose:
            print(f"\n[TRACE] Starting 3-agent investigation")
            print(f"[TRACE] Agents: Planner -> Investigator -> Reflector")
            print(f"[TRACE] Time window: {start_ts} to {end_ts}\n")
        
        async for message in team.run_stream(task=task):
            if isinstance(message, TaskResult):
                all_messages = message.messages
            elif verbose:
                print_trace(message)
                all_messages.append(message)
        
        # Check if we need another iteration
        last_content = str(all_messages[-1].content) if all_messages else ""
        if "NEED_MORE_DATA" in last_content and memory.should_continue():
            memory.iteration += 1
            print(f"\n[TRACE] Reflector requested more data (iteration {memory.iteration})")
            # Could trigger another round here
        
        return extract_rca(all_messages, alert)
        
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        return build_fallback_rca(alert)


async def main():
    print("\n" + "#"*60)
    print("# AI-SRE: Multi-Agent Incident Investigation")
    print("# Architecture: Planner -> Investigator -> Reflector")
    print("#"*60)
    
    alert = DATA['alerts'][0]
    rca = await run_investigation(alert, verbose=True)
    
    print("\n" + "="*60)
    print("FINAL RCA")
    print("="*60)
    print(json.dumps(rca, indent=2))
    
    with open('rca_output.json', 'w') as f:
        json.dump(rca, f, indent=2)
    print(f"\nSaved to: rca_output.json")


if __name__ == "__main__":
    asyncio.run(main())
