"""
PyGenGuard CLI - Production-Grade Command Line Security Tooling for GenAI & Agentic AI.

Commands:
- pygenguard scan <prompt_or_file> [--mode {strict,balanced,permissive,shadow}]
- pygenguard scan-data <dataset_file>
- pygenguard inspect-tool <tool_name> <arguments_json>
- pygenguard validate-policy <policy_file>
- pygenguard audit <logfile>
- pygenguard benchmark
- pygenguard version
"""

import sys
import os
import json
import argparse
import time
from typing import List, Dict, Any

# Ensure parent directory is in sys.path when invoked directly
parent_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

from pygenguard import Guard, Session, __version__
from pygenguard.policy import Policy


def cmd_version(args):
    """Print version and capabilities info."""
    print(f"PyGenGuard v{__version__} - Runtime Security & Governance for GenAI & Agentic AI")
    print("Zero-dependency core | 12 Defense Planes | Agentic Guardrails | Multi-tenancy")


def cmd_scan(args):
    """Scan prompt or JSONL file for vulnerabilities."""
    policy = None
    if getattr(args, "policy", None) and os.path.exists(args.policy):
        try:
            policy = Policy.from_file(args.policy)
            print(f"Loaded custom policy from: {args.policy}")
        except Exception as e:
            print(f"Warning: Failed to load policy file ({e}), falling back to mode '{args.mode}'")

    guard = Guard(mode=args.mode, policy=policy, audit_enabled=False)
    session = Session.create(user_id="cli_scanner")
    
    if os.path.isfile(args.target):
        print(f"Scanning dataset: {args.target}")
        total = 0
        blocked = 0
        degraded = 0
        start = time.perf_counter()
        
        with open(args.target, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    prompt = data.get("prompt") or data.get("text") or line
                except Exception:
                    prompt = line
                    
                total += 1
                dec = guard.inspect(prompt, session)
                if not dec.allowed:
                    blocked += 1
                    if args.verbose:
                        print(f"  [BLOCKED] Line {total}: {dec.rationale}")
                elif dec.action == "DEGRADE":
                    degraded += 1
                    if args.verbose:
                        print(f"  [DEGRADED] Line {total}: {dec.rationale}")
                        
        elapsed = (time.perf_counter() - start) * 1000
        print("\n--- Scan Results ---")
        print(f"Total Evaluated: {total}")
        print(f"Total Blocked:   {blocked} ({(blocked / max(1, total)) * 100:.1f}%)")
        print(f"Total Degraded:  {degraded} ({(degraded / max(1, total)) * 100:.1f}%)")
        print(f"Total Allowed:   {total - blocked}")
        print(f"Time Taken:      {elapsed:.2f} ms (avg {elapsed / max(1, total):.3f} ms/prompt)")
    else:
        prompt = args.target
        dec = guard.inspect(prompt, session)
        print("\n--- Prompt Inspection Result ---")
        print(f"Allowed:   {dec.allowed}")
        print(f"Action:    {dec.action}")
        print(f"Rationale: {dec.rationale}")
        print(f"Risk:      {dec.combined_risk_score:.2f}")
        for plane, res in dec.plane_results.items():
            print(f"  - {plane:14}: {'PASS' if res.passed else 'FAIL'} (risk: {res.risk_score:.2f}) -> {res.details}")


def cmd_scan_data(args):
    """Scan training data, fine-tuning samples, or scraped RAG docs for poisoning and phishing."""
    guard = Guard(mode=args.mode, audit_enabled=False)
    if not os.path.isfile(args.file):
        print(f"Error: File not found: {args.file}")
        sys.exit(1)

    print(f"Auditing training dataset for data poisoning and phishing lures: {args.file}")
    total = 0
    poisoned = 0
    start = time.perf_counter()

    with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                sample = data.get("text") or data.get("sample") or line
            except Exception:
                sample = line
            
            total += 1
            dec = guard.inspect_training_data(sample, source=args.file)
            if not dec.allowed:
                poisoned += 1
                if args.verbose:
                    print(f"  [POISONED/PHISHING] Sample #{total}: {dec.rationale}")

    elapsed = (time.perf_counter() - start) * 1000
    print("\n--- Training Data Audit Summary ---")
    print(f"Total Samples:   {total}")
    print(f"Poisoned/Lures:  {poisoned} ({(poisoned / max(1, total)) * 100:.1f}%)")
    print(f"Clean Samples:   {total - poisoned}")
    print(f"Inspection Time: {elapsed:.2f} ms")


def cmd_inspect_tool(args):
    """Inspect an agent tool call for unauthorized commands or parameter injections."""
    guard = Guard(audit_enabled=False)
    session = Session.create_agent_session(agent_id=args.agent_id)
    try:
        tool_args = json.loads(args.args_json)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON tool arguments: {e}")
        sys.exit(1)

    dec = guard.inspect_tool_call(
        tool_name=args.tool_name,
        arguments=tool_args,
        session=session,
    )
    print(f"\n--- Tool Call Inspection [{args.tool_name}] ---")
    print(f"Allowed:   {dec.allowed}")
    print(f"Action:    {dec.action}")
    print(f"Rationale: {dec.rationale}")
    print(f"Risk:      {dec.combined_risk_score:.2f}")


def cmd_validate_policy(args):
    """Validate and inspect a PyGenGuard policy YAML or JSON file."""
    if not os.path.isfile(args.policy_file):
        print(f"Error: Policy file not found: {args.policy_file}")
        sys.exit(1)

    try:
        policy = Policy.from_file(args.policy_file)
        print(f"Policy '{policy.name}' (version: {policy.version}) is VALID.")
        print(f"Mode: {policy.mode.value}")
        print(f"Configured Planes: {len(policy.planes)}")
        for plane_name, p in policy.planes.items():
            action_val = p.action_on_fail.value if hasattr(p.action_on_fail, "value") else str(p.action_on_fail)
            print(f"  - {plane_name}: action={action_val}, fail_open={p.fail_open}, timeout={p.timeout_ms}ms")
        print(f"Content Safety: {'Enabled' if policy.content_safety.enabled else 'Disabled'}")
        print(f"Rate Limiting:  {'Enabled' if policy.rate_limits.enabled else 'Disabled'}")
        audit_dest = policy.audit.log_destination.value if hasattr(policy.audit.log_destination, "value") else str(policy.audit.log_destination)
        print(f"Audit Target:   {audit_dest}")
    except Exception as e:
        print(f"Policy validation FAILED: {e}")
        sys.exit(1)


def cmd_audit(args):
    """Analyze and aggregate PyGenGuard audit log files."""
    if not os.path.isfile(args.logfile):
        print(f"Error: Audit log file not found: {args.logfile}")
        sys.exit(1)

    print(f"Analyzing PyGenGuard Audit Log: {args.logfile}")
    total = 0
    allows = 0
    blocks = 0
    degrades = 0
    planes_triggered: Dict[str, int] = {}

    with open(args.logfile, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
                total += 1
                action = entry.get("action", "").upper()
                if action == "ALLOW":
                    allows += 1
                elif action == "BLOCK":
                    blocks += 1
                elif action == "DEGRADE":
                    degrades += 1

                for plane, details in entry.get("plane_results", {}).items():
                    if isinstance(details, dict) and not details.get("passed", True):
                        planes_triggered[plane] = planes_triggered.get(plane, 0) + 1
            except Exception:
                continue

    print("\n--- Audit Log Aggregation ---")
    print(f"Total Evaluated Events: {total}")
    print(f"Allowed:                {allows} ({(allows / max(1, total)) * 100:.1f}%)")
    print(f"Blocked:                {blocks} ({(blocks / max(1, total)) * 100:.1f}%)")
    print(f"Degraded:               {degrades} ({(degrades / max(1, total)) * 100:.1f}%)")
    if planes_triggered:
        print("\nTop Planes Triggered:")
        for plane, count in sorted(planes_triggered.items(), key=lambda x: x[1], reverse=True):
            print(f"  - {plane:16}: {count} incidents")


def cmd_benchmark(args):
    """Run standardized security and latency benchmark suite."""
    print("=== Running PyGenGuard Standardized Benchmark Suite ===")
    from pygenguard.audit.benchmark import BenchmarkHarness
    harness = BenchmarkHarness()
    metrics = harness.run_all_suites()
    report = harness.format_markdown_report(metrics)
    print("\n" + report)
    print("\n--- Latency Performance ---")
    for m in metrics:
        print(f"  {m.suite_name}: {m.avg_latency_ms:.2f}ms (p95: {m.p95_latency_ms:.2f}ms)")
    print("\n--- Attack Vectors Blocked ---")
    for m in metrics:
        print(f"  {m.suite_name}: {m.true_positives}/{m.true_positives + m.false_negatives} blocked ({m.recall*100:.1f}%)")


def cmd_scan_batch(args):
    """Scan a list of prompts concurrently using ThreadPool/Async BatchScanner."""
    guard = Guard(mode=args.mode, audit_enabled=False)
    session = Session.create(user_id="cli_batch_scanner")

    prompts = []
    if os.path.isfile(args.file):
        with open(args.file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    prompts.append(line)
    else:
        prompts = [p.strip() for p in args.file.split(";") if p.strip()]

    print(f"Running concurrent batch scan on {len(prompts)} prompts (workers={args.workers})...")
    start = time.perf_counter()
    batch_result = guard.scan_batch(prompts, session=session, max_workers=args.workers)
    elapsed = (time.perf_counter() - start) * 1000.0

    print("\n--- Batch Scan Summary ---")
    print(f"Total Evaluated: {batch_result.total}")
    print(f"Passed / Allowed:{batch_result.allowed_count}")
    print(f"Blocked:         {batch_result.blocked_count}")
    print(f"Total Time:      {elapsed:.2f} ms ({batch_result.avg_latency_ms:.2f} ms/prompt avg)")


def cmd_route(args):
    """Evaluate prompt risk and determine safe model routing."""
    guard = Guard()
    decision = guard.route_safe(
        prompt=args.prompt,
        risk_score=args.risk_score,
        preferred_model=args.model,
    )
    print("\n--- Safe Model Route Decision ---")
    print(f"Selected Model:  {decision.selected_model}")
    print(f"Target Tier:     {decision.target_tier}")
    print(f"Fallback Active: {decision.fallback_applied}")
    print(f"Reason:          {decision.reason}")


def cmd_sanitize(args):
    """Sanitize prompt text to strip zero-width chars, homoglyphs, and delimiter tags."""
    guard = Guard()
    raw = args.text
    if os.path.isfile(raw):
        with open(raw, "r", encoding="utf-8") as f:
            raw = f.read()

    cleaned = guard.sanitize_prompt(raw)
    print("\n--- Sanitized Prompt ---")
    print(cleaned)


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="pygenguard",
        description="PyGenGuard CLI - Runtime Security & Governance for GenAI & Agentic AI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan a prompt or JSONL dataset")
    scan_parser.add_argument("target", help="Prompt string or path to .jsonl file")
    scan_parser.add_argument(
        "--mode",
        default="strict",
        choices=["strict", "balanced", "permissive", "shadow"],
        help="Guard mode preset (default: strict)",
    )
    scan_parser.add_argument("--policy", help="Optional path to custom policy YAML/JSON")
    scan_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan_parser.set_defaults(func=cmd_scan)

    # scan-data
    data_parser = subparsers.add_parser("scan-data", help="Audit training dataset for data poisoning & phishing")
    data_parser.add_argument("file", help="Path to JSONL or text training dataset")
    data_parser.add_argument("--mode", default="strict", choices=["strict", "balanced", "permissive"], help="Guard mode")
    data_parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    data_parser.set_defaults(func=cmd_scan_data)

    # inspect-tool
    tool_parser = subparsers.add_parser("inspect-tool", help="Inspect an agent tool call")
    tool_parser.add_argument("tool_name", help="Name of tool (e.g. bash, sql_query, file_writer)")
    tool_parser.add_argument("args_json", help="JSON string of tool arguments")
    tool_parser.add_argument("--agent-id", default="cli_agent", help="Agent identifier")
    tool_parser.set_defaults(func=cmd_inspect_tool)

    # validate-policy
    val_parser = subparsers.add_parser("validate-policy", help="Validate a policy YAML or JSON file")
    val_parser.add_argument("policy_file", help="Path to policy YAML or JSON file")
    val_parser.set_defaults(func=cmd_validate_policy)

    # audit
    audit_parser = subparsers.add_parser("audit", help="Analyze and aggregate audit log files")
    audit_parser.add_argument("logfile", help="Path to pygenguard audit JSONL file")
    audit_parser.set_defaults(func=cmd_audit)
    
    # benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Run latency and attack benchmark suite")
    bench_parser.set_defaults(func=cmd_benchmark)
    
    # scan-batch
    batch_parser = subparsers.add_parser("scan-batch", help="Concurrently scan a file or list of prompts")
    batch_parser.add_argument("file", help="Path to prompts file or semicolon-delimited prompts")
    batch_parser.add_argument("--mode", default="strict", choices=["strict", "balanced", "permissive"], help="Guard mode")
    batch_parser.add_argument("--workers", type=int, default=8, help="Concurrent worker threads")
    batch_parser.set_defaults(func=cmd_scan_batch)

    # route
    route_parser = subparsers.add_parser("route", help="Evaluate prompt risk and determine safe model routing")
    route_parser.add_argument("prompt", help="Input prompt text")
    route_parser.add_argument("--risk-score", type=float, default=0.0, help="Assessed risk score (0.0 - 1.0)")
    route_parser.add_argument("--model", default="gpt-4o", help="Preferred primary model")
    route_parser.set_defaults(func=cmd_route)

    # sanitize
    san_parser = subparsers.add_parser("sanitize", help="Sanitize prompt text and strip zero-width / delimiters")
    san_parser.add_argument("text", help="Prompt string or path to text file")
    san_parser.set_defaults(func=cmd_sanitize)

    # version
    ver_parser = subparsers.add_parser("version", help="Print version and capabilities")
    ver_parser.set_defaults(func=cmd_version)
    
    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
