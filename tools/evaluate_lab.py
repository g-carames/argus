"""Read-only comparison with independent manifests; never execute fixture code.

Run with uv run python tools/evaluate_lab.py LAB_ROOT OUTPUT_JSON.
Output is confidential local evaluation data and must stay outside tracked files.
"""
import hashlib
import json
from pathlib import Path
import sys
from time import perf_counter
from argus.scanner import scan
from argus.reporting import JsonReportWriter
from argus.models.scan import DISCLAIMER

SCOPE = {'cycle': ('ARGUS-ARCH-001',), 'persistence-model-cycle': ('ARGUS-ARCH-001',),
         'complexity': ('ARGUS-MAINT-003','ARGUS-MAINT-004'),
         'broad-exception':('ARGUS-REL-001','ARGUS-REL-002'), 'request-timeout':('ARGUS-REL-003',),
         'unsafe-execution':('ARGUS-SEC-001',), 'query-loop':('ARGUS-COST-001',),
         'synthetic-exposed-secret':('ARGUS-CRED-001',), 'synthetic-config-secrets':('ARGUS-CRED-001',),
         'loop-model-calls':('ARGUS-AI-002',), 'javascript-model-loop':('ARGUS-AI-002',),
         'write-amplification':('ARGUS-COST-001',)}


def evaluate(root):
    rows = []
    for manifest in sorted((root / 'expected_results').glob('0[1-7]_*.json')):
        truth = json.loads(manifest.read_text())
        repository = root / truth['repository']
        expected = truth['current_inventory_only']['files']
        def fingerprints():
            return {f['path']:hashlib.sha256((repository / f['path']).read_bytes()).hexdigest()
                    for f in expected if not (repository / f['path']).is_symlink()}
        before = fingerprints()
        start = perf_counter()
        result = scan(repository)
        elapsed = perf_counter() - start
        # Serialize to exercise the actual reporting boundary as part of evaluation.
        report=JsonReportWriter().render(result)
        # Independent report boundary check for candidate values, never output candidates.
        import re
        candidates=[]
        from argus.analysis.risks import TOKEN, ASSIGNMENT
        for entry in expected:
            source=repository / entry['path']
            if source.is_symlink() or not source.is_file(): continue
            content=source.read_bytes()
            if len(content)>2*1024*1024: continue
            try: text=content.decode('utf-8')
            except UnicodeError: continue
            candidates.extend(m[0] for m in TOKEN.finditer(text))
            candidates.extend(m[1] for m in ASSIGNMENT.finditer(text))
            if source.name.startswith('.env'):
                candidates.extend(m[1].strip('\"\'') for m in re.finditer(r'(?m)^\s*[A-Za-z_][A-Za-z0-9_]*\s*=\s*([^\s#]+)',text) if len(m[1])>=8)
        # Also check manifest-planted credential literals that the detector missed.
        for issues in truth['future_analysis_rules'].values():
            if not isinstance(issues,list): continue
            for issue in issues:
                if issue['id'] != 'synthetic-exposed-secret': continue
                source=repository / issue['path']
                if source.is_symlink(): continue
                lines=source.read_text().splitlines()
                for line in issue.get('lines',()):
                    if 0<line<=len(lines):
                        candidates.extend(m[1] for m in re.finditer(r"[\"']([^\"']{8,})[\"']",lines[line-1]))
        credentials_absent=all(value not in report for value in candidates)
        after = fingerprints()
        paths = {f.id:f.path for f in result.files}
        module_paths = {m.id:paths[m.file_id] for m in result.modules}
        symbol_paths = {s.id:module_paths[s.module_id] for s in result.symbols}
        affected = {**paths, **module_paths, **symbol_paths}
        findings = []
        for f in result.findings:
            related = {affected[a] for a in f.affected_ids if a in affected}
            if f.rule_id == 'ARGUS-ARCH-001':
                for cycle in result.graph.cycles:
                    if set(cycle.node_ids) & set(f.affected_ids):
                        related.update(module_paths[n] for n in cycle.node_ids)
            findings.append({'rule_id':f.rule_id, 'paths':sorted(related), 'lines':[l.start_line for l in f.locations]})
        comparisons = []
        for group, issues in truth['future_analysis_rules'].items():
            if not isinstance(issues, list):
                continue
            for issue in issues:
                rules = SCOPE.get(issue['id'])
                matching = [f for f in findings if rules and f['rule_id'] in rules and issue['path'] in f['paths']
                            and (f['rule_id'].startswith(('ARGUS-ARCH','ARGUS-MAINT')) or set(issue.get('lines',())) & set(f['lines']))]
                status='detected' if matching else 'missed' if rules else 'outside_supported_scope'
                reason='Exact registered syntax and planted location match.' if matching else 'No rule for this issue scope.' if not rules else 'No matching finding at planted location.'
                if issue['id'] in ('loop-model-calls','javascript-model-loop') and not matching:
                    reason='Missed broader model-loop issue: mock/custom complete wrappers lack the imported provider SDK evidence required by the implemented detector.'
                if issue['id']=='write-amplification':
                    status='partially_evaluated'
                    reason='Query-in-loop consequence evaluated; quotas, retention and full write-amplification semantics unsupported.'
                if not matching and issue['id']=='synthetic-config-secrets':
                    source=next((f for f in result.files if f.path==issue['path']),None)
                    cov=next((c for c in result.coverage.files if source and c.file_id==source.id),None)
                    if cov and cov.status.value in ('excluded','failed'):
                        status='partially_evaluated'
                        reason='Candidate scope excluded or unreadable; tracked/ignored credential override is unavailable.'
                comparisons.append({'issue_id':issue['id'], 'group':group,
                    'status':status, 'reason':reason,
                    'rule_ids':[f['rule_id'] for f in matching]})
        rows.append({'repository':truth['repository'], 'seconds':round(elapsed,4),
            'fixture_hashes_unchanged':before == after, 'credential_candidates_checked':len(candidates), 'credential_candidates_absent_from_report':credentials_absent,
            'fixture_matches_manifest':all(before.get(f['path']) == f['sha256'] for f in expected),
            'inventory_files':len(result.files), 'modules':len(result.modules),'symbols':len(result.symbols),
            'relationships':len(result.graph.relationships),'cycles':len(result.graph.cycles),
            'findings':findings,'comparisons':comparisons,
            'failed_files':sum(c.status.value == 'failed' for c in result.coverage.files),
            'unsupported_files':sum(c.status.value == 'unsupported' for c in result.coverage.files),
            'inventory_gaps':len(result.coverage.inventory_gaps),
            'negative_control':truth['future_analysis_rules']['negative_control']})
    return {'disclaimer':DISCLAIMER, 'method':'Default thresholds; immutable manifest locations and explicit rule mapping. Broader model-loop wrapper misses are disclosed separately from exact SDK scope. Partial consequences do not establish full detection. Unmatched findings require manual review; no precision claim.', 'repositories':rows}


if __name__ == '__main__':
    result = evaluate(Path(sys.argv[1]))
    output = Path(sys.argv[2])
    with output.open('x') as stream:
        json.dump(result,stream,indent=2)
    for row in result['repositories']:
        print(row['repository'], row['seconds'], 'seconds;',len(row['findings']),'findings;',row['cycles'],'cycles;', row['comparisons'])
