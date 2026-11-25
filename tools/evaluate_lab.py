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
         'complexity': ('ARGUS-MAINT-003','ARGUS-MAINT-004')}


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
        JsonReportWriter().render(result)
        after = fingerprints()
        paths = {f.id:f.path for f in result.files}
        module_paths = {m.id:paths[m.file_id] for m in result.modules}
        symbol_paths = {s.id:module_paths[s.module_id] for s in result.symbols}
        affected = {**module_paths, **symbol_paths}
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
                matching = [f for f in findings if rules and f['rule_id'] in rules and issue['path'] in f['paths']]
                comparisons.append({'issue_id':issue['id'], 'group':group,
                    'status': 'detected' if matching else 'missed' if rules else 'outside_implemented_rule_scope',
                    'rule_ids':[f['rule_id'] for f in matching]})
        rows.append({'repository':truth['repository'], 'seconds':round(elapsed,4),
            'fixture_hashes_unchanged':before == after,
            'fixture_matches_manifest':all(before.get(f['path']) == f['sha256'] for f in expected),
            'inventory_files':len(result.files), 'modules':len(result.modules),'symbols':len(result.symbols),
            'relationships':len(result.graph.relationships),'cycles':len(result.graph.cycles),
            'findings':findings,'comparisons':comparisons,
            'failed_files':sum(c.status.value == 'failed' for c in result.coverage.files),
            'unsupported_files':sum(c.status.value == 'unsupported' for c in result.coverage.files),
            'inventory_gaps':len(result.coverage.inventory_gaps),
            'negative_control':truth['future_analysis_rules']['negative_control']})
    return {'disclaimer':DISCLAIMER, 'method':'Default thresholds. Manifest issue IDs mapped explicitly to exact implemented rule scope; broad coupling/boundary/security/AI/cost allegations are outside exact threshold-rule scope. Unmatched findings require human review; no automatic precision claim.', 'repositories':rows}


if __name__ == '__main__':
    result = evaluate(Path(sys.argv[1]))
    output = Path(sys.argv[2])
    with output.open('x') as stream:
        json.dump(result,stream,indent=2)
    for row in result['repositories']:
        print(row['repository'], row['seconds'], 'seconds;',len(row['findings']),'findings;',row['cycles'],'cycles;', row['comparisons'])
