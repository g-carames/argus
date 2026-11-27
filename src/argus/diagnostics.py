"""Diagnostic categories and deterministic consolidation; never hides locations."""
from dataclasses import replace
from .models.scan import DiagnosticClass as D


def classify(code, message=''):
    if code=='semantic_analysis_incomplete':
        if 'limit' in message: return D.RESOURCE
        if 'unresolved' in message or 'unverified' in message: return D.UNRESOLVED
        return D.PARTIAL
    if code=='grammar_unavailable': return D.UNSUPPORTED
    if any(token in code for token in ('limit','budget','timeout','too_large','depth')): return D.RESOURCE
    return D.FAILURE


def consolidate(diagnostics):
    groups={}
    for diagnostic in diagnostics:
        key=(diagnostic.code,diagnostic.stage,diagnostic.message)
        groups.setdefault(key,[]).append(diagnostic)
    output=[]
    for key,items in sorted(groups.items()):
        locations=tuple(sorted({loc for d in items for loc in ((d.location,) if d.location else ())+d.affected_locations},key=lambda l:(l.path,l.start_line,l.start_column)))
        output.append(replace(items[0],classification=classify(items[0].code,items[0].message),
            location=locations[0] if locations else None,affected_locations=locations,occurrences=sum(i.occurrences for i in items)))
    return tuple(output)
