"""Python-only refinement over resolved builtin numeric/collection domains.

Unknown object protocols are not trusted. Constraints are attached to immutable
value identities and joined by intersection of guaranteed predicate provenance.
"""
import ast
from dataclasses import replace
from .abstract import Interval


def pure_predicate(node,env,flow):
    if isinstance(node,ast.Constant):return type(node.value) in (int,float,bool,type(None))
    if isinstance(node,ast.Name):
        value=env.get(node.id)
        return bool(value and (value.numeric or value.boolean or value.collection_kind or value.literal_string))
    if isinstance(node,ast.UnaryOp):return pure_predicate(node.operand,env,flow)
    if isinstance(node,ast.BoolOp):return all(pure_predicate(n,env,flow) for n in node.values)
    if isinstance(node,ast.Compare):
        def numeric(expr):
            if isinstance(expr,ast.Constant):return type(expr.value) in (int,float,bool)
            if isinstance(expr,ast.Name):return bool(env.get(expr.id) and (env[expr.id].numeric or env[expr.id].boolean))
            if isinstance(expr,ast.UnaryOp):return numeric(expr.operand)
            if isinstance(expr,ast.BinOp):return numeric(expr.left) and numeric(expr.right)
            return isinstance(expr,ast.Call) and pure_predicate(expr,env,flow)
        if len(node.ops)==1 and isinstance(node.ops[0],(ast.In,ast.NotIn)):
            right=node.comparators[0]
            return numeric(node.left) and isinstance(right,(ast.List,ast.Tuple,ast.Set)) and all(isinstance(n,ast.Constant) and type(n.value) is int for n in right.elts)
        return all(numeric(n) for n in [node.left]+node.comparators)
    if isinstance(node,(ast.List,ast.Tuple,ast.Set)):return all(pure_predicate(n,env,flow) for n in node.elts)
    if isinstance(node,ast.Call):
        return (isinstance(node.func,ast.Name) and node.func.id=='len' and len(node.args)==1 and not node.keywords
            and isinstance(node.args[0],ast.Name) and bool(env.get(node.args[0].id) and env[node.args[0].id].collection_kind)
            and 'len' not in env and 'len' not in flow.functions and 'len' not in flow.aliases)
    return False


def refine(node,env,truth,flow):
    from .semantic import UNKNOWN, Value
    if flow.language!='python':return env.copy()
    if not flow.spend('iterations'):return env.copy()
    if isinstance(node,(ast.BoolOp,ast.UnaryOp)) and not pure_predicate(node,env,flow):return env.copy()
    for call in (n for n in ast.walk(node) if isinstance(n,ast.Call)):
        if not (isinstance(call.func,ast.Name) and call.func.id=='len' and len(call.args)==1 and isinstance(call.args[0],ast.Name) and env.get(call.args[0].id,UNKNOWN).collection_kind and not call.keywords and 'len' not in env and 'len' not in flow.functions and 'len' not in flow.aliases):
            return env.copy()
    if isinstance(node,ast.UnaryOp) and isinstance(node.op,ast.Not):return refine(node.operand,env,not truth,flow)
    if isinstance(node,ast.BoolOp):
        conjunct=isinstance(node.op,ast.And)
        if truth==conjunct:
            result=env.copy()
            for child in node.values:
                result=refine(child,result,truth,flow)
                if result is None:break
            return result
        # Alternative short-circuit paths join, never union must constraints.
        result=None;prefix=env.copy()
        for child in node.values:
            if flow.counts['iterations']>=flow.b.iterations:
                flow.gap('semantic_iterations_limit');return env.copy()
            branch=refine(child,prefix,truth,flow)
            if branch is not None:result=branch if result is None else {k:result.get(k,UNKNOWN).join(branch.get(k,UNKNOWN)) for k in result.keys()|branch.keys()}
            prefix=refine(child,prefix,not truth,flow)
            if prefix is None:break
        return result
    if isinstance(node,ast.Name) and env.get(node.id,UNKNOWN).boolean and env[node.id].truth is not None:
        return env.copy() if env[node.id].truth==truth else None
    if isinstance(node,ast.Constant) and type(node.value) is bool:
        return env.copy() if node.value==truth else None
    if not isinstance(node,ast.Compare):return env.copy()
    if len(node.ops)>1:
        parts=[ast.copy_location(ast.Compare(left=a,ops=[op],comparators=[b]),node) for a,op,b in zip([node.left]+node.comparators,node.ops,node.comparators)]
        return refine(ast.copy_location(ast.BoolOp(op=ast.And(),values=parts),node),env,truth,flow)
    if len(node.ops)!=1:return env.copy()
    if isinstance(node.left,ast.Constant) and isinstance(node.comparators[0],(ast.Name,ast.Call)):
        inverse={ast.Lt:ast.Gt,ast.LtE:ast.GtE,ast.Gt:ast.Lt,ast.GtE:ast.LtE,ast.Eq:ast.Eq,ast.NotEq:ast.NotEq}.get(type(node.ops[0]))
        if inverse:
            return refine(ast.copy_location(ast.Compare(left=node.comparators[0],ops=[inverse()],comparators=[node.left]),node),env,truth,flow)
    left,right=node.left,node.comparators[0];op=node.ops[0]
    # Recognize builtin len only for a known builtin collection abstraction.
    length=isinstance(left,ast.Call) and isinstance(left.func,ast.Name) and left.func.id=='len' and len(left.args)==1 and not left.keywords and 'len' not in env and 'len' not in flow.functions and 'len' not in flow.aliases
    subject=left.args[0] if length else left
    if not isinstance(subject,ast.Name):return env.copy()
    value=env.get(subject.id,UNKNOWN)
    if length and not value.collection_kind:return env.copy()
    if not length and not value.numeric:return env.copy()
    lower=value.size_lower if length else value.minimum
    upper=(value.size if value.size_verified else None) if length else value.maximum
    interval=Interval(lower,upper)
    if isinstance(op,(ast.In,ast.NotIn)) and not length:
        if not isinstance(right,(ast.List,ast.Tuple,ast.Set)) or not all(isinstance(n,ast.Constant) and type(n.value) is int and abs(n.value)<=10**9 for n in right.elts):return env.copy()
        values={n.value for n in right.elts}
        if isinstance(op,ast.NotIn):truth=not truth
        if truth:
            available=[n for n in values if (lower is None or n>=lower) and (upper is None or n<=upper)]
            if not available:return None
            constraint=Interval(min(available),max(available))
        else:
            if lower is not None and lower==upper and lower in values:return None
            return env.copy()
    else:
        if not isinstance(right,ast.Constant) or type(right.value) is not int or abs(right.value)>10**9:return env.copy()
        bound=right.value
        if not truth:
            op={ast.Lt:ast.GtE,ast.LtE:ast.Gt,ast.Gt:ast.LtE,ast.GtE:ast.Lt,ast.Eq:ast.NotEq,ast.NotEq:ast.Eq}.get(type(op),type(op))()
        integer=length or value.integer
        if isinstance(op,ast.Eq):constraint=Interval(bound,bound)
        elif isinstance(op,ast.NotEq):
            return None if lower is not None and lower==upper==bound else env.copy()
        elif isinstance(op,ast.Lt):constraint=Interval(None,bound-1 if integer else bound)
        elif isinstance(op,ast.LtE):constraint=Interval(None,bound)
        elif isinstance(op,ast.Gt):constraint=Interval(bound+1 if integer else bound,None)
        elif isinstance(op,ast.GtE):constraint=Interval(bound,None)
        else:return env.copy()
    refined=interval.meet(constraint)
    if refined is None:return None
    origins=tuple(sorted(set(value.constraint_origins+((flow.facts.module.id,node.lineno),))))
    result=env.copy()
    if length:
        refined=refined.meet(Interval(0,None))
        if refined is None:return None
        result[subject.id]=replace(value,size=refined.upper,size_verified=True,size_lower=refined.lower,constraint_origins=origins,constraint_must=True,constraint_value_id=value.value_id)
    else:
        result[subject.id]=replace(value,minimum=refined.lower,maximum=refined.upper,
            number=refined.lower if refined.lower==refined.upper else None,constraint_origins=origins,constraint_must=True,constraint_value_id=value.value_id)
    # Alias equality is used only where an existing exact value identity exists.
    if value.value_id:
        for key,other in env.items():
            if key!=subject.id and other.value_id==value.value_id:result[key]=result[subject.id]
    return result
