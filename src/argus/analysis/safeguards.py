"""Narrow framework observations. Registration is not runtime authentication proof."""
import ast


def function_guards(fn,aliases,globals):
    def name(n):
        if isinstance(n,ast.Name): return aliases.get(n.id,n.id)
        if isinstance(n,ast.Attribute): return name(n.value)+'.'+n.attr
        return ''
    guards=[]
    for dec in fn.decorator_list:
        if name(dec)=='flask_login.login_required':
            guards.append('flask_login_authentication_decorator')
    # HTTPBearer defaults enforce presence/format, not token validity or permissions.
    defaults=list(fn.args.defaults)+[d for d in fn.args.kw_defaults if d is not None]
    for d in defaults:
        if not isinstance(d,ast.Call) or name(d.func)!='fastapi.Depends' or not d.args: continue
        dep=d.args[0]
        value=globals.get(dep.id) if isinstance(dep,ast.Name) else None
        if value and value.receiver=='fastapi.security.HTTPBearer' and dict(value.attributes).get('auto_error',None) and dict(value.attributes)['auto_error'].number==1:
            guards.append('fastapi_bearer_presence_dependency')
    return tuple(sorted(set(guards)))
