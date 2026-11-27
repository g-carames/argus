"""Source-anchored control graph used by the abstract interpreter.

Each node is a one-operation basic block. Synthetic entry/exit/dispatch nodes have
no source location; all executable nodes reference an actual frontend node.
Finally is compiled on each exit channel, preserving the pending result/exception.
"""
import ast
from dataclasses import dataclass, field
from enum import StrEnum


class EdgeKind(StrEnum):
    NORMAL='normal'
    TRUE='true'
    FALSE='false'
    BACK='back'
    RETURN='return'
    RAISE='raise'
    BREAK='break'
    CONTINUE='continue'
    EXCEPTION='exception'
    HANDLER='handler'
    UNHANDLED='unhandled'
    FINALLY='finally'


@dataclass(frozen=True)
class Edge:
    target: int
    kind: EdgeKind = EdgeKind.NORMAL
    exception_types: tuple[str, ...] = ()


@dataclass
class Block:
    index: int
    kind: str
    source: object = None
    edges: tuple[Edge, ...] = ()
    loops: tuple[int, ...] = ()
    save: int | None = None
    id: str | None = None


@dataclass
class CFG:
    blocks: list = field(default_factory=list)
    entry: int = 0
    exits: tuple[int, ...] = ()
    truncated: bool = False
    module_id: str | None = None
    owner_id: str | None = None
    budget_used: int = 0


def build(body, limit=2048, python=True):
    g=CFG()
    if limit<5:
        return CFG([Block(0,'incomplete_exit')],0,(0,),True,budget_used=min(1,limit))
    class LimitReached(Exception):pass
    def node(kind,source=None,edges=(),loops=()):
        if len(g.blocks)>=limit:
            g.truncated=True
            raise LimitReached
        index=len(g.blocks);g.blocks.append(Block(index,kind,source,tuple(edges),loops));return index
    normal=node('normal_exit');returned=node('return_exit');raised=node('raise_exit')
    unsupported_exit=node('incomplete_exit')
    g.exits=(normal,returned,raised,unsupported_exit)
    def seq(statements,follow,ret,exc,brk=None,cont=None,loops=()):
        current=follow
        for n in reversed(statements):
            if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Import,ast.ImportFrom)): continue
            if isinstance(n,ast.If):
                left=seq(n.body,current,ret,exc,brk,cont,loops);right=seq(n.orelse,current,ret,exc,brk,cont,loops)
                current=node('branch',n,(Edge(left,EdgeKind.TRUE),Edge(right,EdgeKind.FALSE),Edge(exc,EdgeKind.EXCEPTION)),loops)
            elif isinstance(n,(ast.For,ast.AsyncFor,ast.While)):
                header=node('loop_test',n,loops=loops)
                inner=loops+(header,)
                back=node('back',n,(Edge(header,EdgeKind.BACK),),inner)
                done=seq(n.orelse,current,ret,exc,brk,cont,loops)
                loopbody=seq(n.body,back,ret,exc,current,back,inner)
                g.blocks[header].edges=(Edge(loopbody,EdgeKind.TRUE),Edge(done,EdgeKind.FALSE),Edge(exc,EdgeKind.EXCEPTION))
                current=node('loop_entry',n,(Edge(header),Edge(exc,EdgeKind.EXCEPTION)),loops)
            elif isinstance(n,ast.Try) and python:
                def finish(target,kind):
                    if not n.finalbody: return target
                    # Save pending control while finalbody runs. Its own return or
                    # raise goes to the enclosing channel, overriding pending exit.
                    resume=node('resume_'+kind,None,(Edge(target),),loops)
                    final=seq(n.finalbody,resume,ret,exc,brk,cont,loops)
                    save=node('finally_'+kind,None,(Edge(final,EdgeKind.FINALLY),),loops)
                    g.blocks[resume].save=save
                    return save
                normal_final=finish(current,'normal');return_final=finish(ret,'return');raise_final=finish(exc,'raise')
                break_final=finish(brk,'break') if brk is not None else None
                continue_final=finish(cont,'continue') if cont is not None else None
                dispatch=node('dispatch',n,loops=loops)
                edges=[]
                for handler in n.handlers:
                    target=seq(handler.body,normal_final,return_final,raise_final,break_final,continue_final,loops)
                    target=node('handler',handler,(Edge(target),),loops)
                    types=exception_names(handler.type)
                    edges.append(Edge(target,EdgeKind.HANDLER,types))
                edges.append(Edge(raise_final,EdgeKind.UNHANDLED))
                g.blocks[dispatch].edges=tuple(edges)
                success=seq(n.orelse,normal_final,return_final,raise_final,break_final,continue_final,loops)
                current=seq(n.body,success,return_final,dispatch,break_final,continue_final,loops)
            elif isinstance(n,ast.Return):current=node('return',n,(Edge(ret,EdgeKind.RETURN),Edge(exc,EdgeKind.EXCEPTION)),loops)
            elif isinstance(n,ast.Raise):current=node('raise',n,(Edge(exc,EdgeKind.RAISE),),loops)
            elif isinstance(n,(ast.Break,ast.Continue)):
                target=brk if isinstance(n,ast.Break) else cont
                current=node('jump' if target is not None else 'unsupported',n,(Edge(target if target is not None else current,EdgeKind.BREAK if isinstance(n,ast.Break) else EdgeKind.CONTINUE),),loops)
            elif isinstance(n,(ast.Assign,ast.AnnAssign,ast.AugAssign,ast.Expr,ast.Pass)) and not getattr(n,'argus_unsupported',False):
                current=node('operation',n,(Edge(current),Edge(exc,EdgeKind.EXCEPTION)),loops)
            else:
                # Nested expressions are retained for potential-operation discovery.
                current=node('unsupported',n,(Edge(current),Edge(exc,EdgeKind.EXCEPTION)),loops)
        return current
    try:
        start=seq(body,normal,returned,raised)
        g.entry=node('entry',edges=(Edge(start),))
    except LimitReached:
        return CFG([Block(0,'incomplete_exit')],0,(0,),True,budget_used=limit)
    g.budget_used=len(g.blocks)
    return g


BUILTIN_EXCEPTIONS={'BaseException','Exception','ValueError','TypeError','RuntimeError','KeyError','IndexError','LookupError','ArithmeticError','ZeroDivisionError','AssertionError','StopIteration','OSError'}
PARENTS={'ValueError':'Exception','TypeError':'Exception','RuntimeError':'Exception','KeyError':'LookupError','IndexError':'LookupError','LookupError':'Exception','ZeroDivisionError':'ArithmeticError','ArithmeticError':'Exception','AssertionError':'Exception','StopIteration':'Exception','OSError':'Exception','Exception':'BaseException'}


def exception_names(expr):
    if expr is None:return ('BaseException',)
    if isinstance(expr,ast.Tuple):return tuple(sorted({name for x in expr.elts for name in exception_names(x)}))
    return (expr.id,) if isinstance(expr,ast.Name) and expr.id in BUILTIN_EXCEPTIONS else ('?',)


def matches(actual, expected):
    if expected=='BaseException':return True
    if '?' in (actual,expected):return None
    while actual:
        if actual==expected:return True
        actual=PARENTS.get(actual)
    return False
