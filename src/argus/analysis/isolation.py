"""Bounded native parser/extractor process. Only trusted code executes in child."""
import multiprocessing
import os
import threading
from .parsing import parse, ParseFailure, ParseUnavailable
from .extraction import extract
from .risks import detect


def _worker(connection, file, content):
    try:
        # Prevent native crash diagnostics/core dumps from retaining source data.
        import resource
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
        fd = os.open(os.devnull, os.O_WRONLY)
        os.dup2(fd, 1)
        os.dup2(fd, 2)
        os.close(fd)
        parsed = parse(file.language, content)
        facts = extract(file, parsed)
        hits = detect(parsed)
        connection.send(('ok', facts, hits))
    except ParseUnavailable:
        connection.send(('unavailable',))
    except BaseException:
        connection.send(('failed',))
    finally:
        connection.close()


def isolated_extract(file, content, timeout=5):
    # Fork is restricted to the single-threaded POSIX CLI. Other platforms use spawn.
    context = multiprocessing.get_context('fork' if os.name == 'posix' and threading.active_count()==1 else 'spawn')
    receive, send = context.Pipe(duplex=False)
    process = context.Process(target=_worker, args=(send, file, content), daemon=True)
    try:
        process.start()
        send.close()
        if not receive.poll(timeout):
            raise ParseFailure()
        try:
            message = receive.recv()
        except (EOFError, OSError):
            raise ParseFailure() from None
        if message[0] == 'unavailable':
            raise ParseUnavailable()
        if message[0] != 'ok':
            raise ParseFailure()
        return message[1:]
    finally:
        receive.close()
        send.close()
        if process.pid is not None:
            if process.is_alive(): process.terminate()
            process.join(timeout=1)
            if process.is_alive():
                process.kill()
                process.join(timeout=1)
