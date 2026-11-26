"""Offline static analysis CLI. Machine-readable stdout; controlled stderr diagnostics."""
import argparse
from importlib.metadata import version
import os
from pathlib import Path
import sys

from .config import load_settings, open_directory
from .errors import CliError, DirectorySymlinkError
from .reporting import JsonReportWriter
from .scanner import scan


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics echo arbitrary untrusted argument values.
        self.print_usage(sys.stderr)
        self.exit(2, 'argus: ARGUS_ARGUMENTS_INVALID: invalid arguments; use --help for accepted options.\n')


def write_output(path, report):
    output = Path(path).absolute()
    if not output.name.endswith(('.json', '.txt')):
        raise CliError('OUTPUT_SUFFIX_INVALID')
    # Pin the directory and create exclusively; never truncate or follow an existing object.
    try:
        parent_fd = open_directory(output.parent)
    except DirectorySymlinkError:
        raise CliError('OUTPUT_PARENT_SYMLINK') from None
    except (OSError, ValueError):
        raise CliError('OUTPUT_PARENT_UNAVAILABLE') from None
    try:
        try:
            fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=parent_fd)
        except FileExistsError:
            raise CliError('OUTPUT_ALREADY_EXISTS') from None
        try:
            stream = os.fdopen(fd, 'w', encoding='utf-8')
        except BaseException:
            os.close(fd)
            raise
        with stream:
            stream.write(report)
    except (OSError, UnicodeError):
        raise CliError('OUTPUT_WRITE_FAILED') from None
    finally:
        os.close(parent_fd)


def main(argv=None):
    parser = SafeParser(description='Local offline repository inventory and static architecture analysis.')
    parser.add_argument('--version', action='version', version=version('argus'))
    subs = parser.add_subparsers(dest='command')
    command = subs.add_parser('scan', help='Analyze static architecture in a local directory; unsupported portions disclosed')
    command.add_argument('path', metavar='PATH')
    command.add_argument('--format', choices=['json'], default='json', help='Versioned JSON (default)')
    command.add_argument('--output', metavar='FILE', help='Explicit new .json/.txt report; never overwrite')
    command.add_argument('--config', metavar='FILE', help='Local TOML configuration')
    command.add_argument('--exclude', metavar='PATTERN', action='append', default=[])
    command.add_argument('--verbose', action='store_true')
    args = parser.parse_args(argv)
    if args.command is None:
        parser.print_help()
        return 0

    def progress(count):
        if args.verbose and (count == 1 or count % 100 == 0):
            print(f'argus: inventory inspected {count} files; total unknown', file=sys.stderr)

    try:
        try:
            settings = load_settings(args.config, args.exclude)
        except (OSError, ValueError):
            raise CliError('CONFIG_INVALID') from None
        result = scan(args.path, settings, progress)
        report = JsonReportWriter().render(result)
        if args.output is not None:
            write_output(args.output, report)
        else:
            try:
                sys.stdout.write(report)
                sys.stdout.flush()
            except (OSError, UnicodeError):
                raise CliError('OUTPUT_WRITE_FAILED') from None
        if args.verbose:
            print(f'argus: inventory {result.inventory.status.value}; {len(result.files)} files; '
                  f'{len(result.coverage.inventory_gaps)} gaps; {len(result.findings)} findings; analysis partial', file=sys.stderr)
        if result.execution.cancelled:
            return 130
        if result.diagnostics or any(g.status.value == 'failed' for g in result.coverage.inventory_gaps):
            print('argus: inspection limitations recorded in report', file=sys.stderr)
            return 1
        return 0
    except CliError as error:
        print(f'argus: {error.code}: {error}', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('argus: cancelled before a report could be finalized', file=sys.stderr)
        return 130
    except Exception:
        error = CliError('INTERNAL_ERROR')
        print(f'argus: {error.code}: {error}', file=sys.stderr)
        return 70


def entrypoint():
    raise SystemExit(main())
