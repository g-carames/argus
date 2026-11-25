"""Offline inventory CLI. Machine-readable stdout; controlled stderr diagnostics."""
import argparse
from importlib.metadata import version
import os
from pathlib import Path
import sys

from .config import load_settings, open_directory
from .reporting import JsonReportWriter
from .scanner import scan


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        # argparse's default diagnostics echo arbitrary untrusted argument values.
        self.print_usage(sys.stderr)
        self.exit(2, 'argus: invalid arguments; use --help for accepted options.\n')


def write_output(path, report):
    output = Path(path).absolute()
    if output.parent != output.parent.resolve() or not output.parent.is_dir():
        raise ValueError('Output parent must be an existing directory without symbolic links')
    if not output.name.endswith(('.json', '.txt')):
        raise ValueError('Output must use .json or .txt; existing files are never overwritten')
    # Pin the directory and create exclusively; never truncate or follow an existing object.
    parent_fd = open_directory(output.parent)
    try:
        fd = os.open(output.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                     0o600, dir_fd=parent_fd)
        with os.fdopen(fd, 'w', encoding='utf-8') as stream:
            stream.write(report)
    finally:
        os.close(parent_fd)


def main(argv=None):
    parser = SafeParser(description='Local offline repository inventory. No static analysis adapters or risk rules are implemented.')
    parser.add_argument('--version', action='version', version=version('argus'))
    subs = parser.add_subparsers(dest='command')
    command = subs.add_parser('scan', help='Inventory a local directory; analysis remains Not Reviewed')
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
        settings = load_settings(args.config, args.exclude)
        result = scan(args.path, settings, progress)
        report = JsonReportWriter().render(result)
        if args.output:
            write_output(args.output, report)
        else:
            sys.stdout.write(report)
        if args.verbose:
            print(f'argus: inventory {result.inventory.status.value}; {len(result.files)} files; '
                  f'{len(result.coverage.inventory_gaps)} gaps; analysis Not Reviewed', file=sys.stderr)
        if result.execution.cancelled:
            return 130
        if result.diagnostics or any(g.status.value == 'failed' for g in result.coverage.inventory_gaps):
            print('argus: inspection limitations recorded in report', file=sys.stderr)
            return 1
        return 0
    except (OSError, ValueError, RuntimeError):
        print('argus: invalid or inaccessible input, configuration, or output; output must be a new .json/.txt file.', file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print('argus: cancelled before a report could be finalized', file=sys.stderr)
        return 130


def entrypoint():
    raise SystemExit(main())
