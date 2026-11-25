"""Closed, trusted CLI diagnostics. Never interpolate repository or OS text."""

MESSAGES = {
    'INPUT_UNAVAILABLE': 'Scan input must be an existing accessible directory.',
    'INPUT_SYMLINK_COMPONENT': 'Scan input contains a symbolic-link component; use a non-symlink path. On macOS, use /private/tmp instead of /tmp.',
    'CONFIG_INVALID': 'Configuration is unreadable or invalid; expected supported [discovery]/[analysis] TOML settings and valid exclusion patterns.',
    'OUTPUT_PARENT_UNAVAILABLE': 'Output parent must be an existing accessible directory.',
    'OUTPUT_PARENT_SYMLINK': 'Output parent contains a symbolic-link component; use a non-symlink path. On macOS, use /private/tmp instead of /tmp.',
    'OUTPUT_ALREADY_EXISTS': 'Output destination already exists; Argus never overwrites existing objects.',
    'OUTPUT_SUFFIX_INVALID': 'Output filename must end in .json or .txt.',
    'OUTPUT_WRITE_FAILED': 'Report could not be written; a newly created partial file may remain.',
    'INTERNAL_ERROR': 'An unexpected internal failure prevented report completion; no exception details are disclosed.',
}


class CliError(ValueError):
    """Expected operational failure with a fixed public code and message."""

    def __init__(self, code):
        self.code = 'ARGUS_' + code
        super().__init__(MESSAGES[code])


class DirectorySymlinkError(ValueError):
    """A user-selected directory component is a link, including before '..'."""
