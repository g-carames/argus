"""Argus backend contracts. No scanning capabilities are implemented yet."""


def main() -> None:
    """Keep the installed entry point honest during the contracts milestone."""
    import argparse
    from importlib.metadata import version

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=version("argus"))
    parser.parse_args()
    parser.print_help()
