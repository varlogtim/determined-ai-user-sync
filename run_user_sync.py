import argparse
import logging
import os
import sys
from typing import Optional

from det_user_sync import SourceGroups, SourceUser, UserSync

# XXX TODO:
# - Make usage.
# - Handle exceptions


def err(msg: str):
    sys.stderr.write(f"ERROR: {msg}\n")

def configure_logging(dry_run: bool = True) -> None:
    logging_format="%(asctime)s: %(levelname)s: %(message)s"
    if dry_run:
        logging_format="%(asctime)s: DRYRUN: %(levelname)s: %(message)s"

    logging.basicConfig(format=logging_format, level=logging.INFO)

if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        prog="run_user_sync",
        description="Synchronizes users and groups between a source and Determined AI",
        epilog="",
    )
    arg_parser.add_argument("--apply", default=False, action="store_true", help="actually apply the changes")
    arg_parser.add_argument("--source_func", required=True, help="<module>:<function_reference> which returns a SourceGroups object")
    arg_parser.add_argument("--func_args", nargs="*", help="arguments to the [source_func]")
    args = arg_parser.parse_args()

    source_func = args.source_func.split(":")
    if len(source_func) != 2:
        arg_parser.print_help()
        err("--func argument must be in the format '<module>:<function_reference>'")
        sys.exit(1)

    module_name, func_name = source_func
    try:
        module = __import__(module_name)
        func = getattr(module, func_name)
    except ModuleNotFoundError as e:
        arg_parser.print_help()
        err(f"Could not import module called '{module_name}'. See CSV example")
        sys.exit(1)
    except AttributeError as e:
        arg_parser.print_help()
        err(f"Could not import function called '{func_name}'. See CSV example")
        sys.exit(1)
    
    dry_run = not args.apply
    configure_logging(dry_run)

    user_sync = UserSync(func, args.func_args, dry_run)
    user_sync.sync_users()

