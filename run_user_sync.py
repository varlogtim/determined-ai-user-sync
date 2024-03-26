import argparse
import logging
import sys
import time
from typing import Callable

import det_user_sync

seconds_in_minute = 60


def err(msg: str) -> None:
    sys.stderr.write(f"ERROR: {msg}\n")


def configure_logging(dry_run: bool = True) -> None:
    logging_format = "%(asctime)s: %(levelname)s: %(message)s"
    if dry_run:
        logging_format = "%(asctime)s: DRYRUN: %(levelname)s: %(message)s"

    logging.basicConfig(format=logging_format, level=logging.INFO)


def run(func: Callable, func_args: list, dry_run: bool, period_mins: int) -> None:
    user_sync = det_user_sync.UserSync(func, func_args, dry_run)

    if period_mins < 1:
        logging.info("running once")
        user_sync.sync_users()
        return

    logging.info(f"running as service with period of {args.period_mins} minutes")
    while True:
        start_time = time.time()
        logging.info("started user sync run")

        user_sync.sync_users()

        logging.info("ended user sync run")
        end_time = time.time()

        # XXX do we even need this?
        if end_time - start_time > seconds_in_minute * period_mins:
            logging.warn("the script seems to be taking longer than the wait period?")

        time.sleep(seconds_in_minute * period_mins)


if __name__ == "__main__":
    arg_parser = argparse.ArgumentParser(
        prog="run_user_sync",
        description="Synchronizes users and groups between a source and Determined AI",
        epilog="",
    )
    arg_parser.add_argument(
        "--apply", default=False, action="store_true", help="actually apply the changes"
    )
    arg_parser.add_argument(
        "--period-mins",
        type=int,
        default=0,
        help="execution period in minutes, defaults to single run",
    )
    arg_parser.add_argument(
        "--source-func",
        required=True,
        help="<module>:<function_reference> which returns a SourceGroups object",
    )
    arg_parser.add_argument(
        "--func-args", nargs="*", help="arguments to the [source_func]"
    )
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
    except ModuleNotFoundError:
        arg_parser.print_help()
        err(f"Could not import module called '{module_name}'. See CSV example")
        sys.exit(1)
    except AttributeError:
        arg_parser.print_help()
        err(f"Could not import function called '{func_name}'. See CSV example")
        sys.exit(1)

    dry_run = not args.apply
    configure_logging(dry_run)

    run(func, args.func_args, dry_run, args.period_mins)
