#!/usr/bin/env python3
"""Focused direct-load integration check for an interactive Python REPL.

The freeze-time interpreter and the frozen artifact both run on a real PTY.
This deliberately exercises terminal-owned tracing, runtime file capture, and
the interactive frontend instead of replacing stdin with a pipe.

Usage:
    tests/python_repl_pty.py [--dlfreeze build/dlfreeze] [--python python3]
"""

from __future__ import annotations

import argparse
import errno
import fcntl
import os
import pty
import select
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence


PROMPT = b">>> "
TRACE_INPUT = (
    b'print("DLFREEZE_" + "TRACE_READY", 6 * 7)\n'
    b"raise SystemExit\n"
)
TRACE_MARKER = "DLFREEZE_TRACE_READY 42"
RUNTIME_INPUT = (
    b'print("DLFREEZE_" + "REPL_OK", 6 * 7)\n'
    b"raise SystemExit\n"
)
RUNTIME_MARKER = "DLFREEZE_REPL_OK 42"


class CheckFailure(RuntimeError):
    pass


@dataclass
class PtyResult:
    returncode: int
    output: str
    saw_prompt: bool


def wait_status_to_returncode(status: int) -> int:
    if os.WIFEXITED(status):
        return os.WEXITSTATUS(status)
    if os.WIFSIGNALED(status):
        return -os.WTERMSIG(status)
    return 125


def descendants(pid: int) -> List[int]:
    """Return Linux descendants, deepest first, for timeout cleanup."""
    found: List[int] = []
    pending = [pid]
    while pending:
        parent = pending.pop()
        try:
            text = Path(f"/proc/{parent}/task/{parent}/children").read_text()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
        children = [int(value) for value in text.split()]
        found.extend(children)
        pending.extend(children)
    found.reverse()
    return found


def terminate_tree(pid: int) -> None:
    for child in descendants(pid):
        try:
            os.kill(child, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_on_pty(
    command: Sequence[str],
    environment: Dict[str, str],
    input_after_prompt: bytes,
    timeout: float,
    verbose: bool,
) -> PtyResult:
    pid, master_fd = pty.fork()
    if pid == 0:
        try:
            os.execvpe(command[0], list(command), environment)
        except BaseException as error:  # only reached before exec
            os.write(2, f"exec failed: {error}\n".encode())
            os._exit(127)

    # Give terminal frontends a conventional geometry rather than the PTY's
    # implementation-defined initial size.
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ,
                struct.pack("HHHH", 24, 80, 0, 0))
    descriptor_flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
    fcntl.fcntl(master_fd, fcntl.F_SETFL,
                descriptor_flags | os.O_NONBLOCK)
    deadline = time.monotonic() + timeout
    output = bytearray()
    sent_input = False
    saw_eof = False
    status: Optional[int] = None

    try:
        while status is None or not saw_eof:
            if time.monotonic() >= deadline:
                terminate_tree(pid)
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
                rendered = output.decode("utf-8", "replace")
                raise CheckFailure(
                    f"PTY command timed out after {timeout:.0f}s: "
                    f"{shlex_join(command)}\n{rendered}"
                )

            ready, _, _ = select.select([master_fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        chunk = b""
                    elif error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        chunk = None
                    else:
                        raise
                if chunk is None:
                    pass
                elif chunk:
                    output.extend(chunk)
                    if verbose:
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                    if not sent_input and PROMPT in output:
                        os.write(master_fd, input_after_prompt)
                        sent_input = True
                else:
                    saw_eof = True

            if status is None:
                waited, candidate = os.waitpid(pid, os.WNOHANG)
                if waited == pid:
                    status = candidate

            if status is not None and not ready:
                # A final read observes either pending output or PTY EIO.
                try:
                    chunk = os.read(master_fd, 65536)
                except OSError as error:
                    if error.errno == errno.EIO:
                        saw_eof = True
                        continue
                    if error.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                        continue
                    raise
                if chunk:
                    output.extend(chunk)
                    if verbose:
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                else:
                    saw_eof = True
    finally:
        os.close(master_fd)

    assert status is not None
    return PtyResult(
        wait_status_to_returncode(status),
        output.decode("utf-8", "replace"),
        sent_input,
    )


def shlex_join(command: Sequence[str]) -> str:
    try:
        import shlex

        return shlex.join(command)
    except (AttributeError, ImportError):
        return " ".join(repr(part) for part in command)


def require_success(phase: str, result: PtyResult, marker: str) -> None:
    failures = []
    if result.returncode != 0:
        failures.append(f"exit status {result.returncode}")
    if not result.saw_prompt:
        failures.append("interactive prompt was not observed")
    if marker not in result.output:
        failures.append(f"semantic marker {marker!r} was not produced")
    if "not in frozen image" in result.output.lower():
        failures.append("runtime loaded an uncaptured library from disk")
    if failures:
        raise CheckFailure(
            f"{phase} failed: {', '.join(failures)}\n--- PTY output ---\n"
            f"{result.output}"
        )


def resolve_program(value: str, label: str) -> str:
    resolved = shutil.which(value) if os.sep not in value else value
    if not resolved:
        raise CheckFailure(f"cannot find {label}: {value}")
    path = str(Path(resolved).resolve())
    if not os.access(path, os.X_OK):
        raise CheckFailure(f"{label} is not executable: {path}")
    return path


def python_stdlib(python: str) -> str:
    try:
        raw = subprocess.check_output(
            [
                python,
                "-I",
                "-c",
                "import os,sysconfig; "
                "print(os.path.realpath(sysconfig.get_path('stdlib')))",
            ],
            text=True,
            stderr=subprocess.STDOUT,
        )
    except subprocess.CalledProcessError as error:
        raise CheckFailure(
            f"cannot determine Python stdlib path:\n{error.output}"
        ) from error
    path = raw.strip()
    if not path or not Path(path).is_dir():
        raise CheckFailure(f"invalid Python stdlib path: {path!r}")
    return path


def run_check(args: argparse.Namespace, work: Path) -> None:
    dlfreeze = resolve_program(args.dlfreeze, "dlfreeze")
    python = resolve_program(args.python, "Python")
    stdlib = python_stdlib(python)
    artifact = work / "python-repl.frozen"
    file_pattern = stdlib.rstrip("/") + "/*"

    environment = dict(os.environ)
    environment.pop("DLFREEZE_NO_FORK", None)
    environment.pop("PYTHON_BASIC_REPL", None)
    environment["TERM"] = args.term

    freeze_command = [
        dlfreeze,
        "-d",
        "-t",
        "-f",
        file_pattern,
        "-o",
        str(artifact),
        "--",
        python,
        "-I",
        "-q",
    ]
    traced = run_on_pty(
        freeze_command,
        environment,
        TRACE_INPUT,
        args.freeze_timeout,
        args.verbose,
    )
    require_success("freeze-time REPL", traced, TRACE_MARKER)
    if "mode       : direct-load" not in traced.output:
        raise CheckFailure(
            "packer did not produce a direct-load artifact\n"
            f"--- PTY output ---\n{traced.output}"
        )
    if not artifact.is_file() or not os.access(artifact, os.X_OK):
        raise CheckFailure(f"frozen artifact was not created: {artifact}")

    strict_environment = dict(environment)
    strict_environment["DLFREEZE_NO_FORK"] = "1"
    strict = run_on_pty(
        [str(artifact), "-I", "-q"],
        strict_environment,
        RUNTIME_INPUT,
        args.run_timeout,
        args.verbose,
    )
    require_success("strict frozen REPL", strict, RUNTIME_MARKER)

    supervised = run_on_pty(
        [str(artifact), "-I", "-q"],
        environment,
        RUNTIME_INPUT,
        args.run_timeout,
        args.verbose,
    )
    require_success("supervised frozen REPL", supervised, RUNTIME_MARKER)

    print(
        "PASS: Python REPL trace and strict/supervised direct-load PTY runs "
        f"({python}, stdlib {stdlib})"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dlfreeze", default="build/dlfreeze")
    parser.add_argument("--python", default="python3")
    parser.add_argument("--term", default="xterm-256color")
    parser.add_argument("--freeze-timeout", type=float, default=240.0)
    parser.add_argument("--run-timeout", type=float, default=60.0)
    parser.add_argument(
        "--work-dir",
        help="keep/use this directory instead of a temporary directory",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        if args.work_dir:
            work = Path(args.work_dir).resolve()
            work.mkdir(parents=True, exist_ok=True)
            run_check(args, work)
        else:
            with tempfile.TemporaryDirectory(prefix="dlfreeze-python-repl-") as tmp:
                run_check(args, Path(tmp))
    except (CheckFailure, OSError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
