"""Entrypoint invoked by ``helios python`` and ``helios vm ... python``.

Reads target, fleet, identity, and attenuation context from environment
variables set by the ``helios`` CLI:

- ``HELIOS_TARGET``: target name from ``targets.toml`` or direct URI
- ``HELIOS_LABELS``: comma-separated ``k=v`` fleet label selectors
- ``HELIOS_CONCURRENCY``: fleet concurrency bound (default 16)
- ``HELIOS_IDENTITY``: identity profile name or path
- ``HELIOS_SCOPE``: capability subtree scope (e.g. ``/core/http``)
- ``HELIOS_ONLY``: comma-separated capability rights
- ``HELIOS_TARGETS_PATH``: optional path overriding ``targets.toml``

Supports inline code (``-c <code>``), scripts (``<script.py> [args...]``), and
an interactive async-capable REPL with top-level ``await`` and ``rlcompleter``
``<Tab>`` completion.
"""

from __future__ import annotations

import ast
import asyncio
import codeop
import inspect as py_inspect
import os
import sys
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import helios

DEFAULT_CONCURRENCY = 16


@dataclass(frozen=True)
class CliContextConfig:
    target: str | None
    labels: list[str]
    concurrency: int
    identity: str | None
    scope: str | None
    only: list[str] | None
    targets_path: str | None

    @classmethod
    def from_env(cls) -> CliContextConfig:
        target = _non_empty_env("HELIOS_TARGET")
        labels_raw = _non_empty_env("HELIOS_LABELS")
        labels = [item.strip() for item in labels_raw.split(",") if item.strip()] if labels_raw else []
        concurrency_raw = _non_empty_env("HELIOS_CONCURRENCY")
        concurrency = DEFAULT_CONCURRENCY
        if concurrency_raw is not None:
            try:
                concurrency = max(1, int(concurrency_raw))
            except ValueError as exc:
                raise ValueError(f"HELIOS_CONCURRENCY must be an integer, got {concurrency_raw!r}") from exc
        identity = _non_empty_env("HELIOS_IDENTITY")
        scope = _non_empty_env("HELIOS_SCOPE")
        only_raw = _non_empty_env("HELIOS_ONLY")
        only = [item.strip() for item in only_raw.split(",") if item.strip()] if only_raw else None
        targets_path = _non_empty_env("HELIOS_TARGETS_PATH")
        return cls(
            target=target,
            labels=labels,
            concurrency=concurrency,
            identity=identity,
            scope=scope,
            only=only,
            targets_path=targets_path,
        )


def _non_empty_env(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None:
        return None
    stripped = value.strip()
    return stripped if stripped else None


async def _open_context(cfg: CliContextConfig) -> tuple[helios.Session | None, helios.Fleet | None]:
    if cfg.labels:
        fleet_obj = helios.Fleet.from_labels(
            cfg.labels,
            concurrency=cfg.concurrency,
            scope=cfg.scope,
            only=cfg.only,
            identity=cfg.identity,
            targets_path=cfg.targets_path,
        )
        primary_session: helios.Session | None = None
        if fleet_obj.targets:
            primary_session = await helios.connect(
                fleet_obj.targets[0],
                scope=cfg.scope,
                only=cfg.only,
                identity=cfg.identity,
                targets_path=cfg.targets_path,
            )
        return primary_session, fleet_obj

    if cfg.target is not None:
        session = await helios.connect(
            cfg.target,
            scope=cfg.scope,
            only=cfg.only,
            identity=cfg.identity,
            targets_path=cfg.targets_path,
        )
        return session, None

    return None, None


def _build_namespace(
    session: helios.Session | None,
    fleet_obj: helios.Fleet | None,
    cfg: CliContextConfig,
) -> dict[str, Any]:
    ns: dict[str, Any] = {
        "__name__": "__main__",
        "__builtins__": __builtins__,
        "asyncio": asyncio,
        "sys": sys,
        "helios": helios,
        "session": session,
        "fleet": fleet_obj,
        "helios_config": cfg,
    }
    if session is not None:
        ns["inspect"] = session.inspect
        ns["kernel_snapshot"] = session.kernel_snapshot
        ns["ps"] = session.ps
        ns["kill"] = session.kill
        ns["trace"] = session.trace_recent
        ns["bundle"] = session.bundle
    elif fleet_obj is not None:
        ns["inspect"] = fleet_obj.inspect
        ns["ps"] = fleet_obj.ps
    return ns


def _compile_with_top_level_await(source: str, filename: str, mode: str) -> Any:
    return compile(source, filename, mode, flags=ast.PyCF_ALLOW_TOP_LEVEL_AWAIT, dont_inherit=True)


async def _run_code_async(
    source: str,
    filename: str,
    cfg: CliContextConfig,
    argv: list[str],
) -> None:
    session, fleet_obj = await _open_context(cfg)
    ns = _build_namespace(session, fleet_obj, cfg)
    if filename != "<string>":
        ns["__file__"] = filename
    sys.argv = argv
    compiled = _compile_with_top_level_await(source, filename, "exec")
    result = eval(compiled, ns)
    if py_inspect.iscoroutine(result):
        await result


def _run_code_sync_or_async(
    source: str,
    filename: str,
    cfg: CliContextConfig,
    argv: list[str],
) -> int:
    compiled = _compile_with_top_level_await(source, filename, "exec")
    is_top_level_async = bool(compiled.co_flags & py_inspect.CO_COROUTINE)
    if is_top_level_async:
        asyncio.run(_run_code_async(source, filename, cfg, argv))
        return 0

    session, fleet_obj = (None, None)
    if cfg.target is not None or cfg.labels:
        session, fleet_obj = asyncio.run(_open_context(cfg))
    ns = _build_namespace(session, fleet_obj, cfg)
    if filename != "<string>":
        ns["__file__"] = filename
    sys.argv = argv
    exec(compiled, ns)
    return 0


def _configure_readline(namespace: dict[str, Any]) -> None:
    try:
        import readline
        import rlcompleter
    except ImportError:
        return
    readline.set_completer(rlcompleter.Completer(namespace).complete)
    doc = getattr(readline, "__doc__", "") or ""
    if "libedit" in doc:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")


class AsyncInteractiveConsole:
    """Interactive Python REPL supporting top-level ``await`` and ``rlcompleter`` completion."""

    def __init__(self, namespace: dict[str, Any], loop: asyncio.AbstractEventLoop) -> None:
        self.namespace = namespace
        self.loop = loop
        self.compiler = codeop.CommandCompiler()
        self.compiler.compiler.flags |= ast.PyCF_ALLOW_TOP_LEVEL_AWAIT
        self._buffer: list[str] = []

    def push(self, line: str) -> bool:
        """Push one input line; return ``True`` when more lines are needed for a block."""
        self._buffer.append(line)
        source = "\n".join(self._buffer)
        try:
            code = self.compiler(source, "<stdin>", "single")
        except (OverflowError, SyntaxError, ValueError):
            self._buffer.clear()
            traceback.print_exc(limit=0)
            return False

        if code is None:
            return True

        self._buffer.clear()
        try:
            outcome = eval(code, self.namespace)
            if py_inspect.iscoroutine(outcome):
                self.loop.run_until_complete(outcome)
        except SystemExit:
            raise
        except BaseException:
            traceback.print_exc()
        return False

    def interact(self, banner: str) -> int:
        is_tty = sys.stdin.isatty()
        if is_tty:
            _configure_readline(self.namespace)
            print(banner, flush=True)

        more = False
        while True:
            prompt = "... " if more else ">>> "
            try:
                line = input(prompt) if is_tty else _read_non_tty_line()
            except KeyboardInterrupt:
                self._buffer.clear()
                more = False
                if is_tty:
                    print("\nKeyboardInterrupt", flush=True)
                continue
            except EOFError:
                if self._buffer:
                    self.push("")
                if is_tty:
                    print(flush=True)
                return 0
            try:
                more = self.push(line)
            except SystemExit as exc:
                code = exc.code
                return code if isinstance(code, int) else 0


def _read_non_tty_line() -> str:
    raw = sys.stdin.readline()
    if raw == "":
        raise EOFError
    return raw.rstrip("\r\n")


def _run_repl(cfg: CliContextConfig) -> int:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        session, fleet_obj = loop.run_until_complete(_open_context(cfg))
        ns = _build_namespace(session, fleet_obj, cfg)
        if session is not None:
            target_desc = f"{session.target.name} ({session.target.uri})"
            bound = "session, inspect, ps, helios"
        elif fleet_obj is not None:
            target_desc = f"fleet ({len(fleet_obj.targets)} targets)"
            bound = "fleet, inspect, ps, helios"
        else:
            target_desc = "disconnected (use `await helios.connect(...)`)"
            bound = "helios, asyncio, sys"
        banner = (
            f"Helios Python async REPL [{target_desc}]\n"
            f"Pre-bound: {bound}. Top-level `await` and <Tab> completion enabled."
        )
        console = AsyncInteractiveConsole(ns, loop)
        return console.interact(banner)
    finally:
        loop.close()


def _parse_args(argv: list[str]) -> tuple[str | None, Path | None, list[str]]:
    if not argv:
        return None, None, []
    if argv[0] == "-c":
        if len(argv) < 2:
            raise ValueError("option -c requires a Python code argument")
        return argv[1], None, ["-c", *argv[2:]]
    if argv[0] in ("-h", "--help"):
        print(
            "usage: python -m helios._cli_entry [-c CODE | SCRIPT [ARGS...]]\n"
            "Starts an async Helios Python REPL when neither -c nor SCRIPT is given."
        )
        raise SystemExit(0)
    script = Path(argv[0])
    return None, script, [str(script), *argv[1:]]


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    try:
        cfg = CliContextConfig.from_env()
        inline_code, script_path, script_argv = _parse_args(args)
        if inline_code is not None:
            return _run_code_sync_or_async(inline_code, "<string>", cfg, script_argv)
        if script_path is not None:
            script_dir = str(script_path.resolve().parent)
            if script_dir not in sys.path:
                sys.path.insert(0, script_dir)
            source = script_path.read_text(encoding="utf-8")
            return _run_code_sync_or_async(source, str(script_path), cfg, script_argv)
        return _run_repl(cfg)
    except SystemExit as exc:
        code = exc.code
        return code if isinstance(code, int) else 0
    except Exception as exc:
        print(f"helios python error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
