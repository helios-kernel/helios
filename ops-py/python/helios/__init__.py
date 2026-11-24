"""Async-first Python operations SDK for Helios OS."""

from __future__ import annotations

from collections.abc import Generator, Sequence
from typing import Any

from helios._native import (
    AttenuationDeniedError,
    BundleManifest,
    Child,
    ComponentPublication,
    DiagnosticBundle,
    ExecResult,
    Fleet,
    HeliosError,
    InspectEntry,
    InspectSnapshot,
    Instance,
    NodeOutcome,
    RemoteEntry,
    RemoteStat,
    RpcError,
    Session,
    Target,
    TargetError,
    TargetStore,
    TraceEvent,
    TransportError,
)


class _ConnectContext:
    """Awaitable and async context manager returned by :func:`connect`.

    Supports both::

        session = await helios.connect("tcp://127.0.0.1:9443")

    and::

        async with helios.connect("tcp://127.0.0.1:9443") as session:
            ...
    """

    def __init__(
        self,
        target: Target | str | None = None,
        *,
        timeout_secs: float | None = None,
        scope: str | None = None,
        only: Sequence[str] | None = None,
        identity: str | None = None,
        targets_path: str | None = None,
    ) -> None:
        self._target = target
        self._timeout_secs = timeout_secs
        self._scope = scope
        self._only = list(only) if only is not None else None
        self._identity = identity
        self._targets_path = targets_path
        self._session: Session | None = None

    async def _open(self) -> Session:
        return await Session.connect(
            self._target,
            timeout_secs=self._timeout_secs,
            scope=self._scope,
            only=self._only,
            identity=self._identity,
            targets_path=self._targets_path,
        )

    def __await__(self) -> Generator[Any, None, Session]:
        return self._open().__await__()

    async def __aenter__(self) -> Session:
        self._session = await self._open()
        return await self._session.__aenter__()

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        session = self._session
        self._session = None
        if session is not None:
            return await session.__aexit__(exc_type, exc_val, exc_tb)
        return False


def connect(
    target: Target | str | None = None,
    *,
    timeout_secs: float | None = None,
    scope: str | None = None,
    only: Sequence[str] | None = None,
    identity: str | None = None,
    targets_path: str | None = None,
) -> _ConnectContext:
    """Connect asynchronously to a Helios node (`await` or `async with`)."""
    return _ConnectContext(
        target,
        timeout_secs=timeout_secs,
        scope=scope,
        only=only,
        identity=identity,
        targets_path=targets_path,
    )


def fleet(
    targets: Sequence[Target | str] | None = None,
    *,
    labels: Sequence[str] | None = None,
    concurrency: int = 16,
    timeout_secs: float | None = None,
    scope: str | None = None,
    only: Sequence[str] | None = None,
    identity: str | None = None,
    targets_path: str | None = None,
) -> Fleet:
    """Construct a bounded-concurrency :class:`Fleet` from explicit targets or label selectors."""
    only_list = list(only) if only is not None else None
    if labels is not None:
        if targets is not None:
            raise ValueError("specify either `targets` or `labels`, not both")
        return Fleet.from_labels(
            list(labels),
            concurrency=concurrency,
            timeout_secs=timeout_secs,
            scope=scope,
            only=only_list,
            identity=identity,
            targets_path=targets_path,
        )
    if targets is None:
        raise ValueError("fleet() requires either `targets` or `labels`")
    return Fleet.from_targets(
        list(targets),
        concurrency=concurrency,
        timeout_secs=timeout_secs,
        scope=scope,
        only=only_list,
        identity=identity,
        targets_path=targets_path,
    )


__all__ = [
    "AttenuationDeniedError",
    "BundleManifest",
    "Child",
    "ComponentPublication",
    "DiagnosticBundle",
    "ExecResult",
    "Fleet",
    "HeliosError",
    "InspectEntry",
    "InspectSnapshot",
    "Instance",
    "NodeOutcome",
    "RemoteEntry",
    "RemoteStat",
    "RpcError",
    "Session",
    "Target",
    "TargetError",
    "TargetStore",
    "TraceEvent",
    "TransportError",
    "connect",
    "fleet",
]
