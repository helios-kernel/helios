"""Navigable tree view over ``InspectSnapshot`` with dynamic ``__dir__`` completion."""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any


def _sanitize_attr(segment: str) -> str:
    cleaned = segment.replace("-", "_").replace(".", "_").replace(":", "_")
    if cleaned and cleaned[0].isdigit():
        cleaned = f"n_{cleaned}"
    return cleaned


class InspectNode:
    """Hierarchical view of Helios inspect paths with dynamic ``__dir__`` completion.

    Example::

        tree = InspectNode.from_snapshot(await s.inspect())
        tree.kernel.processors.online  # 4
        tree["/core/http-client/status"]  # "healthy"
    """

    def __init__(self, path: str = "/", value: Any = None, *, has_value: bool = False) -> None:
        self._path = path
        self._value = value
        self._has_value = has_value
        self._children: dict[str, InspectNode] = {}
        self._attr_map: dict[str, str] = {}

    @classmethod
    def from_snapshot(cls, snapshot: Any) -> InspectNode:
        """Build a root :class:`InspectNode` tree from an ``InspectSnapshot`` or dict."""
        root = cls("/")
        mapping: dict[str, Any] = snapshot.to_dict() if hasattr(snapshot, "to_dict") else dict(snapshot)
        for full_path, val in mapping.items():
            root._insert(full_path, val)
        return root

    def _insert(self, full_path: str, val: Any) -> None:
        segments = [seg for seg in full_path.split("/") if seg]
        if not segments:
            self._value = val
            self._has_value = True
            return
        cur = self
        prefix = ""
        for seg in segments:
            prefix = f"{prefix}/{seg}"
            child = cur._children.get(seg)
            if child is None:
                child = InspectNode(prefix)
                cur._children[seg] = child
                attr = _sanitize_attr(seg)
                if attr.isidentifier() and attr not in cur._attr_map:
                    cur._attr_map[attr] = seg
            cur = child
        cur._value = val
        cur._has_value = True

    @property
    def path(self) -> str:
        return self._path

    @property
    def value(self) -> Any:
        return self._value

    @property
    def is_leaf(self) -> bool:
        return self._has_value and not self._children

    def keys(self) -> list[str]:
        return sorted(self._children.keys())

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if self._has_value:
            out[self._path] = self._value
        for child in self._children.values():
            out.update(child.to_dict())
        return out

    def __dir__(self) -> list[str]:
        base = set(super().__dir__())
        base.update(self._attr_map.keys())
        return sorted(base)

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        seg = self._attr_map.get(name, name)
        child = self._children.get(seg)
        if child is None:
            raise AttributeError(f"InspectNode({self._path!r}) has no child {name!r}")
        if child.is_leaf:
            return child._value
        return child

    def __getitem__(self, key: str) -> Any:
        if key.startswith("/"):
            segments = [seg for seg in key.split("/") if seg]
            cur = self
            for seg in segments:
                if seg not in cur._children:
                    raise KeyError(key)
                cur = cur._children[seg]
            return cur._value if cur.is_leaf else cur
        if key in self._children:
            child = self._children[key]
            return child._value if child.is_leaf else child
        if key in self._attr_map:
            child = self._children[self._attr_map[key]]
            return child._value if child.is_leaf else child
        raise KeyError(key)

    def __contains__(self, key: str) -> bool:
        try:
            self[key]
            return True
        except KeyError:
            return False

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._children.keys()))

    def __len__(self) -> int:
        return len(self._children)

    def _format_lines(self, prefix: str = "") -> list[str]:
        lines: list[str] = []
        items = sorted(self._children.items())
        for idx, (name, child) in enumerate(items):
            last = idx + 1 == len(items)
            branch = "└─ " if last else "├─ "
            if child.is_leaf:
                lines.append(f"{prefix}{branch}{name}: {child._value!r}")
            else:
                suffix = f" = {child._value!r}" if child._has_value else ""
                lines.append(f"{prefix}{branch}{name}/{suffix}")
                ext = "   " if last else "│  "
                lines.extend(child._format_lines(prefix + ext))
        return lines

    def __repr__(self) -> str:
        if self.is_leaf:
            return f"InspectNode(path={self._path!r}, value={self._value!r})"
        header = f"InspectNode({self._path})"
        body = self._format_lines()
        if not body:
            return header
        return "\n".join([header, *body])
