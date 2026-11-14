"""Structured response containers and protocol helpers for MCP tools."""
from __future__ import annotations

from typing import Any


class ToolResultListDict(dict):
    """Structured container that ensures atomic, single-block MCP response serialization while preserving list semantics.

    FastMCP converts any returned Python list into multiple separate TextContent blocks
    in the MCP protocol response. When intermediate MCP gateways or LLM clients parse
    the response, many gateways only inspect the last TextContent block, resulting in
    truncation (e.g. only returning the last project, file, or item).

    ToolResultListDict inherits from dict so FastMCP serializes the ENTIRE structure
    into a single TextContent JSON payload:
    {"status": "success", "count": N, "total": N, "<key>": items, "entries": items}

    Simultaneously, for Python unit tests and backward compatibility, it implements
    list-like iteration (__iter__), indexing (__getitem__ for int), length (__len__),
    and membership (__contains__).
    """

    def __init__(
        self,
        items: list[Any],
        key: str = "items",
        status: str = "success",
        **extra: Any,
    ) -> None:
        super().__init__()
        self["status"] = status
        self["total"] = len(items)
        self["count"] = len(items)
        self[key] = items
        if key != "entries":
            self["entries"] = items
        for k, v in extra.items():
            self[k] = v
        self._items = items

    def __iter__(self):
        return iter(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def __getitem__(self, item: Any) -> Any:
        if isinstance(item, (int, slice)):
            return self._items[item]
        return super().__getitem__(item)

    def __contains__(self, item: Any) -> bool:
        try:
            if super().__contains__(item):
                return True
        except TypeError:
            pass
        return item in self._items
