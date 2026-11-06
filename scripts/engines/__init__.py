#!/usr/bin/env python3
"""engines/__init__.py - engine registry, shape detection and validation."""

from __future__ import annotations

from typing import Optional, Sequence, Tuple

import core
from . import v1, v2

MODULES = {"v1": v1, "v2": v2}
SHAPE_KEYS = {"v1": v1.SHAPE_KEY, "v2": v2.SHAPE_KEY}


def get(engine: str):
    """Return the engine module for `v1` or `v2`."""
    try:
        return MODULES[engine]
    except KeyError as exc:
        raise core.ConfigError(
            "unknown engine %r; expected v1 or v2" % engine
        ) from exc


def shape(document: dict, source: str) -> Optional[str]:
    """Return the engine hinted by one document, or None when it has no rules."""
    present = {}
    for engine, key in SHAPE_KEYS.items():
        if key not in document:
            continue
        value = document[key]
        expected = dict if engine == "v1" else list
        if not isinstance(value, expected):
            kind = "an object" if engine == "v1" else "a list"
            raise core.ConfigError(
                "%s: `%s` must be %s (%s rules)"
                % (
                    source,
                    key,
                    kind,
                    "V1" if engine == "v1" else "V2",
                )
            )
        present[engine] = bool(value)

    nonempty = [engine for engine, value in present.items() if value]
    if len(nonempty) > 1:
        raise core.ConfigError(
            "%s contains both a non-empty `permission` map and a non-empty "
            "`permissions` list. Keep one engine per file: move V1 rules into "
            "`permission`, or convert them into the V2 `permissions` list."
            % source
        )
    return nonempty[0] if nonempty else None


def detect(documents: Sequence[Tuple[str, str, dict]]) -> str:
    """Detect one engine for all loaded documents; default to V2."""
    shapes = set()
    for label, path, document in documents:
        found = shape(document, label or path)
        if found:
            shapes.add(found)

    if len(shapes) > 1:
        raise core.ConfigError(
            "the loaded sources mix V1 (`permission` map) and V2 "
            "(`permissions` list) formats. Pass --engine v1 or --engine v2 "
            "only after converting the files to one format."
        )
    if shapes:
        return shapes.pop()
    return "v2"


def validate(engine: str, documents: Sequence[Tuple[str, str, dict]]) -> None:
    """Reject a forced engine that contradicts a document's shape."""
    for label, path, document in documents:
        source = label or path
        found = shape(document, source)
        if found is None or found == engine:
            continue
        found_module = get(found)
        raise core.ConfigError(
            "%s is a %s `%s` document, but --engine %s was requested. "
            "Use --engine %s or convert the file to the %s format."
            % (
                source,
                found.upper(),
                found_module.SHAPE_KEY,
                engine,
                found,
                engine.upper(),
            )
        )
