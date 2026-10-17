"""
database.py — FalkorDB connection utility.

Provides a singleton-style accessor for the FalkorDB graph instance so
every module imports from one place and we never open stale connections.
"""

from __future__ import annotations

import logging
from functools import lru_cache

from falkordb import FalkorDB, Graph

logger = logging.getLogger(__name__)

_FALKOR_HOST: str = "localhost"
_FALKOR_PORT: int = 6379
_GRAPH_NAME: str = "security_graph"


@lru_cache(maxsize=1)
def _get_client() -> FalkorDB:
    """Return a cached FalkorDB client (connects once per process)."""
    logger.info("Connecting to FalkorDB at %s:%d", _FALKOR_HOST, _FALKOR_PORT)
    return FalkorDB(host=_FALKOR_HOST, port=_FALKOR_PORT)


def get_graph() -> Graph:
    """
    Return the FalkorDB Graph object for *security_graph*.

    Callers should NOT close or cache this object themselves — just call
    ``get_graph()`` each time they need it.  FalkorDB's Python client
    holds the underlying Redis connection pool internally.
    """
    db: FalkorDB = _get_client()
    graph: Graph = db.select_graph(_GRAPH_NAME)
    return graph


def health_check() -> dict:
    """
    Ping FalkorDB and return basic connectivity info.

    Returns:
        dict with keys ``status``, ``host``, ``port``, ``graph``.
    """
    try:
        graph = get_graph()
        result = graph.query("RETURN 1 AS ping")
        ping_val = result.result_set[0][0] if result.result_set else None
        return {
            "status": "ok" if ping_val == 1 else "degraded",
            "host": _FALKOR_HOST,
            "port": _FALKOR_PORT,
            "graph": _GRAPH_NAME,
        }
    except Exception as exc:  # noqa: BLE001
        logger.error("FalkorDB health check failed: %s", exc)
        return {
            "status": "error",
            "host": _FALKOR_HOST,
            "port": _FALKOR_PORT,
            "graph": _GRAPH_NAME,
            "detail": str(exc),
        }
