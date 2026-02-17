from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Tuple

import networkx as nx

@dataclass(frozen=True)
class TriggerEdge:
    source: str   # e.g., 'http', 's3:bucket', 'eventbridge:rule'
    target: str   # e.g., 'lambda:fn'
    meta: Dict[str, Any]

def build_trigger_graph(edges: List[TriggerEdge]) -> nx.DiGraph:
    g = nx.DiGraph()
    for e in edges:
        g.add_node(e.source, kind="trigger")
        g.add_node(e.target, kind="compute")
        g.add_edge(e.source, e.target, **e.meta)
    return g

def graph_to_json(g: nx.DiGraph) -> Dict[str, Any]:
    return {
        "nodes": [{"id": n, **g.nodes[n]} for n in g.nodes],
        "edges": [{"source": u, "target": v, **g.edges[u, v]} for u, v in g.edges],
    }
