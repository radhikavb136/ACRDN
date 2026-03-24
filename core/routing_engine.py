import networkx as nx
import time
import threading
from collections import defaultdict
from config import (
    NETWORK_NODES, NETWORK_EDGES,
    DECOY_NODE, SOURCE_NODE, DESTINATION_NODE
)


class RoutingEngine:

    def __init__(self):
        self.graph        = nx.DiGraph()
        self.load_data    = defaultdict(float)
        self.packet_count = defaultdict(int)
        self.last_path    = None

        self.build_graph()

        threading.Thread(
            target=self._decay_loop,
            daemon=True
        ).start()

        print("[ROUTING] Routing Engine initialized")

    def build_graph(self):
        self.graph.add_nodes_from(NETWORK_NODES)
        for src, dst, data in NETWORK_EDGES:
            self.graph.add_edge(src, dst, **data)

    def _decay_loop(self):
        while True:
            time.sleep(5)
            for edge in list(self.load_data.keys()):
                self.load_data[edge] = max(
                    0, self.load_data[edge] - 10
                )
                src, dst = edge
                if self.graph.has_edge(src, dst):
                    latency = self.graph[src][dst].get(
                        "latency", 5
                    )
                    load = self.load_data[edge]
                    cost = (load * 0.4) + (latency * 0.6)
                    self.graph[src][dst]["weight"] = cost
                    self.graph[src][dst]["load"]   = load

    def record_packet(self, src_ip, intent):
        if intent == "NORMAL":
            self._add_load("A", "B", 5)
        elif intent == "SUSPICIOUS":
            self._add_load("A", "B", 20)
            self._add_load("B", "D", 15)
        elif intent == "MALICIOUS":
            self._add_load("A", "B", 50)
            self._add_load("B", "D", 40)
            self._add_load("B", "E", 35)

    def _add_load(self, src, dst, amount):
        key = (src, dst)
        self.load_data[key] = min(
            100, self.load_data[key] + amount
        )
        load = self.load_data[key]
        if self.graph.has_edge(src, dst):
            latency = self.graph[src][dst].get(
                "latency", 5
            )
            cost = (load * 0.4) + (latency * 0.6)
            self.graph[src][dst]["weight"] = cost
            self.graph[src][dst]["load"]   = load

    def update_load(self, src_node, dst_node,
                    load, latency):
        cost = (load * 0.4) + (latency * 0.6)
        if self.graph.has_edge(src_node, dst_node):
            self.graph[src_node][dst_node]["weight"] = cost
            self.graph[src_node][dst_node]["load"]   = load
        self.load_data[(src_node, dst_node)] = load

    def best_path(self):
        try:
            path = nx.dijkstra_path(
                self.graph,
                SOURCE_NODE,
                DESTINATION_NODE,
                weight="weight"
            )
            cost = nx.dijkstra_path_length(
                self.graph,
                SOURCE_NODE,
                DESTINATION_NODE,
                weight="weight"
            )
            # Only print when path changes
            if path != self.last_path:
                print(
                    f"[ROUTING] Best path: "
                    f"{' -> '.join(path)} "
                    f"(cost: {cost:.2f})"
                )
                self.last_path = path
            return path
        except Exception as e:
            print(f"[ROUTING] Error: {e}")
            return [SOURCE_NODE, DESTINATION_NODE]

    def monitored_path(self):
        try:
            all_paths = list(nx.all_simple_paths(
                self.graph,
                SOURCE_NODE,
                DESTINATION_NODE
            ))
            if len(all_paths) <= 1:
                return all_paths[0]
            costs = []
            for p in all_paths:
                cost = sum(
                    self.graph[p[i]][p[i+1]].get(
                        "weight", 1
                    )
                    for i in range(len(p) - 1)
                )
                costs.append((cost, p))
            costs.sort()
            idx  = 1 if len(costs) > 1 else 0
            path = costs[idx][1]
            # No print - called too frequently
            return path
        except Exception as e:
            print(f"[ROUTING] Error: {e}")
            return [SOURCE_NODE, DESTINATION_NODE]

    def decoy_path(self):
        print("[ROUTING] -> DECOY NODE (honeypot)")
        return [SOURCE_NODE, DECOY_NODE]

    def simulate_real_load(self, packet_counts):
        for node, count in packet_counts.items():
            load = min(count / 10.0, 100.0)
            for src, dst in self.graph.edges():
                if dst == node:
                    latency = self.graph[src][dst].get(
                        "latency", 5
                    )
                    self.update_load(
                        src, dst, load, latency
                    )

    def get_graph_data(self):
        nodes = list(self.graph.nodes())
        edges = []
        for u, v, d in self.graph.edges(data=True):
            edges.append({
                "src":    u,
                "dst":    v,
                "weight": round(d.get("weight", 1), 2),
                "load":   round(d.get("load", 0), 2)
            })
        return {"nodes": nodes, "edges": edges}
