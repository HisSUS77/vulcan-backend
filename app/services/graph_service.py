from typing import Dict, Any, Optional
import logging

from motor.motor_asyncio import AsyncIOMotorDatabase

logger = logging.getLogger(__name__)


class GraphService:
    """
    Service for retrieving graph visualizations from completed scans.
    Returns actual AST/CFG/DFG graphs from the semantic analysis engine.
    """
    
    def __init__(self, db: AsyncIOMotorDatabase) -> None:
        self.db = db

    async def graph(self, scan_id: str, file_id: str, gtype: str) -> Dict[str, Any]:
        """
        Get graph visualization for a scanned file.
        
        Args:
            scan_id: Scan identifier
            file_id: File identifier (currently unused for direct code scans)
            gtype: Graph type (AST, CFG, DFG, or CPG)
        
        Returns:
            Graph data with nodes and edges
        """
        scan = await self.db.scans.find_one({"scan_id": scan_id})
        
        if not scan:
            return {
                "type": gtype.upper(),
                "nodes": [],
                "edges": [],
                "error": "Scan not found",
                "detail": f"No scan found with ID: {scan_id}"
            }
        
        # Check if scan is complete
        if scan.get("state") != "COMPLETED":
            return {
                "type": gtype.upper(),
                "nodes": [],
                "edges": [],
                "error": "Scan not completed",
                "detail": f"Scan is in state: {scan.get('state')}. Wait for completion."
            }
        
        # Get stored graph data
        graph_data = scan.get("graph_data")
        
        if not graph_data:
            return {
                "type": gtype.upper(),
                "nodes": [],
                "edges": [],
                "error": "No graph data available",
                "detail": "Graph data was not stored during scan. This may be an older scan."
            }
        
        # Return requested graph type
        graph_type = gtype.upper()
        
        if graph_type == "AST":
            return self._format_ast_graph(graph_data)
        elif graph_type == "CFG":
            return self._format_cfg_graph(graph_data)
        elif graph_type == "DFG":
            return self._format_dfg_graph(graph_data)
        elif graph_type == "CPG":
            return self._format_cpg_graph(graph_data)
        else:
            return {
                "error": "Unsupported graph type",
                "detail": f"Graph type '{gtype}' not supported. Use AST, CFG, DFG, or CPG."
            }
    
    def _format_ast_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format AST graph for visualization."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # Filter to AST nodes and edges only
        ast_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", node.get("type", "Node")),
                "type": node.get("type"),
                "properties": node.get("properties", {})
            }
            for node in nodes
            if node.get("node_type") in ["AST", None]  # Include nodes without explicit type
        ]
        
        # Get node IDs for filtering edges
        ast_node_ids = {n["id"] for n in ast_nodes}
        
        ast_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type")
            }
            for edge in edges
            if edge.get("edge_type") in ["AST", "CHILD", None]
            and edge["source"] in ast_node_ids
            and edge["target"] in ast_node_ids
        ]
        
        return {
            "type": "AST",
            "nodes": ast_nodes,
            "edges": ast_edges,
            "meta": {
                "total_nodes": len(ast_nodes),
                "total_edges": len(ast_edges)
            }
        }
    
    def _format_cfg_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format CFG graph for visualization."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # For CFG, show control flow nodes
        cfg_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", "Block"),
                "type": node.get("type"),
                "properties": node.get("properties", {})
            }
            for node in nodes
        ]
        
        # Filter CFG edges
        cfg_node_ids = {n["id"] for n in cfg_nodes}
        
        cfg_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type"),
                "condition": edge.get("properties", {}).get("condition")
            }
            for edge in edges
            if edge.get("edge_type") in ["CFG", "CONTROL_FLOW"]
            and edge["source"] in cfg_node_ids
            and edge["target"] in cfg_node_ids
        ]
        
        return {
            "type": "CFG",
            "nodes": cfg_nodes,
            "edges": cfg_edges,
            "meta": {
                "total_nodes": len(cfg_nodes),
                "total_edges": len(cfg_edges)
            }
        }
    
    def _format_dfg_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format DFG graph for visualization."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # For DFG, show data flow nodes
        dfg_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", "Variable"),
                "type": node.get("type"),
                "properties": node.get("properties", {}),
                "tainted": node.get("properties", {}).get("tainted", False)
            }
            for node in nodes
        ]
        
        # Filter DFG edges
        dfg_node_ids = {n["id"] for n in dfg_nodes}
        
        dfg_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type"),
                "data_flow": edge.get("properties", {}).get("flow_type")
            }
            for edge in edges
            if edge.get("edge_type") in ["DFG", "DATA_FLOW", "DFG_INTERP", "DFG_TEMPLATE"]
            and edge["source"] in dfg_node_ids
            and edge["target"] in dfg_node_ids
        ]
        
        return {
            "type": "DFG",
            "nodes": dfg_nodes,
            "edges": dfg_edges,
            "meta": {
                "total_nodes": len(dfg_nodes),
                "total_edges": len(dfg_edges),
                "tainted_nodes": sum(1 for n in dfg_nodes if n.get("tainted"))
            }
        }
    
    def _format_cpg_graph(self, graph_data: Dict[str, Any]) -> Dict[str, Any]:
        """Format complete CPG (all graphs combined)."""
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        # Return all nodes and edges
        all_nodes = [
            {
                "id": node["id"],
                "label": node.get("label", "Node"),
                "type": node.get("type"),
                "node_type": node.get("node_type"),
                "properties": node.get("properties", {}),
                "tainted": node.get("properties", {}).get("tainted", False)
            }
            for node in nodes
        ]
        
        all_edges = [
            {
                "from": edge["source"],
                "to": edge["target"],
                "label": edge.get("label", ""),
                "type": edge.get("type"),
                "edge_type": edge.get("edge_type")
            }
            for edge in edges
        ]
        
        return {
            "type": "CPG",
            "nodes": all_nodes,
            "edges": all_edges,
            "meta": {
                "total_nodes": len(all_nodes),
                "total_edges": len(all_edges),
                "tainted_nodes": sum(1 for n in all_nodes if n.get("tainted"))
            }
        }
