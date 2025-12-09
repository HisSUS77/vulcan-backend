# Graph Visualization Guide for Frontend

## Overview

This guide explains how to fetch and visualize the Code Property Graph (CPG) with vulnerability taint paths from the Vulcan backend.

---

## Backend API Endpoints

### 1. Get Scan Summary with Vulnerabilities
**Endpoint:** `GET /api/v1/scans/{scan_id}/summary`

**Response:**
```json
{
  "scan_id": "scan-abc123",
  "status": "COMPLETED",
  "vulnerabilities_found": 3,
  "vulnerabilities": [
    {
      "id": "sqli_request.form_cursor.execute_1",
      "type": "SQL Injection",
      "severity": "critical",
      "confidence": 0.95,
      "owasp": "A03:2021-Injection",
      "cwe": "CWE-89",
      
      "location": {
        "file": "app.py",
        "start_line": 45,
        "end_line": 48
      },
      
      "evidence": {
        "source": "request.form",
        "sink": "cursor.execute",
        "pattern": "DFG_FLOW",
        "code_snippet": "username = request.form.get('username')\nquery = f\"SELECT * FROM users WHERE name = '{username}'\"\ncursor.execute(query)",
        "data_flow_path": [
          "node_request_form_123",
          "node_username_var_124",
          "node_fstring_125",
          "node_query_var_126",
          "node_execute_call_127"
        ]
      },
      
      "analysis": {
        "static_detection": {
          "severity": "high",
          "confidence": "medium",
          "reason": "Unsanitized user input flows to SQL execution"
        },
        "llm_classification": {
          "classification": "VULNERABLE",
          "severity": "critical",
          "exploitability": 0.9,
          "confidence": 0.95,
          "explanation": "Direct string concatenation of user input into SQL query allows SQL injection",
          "remediation": "Use parameterized queries with placeholders"
        }
      }
    }
  ]
}
```

---

### 2. Get Graph Visualization Data
**Endpoint:** `GET /api/v1/graphs/{scan_id}/file/{file_id}?type={graph_type}`

**Query Parameters:**
- `type`: Graph type - `AST`, `CFG`, `DFG`, or `CPG` (default: `AST`)

**Response:**
```json
{
  "type": "DFG",
  "nodes": [
    {
      "id": "node_request_form_123",
      "label": "request.form",
      "type": "ATTRIBUTE",
      "node_type": "DFG",
      "properties": {
        "file": "app.py",
        "line": 10,
        "column": 15,
        "value": null
      },
      "tainted": true
    },
    {
      "id": "node_username_var_124",
      "label": "username",
      "type": "IDENTIFIER",
      "node_type": "DFG",
      "properties": {
        "file": "app.py",
        "line": 10,
        "column": 5,
        "value": null
      },
      "tainted": true
    },
    {
      "id": "node_execute_call_127",
      "label": "cursor.execute",
      "type": "CALL_EXPRESSION",
      "node_type": "DFG",
      "properties": {
        "file": "app.py",
        "line": 12,
        "column": 5,
        "value": null
      },
      "tainted": false
    }
  ],
  "edges": [
    {
      "from": "node_request_form_123",
      "to": "node_username_var_124",
      "label": "DATA_FLOW",
      "type": "DATA_FLOW",
      "edge_type": "DFG",
      "data_flow": "assignment"
    },
    {
      "from": "node_username_var_124",
      "to": "node_fstring_125",
      "label": "DATA_FLOW",
      "type": "DATA_FLOW",
      "edge_type": "DFG",
      "data_flow": "string_interpolation"
    }
  ],
  "meta": {
    "total_nodes": 45,
    "total_edges": 67,
    "tainted_nodes": 5
  }
}
```

---

## Frontend Implementation

### Step 1: Fetch Data

```javascript
// services/graphService.js

export const graphService = {
  /**
   * Get scan summary with vulnerabilities
   */
  getSummary: async (scanId) => {
    const response = await api.get(`/scans/${scanId}/summary`);
    return response.data;
  },

  /**
   * Get graph visualization data
   * @param {string} scanId - Scan ID
   * @param {string} fileId - File ID (use 'main' for direct code scans)
   * @param {string} type - Graph type: 'AST', 'CFG', 'DFG', or 'CPG'
   */
  getGraph: async (scanId, fileId = 'main', type = 'DFG') => {
    const response = await api.get(`/graphs/${scanId}/file/${fileId}`, {
      params: { type }
    });
    return response.data;
  }
};
```

---

### Step 2: Graph Visualization with React + React Flow

#### Installation
```bash
npm install reactflow
```

#### Component Implementation

```jsx
// components/VulnerabilityGraphViewer.jsx

import React, { useState, useEffect, useMemo } from 'react';
import ReactFlow, {
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { graphService } from '../services/graphService';

const VulnerabilityGraphViewer = ({ scanId, vulnerability }) => {
  const [graphData, setGraphData] = useState(null);
  const [nodes, setNodes, onNodesChange] = useNodesState([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [loading, setLoading] = useState(true);

  // Fetch graph data
  useEffect(() => {
    const fetchGraph = async () => {
      try {
        setLoading(true);
        const data = await graphService.getGraph(scanId, 'main', 'DFG');
        setGraphData(data);
      } catch (error) {
        console.error('Failed to fetch graph:', error);
      } finally {
        setLoading(false);
      }
    };

    fetchGraph();
  }, [scanId]);

  // Process graph data and highlight vulnerability path
  useEffect(() => {
    if (!graphData || !vulnerability) return;

    const vulnerablePath = new Set(vulnerability.evidence.data_flow_path);

    // Convert nodes
    const processedNodes = graphData.nodes.map((node, index) => {
      const isInPath = vulnerablePath.has(node.id);
      const isSource = node.id === vulnerablePath.values().next().value;
      const isSink = node.id === Array.from(vulnerablePath).pop();

      return {
        id: node.id,
        type: 'default',
        data: {
          label: (
            <div style={{ padding: '5px', textAlign: 'center' }}>
              <div style={{ fontWeight: 'bold' }}>{node.label}</div>
              <div style={{ fontSize: '10px', color: '#666' }}>
                Line {node.properties.line}
              </div>
            </div>
          ),
        },
        position: calculatePosition(index, graphData.nodes.length),
        style: {
          background: isSource ? '#ff6b6b' : isSink ? '#ff0000' : isInPath ? '#ffd93d' : '#fff',
          border: isInPath ? '3px solid #ff0000' : '1px solid #ddd',
          borderRadius: '8px',
          padding: '10px',
          boxShadow: isInPath ? '0 4px 8px rgba(255,0,0,0.3)' : '0 2px 4px rgba(0,0,0,0.1)',
        },
      };
    });

    // Convert edges
    const processedEdges = graphData.edges.map((edge) => {
      const isInPath = 
        vulnerablePath.has(edge.from) && vulnerablePath.has(edge.to);

      return {
        id: `${edge.from}-${edge.to}`,
        source: edge.from,
        target: edge.to,
        label: edge.label,
        type: 'smoothstep',
        animated: isInPath,
        style: {
          stroke: isInPath ? '#ff0000' : '#b1b1b7',
          strokeWidth: isInPath ? 3 : 1,
        },
        markerEnd: {
          type: 'arrowclosed',
          color: isInPath ? '#ff0000' : '#b1b1b7',
        },
      };
    });

    setNodes(processedNodes);
    setEdges(processedEdges);
  }, [graphData, vulnerability, setNodes, setEdges]);

  // Simple layout algorithm (you can use dagre for better layouts)
  const calculatePosition = (index, total) => {
    const columns = Math.ceil(Math.sqrt(total));
    const row = Math.floor(index / columns);
    const col = index % columns;
    
    return {
      x: col * 250,
      y: row * 150,
    };
  };

  if (loading) {
    return <div>Loading graph...</div>;
  }

  return (
    <div style={{ width: '100%', height: '600px' }}>
      <div style={{ marginBottom: '10px', padding: '10px', background: '#f5f5f5' }}>
        <h3>Vulnerability Path Visualization</h3>
        <p>
          <span style={{ color: '#ff6b6b', fontWeight: 'bold' }}>● Source</span> → 
          <span style={{ color: '#ffd93d', fontWeight: 'bold' }}> Taint Flow </span> → 
          <span style={{ color: '#ff0000', fontWeight: 'bold' }}>● Sink</span>
        </p>
        <p><strong>Type:</strong> {vulnerability.type} | <strong>Severity:</strong> {vulnerability.severity}</p>
      </div>

      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        fitView
        attributionPosition="bottom-left"
      >
        <Background />
        <Controls />
        <MiniMap 
          nodeColor={(node) => {
            if (node.style?.background) return node.style.background;
            return '#fff';
          }}
        />
      </ReactFlow>
    </div>
  );
};

export default VulnerabilityGraphViewer;
```

---

### Step 3: Advanced Layout with Dagre

For better automatic graph layout, use `dagre`:

```bash
npm install dagre
```

```javascript
// utils/graphLayout.js

import dagre from 'dagre';

export const getLayoutedElements = (nodes, edges, direction = 'TB') => {
  const dagreGraph = new dagre.graphlib.Graph();
  dagreGraph.setDefaultEdgeLabel(() => ({}));
  dagreGraph.setGraph({ rankdir: direction });

  nodes.forEach((node) => {
    dagreGraph.setNode(node.id, { width: 200, height: 80 });
  });

  edges.forEach((edge) => {
    dagreGraph.setEdge(edge.source, edge.target);
  });

  dagre.layout(dagreGraph);

  const layoutedNodes = nodes.map((node) => {
    const nodeWithPosition = dagreGraph.node(node.id);
    return {
      ...node,
      position: {
        x: nodeWithPosition.x - 100,
        y: nodeWithPosition.y - 40,
      },
    };
  });

  return { nodes: layoutedNodes, edges };
};
```

Update the component to use dagre layout:

```javascript
import { getLayoutedElements } from '../utils/graphLayout';

// Inside useEffect, after processing nodes and edges:
const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(
  processedNodes,
  processedEdges,
  'TB' // Top to Bottom
);

setNodes(layoutedNodes);
setEdges(layoutedEdges);
```

---

### Step 4: Alternative - D3.js Force-Directed Graph

```javascript
// components/D3VulnerabilityGraph.jsx

import React, { useEffect, useRef } from 'react';
import * as d3 from 'd3';

const D3VulnerabilityGraph = ({ graphData, vulnerability }) => {
  const svgRef = useRef();

  useEffect(() => {
    if (!graphData || !vulnerability) return;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    const width = 1200;
    const height = 800;

    svg.attr('width', width).attr('height', height);

    const vulnerablePath = new Set(vulnerability.evidence.data_flow_path);

    // Create force simulation
    const simulation = d3.forceSimulation(graphData.nodes)
      .force('link', d3.forceLink(graphData.edges)
        .id(d => d.id)
        .distance(150))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(width / 2, height / 2));

    // Draw edges
    const link = svg.append('g')
      .selectAll('line')
      .data(graphData.edges)
      .enter()
      .append('line')
      .attr('stroke', d => 
        vulnerablePath.has(d.from) && vulnerablePath.has(d.to) ? '#ff0000' : '#999')
      .attr('stroke-width', d =>
        vulnerablePath.has(d.from) && vulnerablePath.has(d.to) ? 3 : 1)
      .attr('marker-end', 'url(#arrowhead)');

    // Add arrow markers
    svg.append('defs').append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '-0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('orient', 'auto')
      .attr('markerWidth', 8)
      .attr('markerHeight', 8)
      .append('path')
      .attr('d', 'M 0,-5 L 10,0 L 0,5')
      .attr('fill', '#999');

    // Draw nodes
    const node = svg.append('g')
      .selectAll('circle')
      .data(graphData.nodes)
      .enter()
      .append('circle')
      .attr('r', 15)
      .attr('fill', d => {
        if (vulnerablePath.has(d.id)) {
          const pathArray = Array.from(vulnerablePath);
          if (d.id === pathArray[0]) return '#ff6b6b'; // Source
          if (d.id === pathArray[pathArray.length - 1]) return '#ff0000'; // Sink
          return '#ffd93d'; // Path
        }
        return d.tainted ? '#ffec99' : '#69b3a2';
      })
      .call(d3.drag()
        .on('start', dragstarted)
        .on('drag', dragged)
        .on('end', dragended));

    // Add labels
    const labels = svg.append('g')
      .selectAll('text')
      .data(graphData.nodes)
      .enter()
      .append('text')
      .text(d => d.label)
      .attr('font-size', 12)
      .attr('dx', 20)
      .attr('dy', 5);

    // Update positions on simulation tick
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);

      node
        .attr('cx', d => d.x)
        .attr('cy', d => d.y);

      labels
        .attr('x', d => d.x)
        .attr('y', d => d.y);
    });

    function dragstarted(event) {
      if (!event.active) simulation.alphaTarget(0.3).restart();
      event.subject.fx = event.subject.x;
      event.subject.fy = event.subject.y;
    }

    function dragged(event) {
      event.subject.fx = event.x;
      event.subject.fy = event.y;
    }

    function dragended(event) {
      if (!event.active) simulation.alphaTarget(0);
      event.subject.fx = null;
      event.subject.fy = null;
    }

    return () => {
      simulation.stop();
    };
  }, [graphData, vulnerability]);

  return <svg ref={svgRef}></svg>;
};

export default D3VulnerabilityGraph;
```

---

## Integration Example

```jsx
// pages/ScanDetailsPage.jsx

import React, { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { graphService } from '../services/graphService';
import VulnerabilityGraphViewer from '../components/VulnerabilityGraphViewer';

const ScanDetailsPage = () => {
  const { scanId } = useParams();
  const [summary, setSummary] = useState(null);
  const [selectedVuln, setSelectedVuln] = useState(null);

  useEffect(() => {
    const fetchSummary = async () => {
      const data = await graphService.getSummary(scanId);
      setSummary(data);
      if (data.vulnerabilities?.length > 0) {
        setSelectedVuln(data.vulnerabilities[0]);
      }
    };

    fetchSummary();
  }, [scanId]);

  if (!summary) return <div>Loading...</div>;

  return (
    <div className="scan-details">
      <h1>Scan Results: {scanId}</h1>

      {/* Vulnerability List */}
      <div className="vulnerability-list">
        {summary.vulnerabilities.map((vuln) => (
          <div
            key={vuln.id}
            className={`vuln-item ${selectedVuln?.id === vuln.id ? 'active' : ''}`}
            onClick={() => setSelectedVuln(vuln)}
          >
            <h3>{vuln.type}</h3>
            <span className={`severity ${vuln.severity}`}>{vuln.severity}</span>
            <p>Line {vuln.location.start_line} - {vuln.location.end_line}</p>
          </div>
        ))}
      </div>

      {/* Graph Visualization */}
      {selectedVuln && (
        <VulnerabilityGraphViewer
          scanId={scanId}
          vulnerability={selectedVuln}
        />
      )}
    </div>
  );
};

export default ScanDetailsPage;
```

---

## Visualization Features

### Legend
- **Red Node (●)**: Taint Source (where vulnerable data enters)
- **Yellow Nodes (●)**: Intermediate nodes in taint flow
- **Dark Red Node (●)**: Taint Sink (where vulnerability is exploited)
- **Animated Red Edges**: Data flow path showing taint propagation
- **Gray Nodes/Edges**: Other graph elements not in vulnerability path

### Interactive Features
1. **Click vulnerability** to highlight its path
2. **Drag nodes** to rearrange layout
3. **Zoom and pan** for large graphs
4. **Hover** to see node details
5. **Toggle graph types** (AST/CFG/DFG/CPG)

---

## Complete Flow

```
1. User runs scan → Backend analyzes code
2. Backend stores graph_data in scan job
3. Backend finds vulnerabilities with path_nodes
4. Frontend fetches /scans/{id}/summary → Gets vulnerabilities with data_flow_path
5. Frontend fetches /graphs/{id}/file/main?type=DFG → Gets full graph
6. Frontend overlays vulnerability path on graph
7. User sees highlighted source → flow → sink visualization
```

---

## Testing

```bash
# Start backend
cd vulcan-backend
uvicorn app.main:app --reload

# Run a scan
curl -X POST http://localhost:8000/api/v1/scans/start \
  -H "Authorization: Bearer <token>" \
  -H "Content-Type: application/json" \
  -d '{
    "code": "username = request.form.get(\"username\")\nquery = f\"SELECT * FROM users WHERE name = '\''{username}'\''\"",
    "language": "python"
  }'

# Get summary (includes data_flow_path now!)
curl http://localhost:8000/api/v1/scans/scan-abc123/summary \
  -H "Authorization: Bearer <token>"

# Get graph data
curl http://localhost:8000/api/v1/graphs/scan-abc123/file/main?type=DFG \
  -H "Authorization: Bearer <token>"
```

---

## Summary

✅ **Backend Changes:**
- Added `data_flow_path` to vulnerability response
- Graph endpoint already provides full node/edge data
- Tainted nodes marked with `tainted: true`

✅ **Frontend Implementation:**
- Fetch summary to get vulnerabilities with paths
- Fetch graph to get all nodes and edges
- Overlay vulnerability path on graph
- Highlight source (red), path (yellow), sink (dark red)
- Use React Flow or D3.js for visualization

✅ **User Experience:**
- Click vulnerability → See highlighted path in graph
- Visual flow: Source → Taint Propagation → Sink
- Interactive graph exploration
- Multiple graph views (AST/CFG/DFG/CPG)
