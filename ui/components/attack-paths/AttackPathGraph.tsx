"use client";

import {
  Background,
  Controls,
  type Edge,
  type EdgeProps,
  getBezierPath,
  Handle,
  type Node,
  type NodeProps,
  Position,
  ReactFlow,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useCallback, useMemo, useState } from "react";

interface GraphNode {
  id: string;
  label: string;
  type: "resource" | "finding" | "internet" | "identity";
  properties: Record<string, unknown>;
  riskLevel?: "critical" | "high" | "medium" | "low";
}

interface GraphEdge {
  id: string;
  source: string;
  target: string;
  label: string;
}

interface AttackPathGraphProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  onNodeClick?: (node: GraphNode) => void;
  title?: string;
}

const NODE_FILL: Record<string, string> = {
  finding: "#ef4444",
  internet: "#f97316",
  resource: "#3b82f6",
  identity: "#8b5cf6",
};

const NODE_COLORS_TW: Record<string, string> = {
  finding: "bg-red-500",
  internet: "bg-orange-500",
  resource: "bg-blue-500",
  identity: "bg-purple-500",
};

function AttackPathNode({ data }: NodeProps) {
  const color = NODE_FILL[data.nodeType as string] ?? "#3b82f6";
  return (
    <div
      className="flex flex-col items-center"
      style={{ minWidth: 60 }}
    >
      <Handle type="target" position={Position.Top} className="opacity-0" />
      <div
        className="flex h-12 w-12 items-center justify-center rounded-full text-[10px] font-bold text-white shadow"
        style={{ backgroundColor: color }}
      >
        {(data.label as string).slice(0, 3).toUpperCase()}
      </div>
      <span className="mt-1 max-w-[120px] truncate text-center text-[10px] text-gray-700 dark:text-gray-300">
        {(data.label as string).length > 20
          ? (data.label as string).slice(0, 18) + "..."
          : (data.label as string)}
      </span>
      <Handle type="source" position={Position.Bottom} className="opacity-0" />
    </div>
  );
}

function AnimatedEdge({
  id,
  sourceX,
  sourceY,
  targetX,
  targetY,
  sourcePosition,
  targetPosition,
  data,
}: EdgeProps) {
  const [edgePath, labelX, labelY] = getBezierPath({
    sourceX,
    sourceY,
    sourcePosition,
    targetX,
    targetY,
    targetPosition,
  });

  return (
    <>
      <path
        id={id}
        d={edgePath}
        fill="none"
        stroke="#6b7280"
        strokeWidth={1.5}
        markerEnd="url(#react-flow__arrowclosed)"
        className="opacity-60"
      />
      <circle r="3" fill="#ef4444">
        <animateMotion dur="2s" repeatCount="indefinite" path={edgePath} />
      </circle>
      {data?.label && (
        <text
          x={labelX}
          y={labelY - 8}
          textAnchor="middle"
          className="fill-gray-500 text-[10px]"
        >
          {data.label as string}
        </text>
      )}
    </>
  );
}

const nodeTypes = { attackPath: AttackPathNode };
const edgeTypes = { animated: AnimatedEdge };

export function AttackPathGraph({
  nodes: graphNodes,
  edges: graphEdges,
  onNodeClick,
  title,
}: AttackPathGraphProps) {
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);

  const initialNodes: Node[] = useMemo(() => {
    const cols = Math.ceil(Math.sqrt(graphNodes.length));
    return graphNodes.map((n, i) => ({
      id: n.id,
      type: "attackPath",
      position: { x: (i % cols) * 200, y: Math.floor(i / cols) * 150 },
      data: { label: n.label, nodeType: n.type, raw: n },
    }));
  }, [graphNodes]);

  const initialEdges: Edge[] = useMemo(
    () =>
      graphEdges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        type: "animated",
        data: { label: e.label },
        markerEnd: { type: "arrowclosed" as const },
      })),
    [graphEdges],
  );

  const [nodes, , onNodesChange] = useNodesState(initialNodes);
  const [edges, , onEdgesChange] = useEdgesState(initialEdges);

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const raw = node.data.raw as GraphNode;
      setSelectedNode(raw);
      onNodeClick?.(raw);
    },
    [onNodeClick],
  );

  return (
    <div className="flex w-full flex-col gap-4">
      {title && <h3 className="text-lg font-semibold">{title}</h3>}
      <div className="flex gap-4">
        <div className="h-[500px] flex-1 overflow-hidden rounded-lg border bg-gray-50 dark:bg-gray-900">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={handleNodeClick}
            nodeTypes={nodeTypes}
            edgeTypes={edgeTypes}
            fitView
            minZoom={0.2}
            maxZoom={3}
          >
            <Background />
            <Controls />
          </ReactFlow>
        </div>
        {selectedNode && (
          <div className="max-h-[500px] w-72 overflow-auto rounded-lg border bg-white p-4 dark:bg-gray-800">
            <h4 className="mb-2 text-sm font-semibold">{selectedNode.label}</h4>
            <span
              className={`inline-block rounded px-2 py-0.5 text-xs text-white ${NODE_COLORS_TW[selectedNode.type]}`}
            >
              {selectedNode.type}
            </span>
            {selectedNode.riskLevel && (
              <span className="ml-2 inline-block rounded border px-2 py-0.5 text-xs">
                {selectedNode.riskLevel}
              </span>
            )}
            <dl className="mt-3 space-y-1 text-xs">
              {Object.entries(selectedNode.properties)
                .slice(0, 10)
                .map(([k, v]) => (
                  <div key={k}>
                    <dt className="text-gray-500 dark:text-gray-400">{k}</dt>
                    <dd className="truncate font-mono">{String(v)}</dd>
                  </div>
                ))}
            </dl>
          </div>
        )}
      </div>
      <div className="flex gap-4 text-xs text-gray-600 dark:text-gray-400">
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 rounded-full bg-red-500" />
          Finding
        </span>
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 rounded-full bg-orange-500" />
          Internet
        </span>
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 rounded-full bg-blue-500" />
          Resource
        </span>
        <span className="flex items-center gap-1">
          <span className="h-3 w-3 rounded-full bg-purple-500" />
          Identity
        </span>
      </div>
    </div>
  );
}
