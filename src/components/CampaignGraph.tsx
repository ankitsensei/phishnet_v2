import React, { useRef, useEffect, useState } from 'react';
import { Network, ZoomIn, ZoomOut, RotateCcw, Layers, Share2, Info, Sparkles } from 'lucide-react';
import { GraphNode, GraphLink, CampaignCluster } from '../types/threat';

interface CampaignGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  campaigns: CampaignCluster[];
  onSelectThreat?: (threatId: string) => void;
  onSelectNode?: (node: GraphNode) => void;
}

const TYPE_STYLES: Record<GraphNode['type'], { fill: string; stroke: string; glow: string; label: string }> = {
  CAMPAIGN: { fill: '#ef4444', stroke: '#dc2626', glow: 'rgba(239, 68, 68, 0.15)', label: 'Threat Syndicate' },
  DOMAIN: { fill: '#0284c7', stroke: '#0369a1', glow: 'rgba(2, 132, 199, 0.15)', label: 'Cloned Domain' },
  IP: { fill: '#2563eb', stroke: '#1d4ed8', glow: 'rgba(37, 99, 235, 0.15)', label: 'Bulletproof IP' },
  ASN: { fill: '#4f46e5', stroke: '#4338ca', glow: 'rgba(79, 70, 229, 0.15)', label: 'Routing ASN' },
  UPI_VPA: { fill: '#059669', stroke: '#047857', glow: 'rgba(5, 150, 105, 0.15)', label: 'Malicious UPI VPA' },
  PHONE: { fill: '#d97706', stroke: '#b45309', glow: 'rgba(217, 119, 6, 0.15)', label: 'Mule Phone / WhatsApp' },
  APK: { fill: '#ea580c', stroke: '#c2410c', glow: 'rgba(234, 88, 12, 0.15)', label: 'Trojan APK' },
  SSL_CERT: { fill: '#7c3aed', stroke: '#6d28d9', glow: 'rgba(124, 58, 237, 0.15)', label: 'SSL Certificate' }
};

export const CampaignGraph: React.FC<CampaignGraphProps> = ({
  nodes: initialNodes,
  links: initialLinks,
  campaigns,
  onSelectNode
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const [selectedTypeFilter, setSelectedTypeFilter] = useState<string>('ALL');
  const [selectedCampaignFilter, setSelectedCampaignFilter] = useState<string>('ALL');
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [zoom, setZoom] = useState<number>(1);
  const [offset, setOffset] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [isDraggingCanvas, setIsDraggingCanvas] = useState<boolean>(false);
  const [dragStart, setDragStart] = useState<{ x: number; y: number }>({ x: 0, y: 0 });
  const [draggedNode, setDraggedNode] = useState<GraphNode | null>(null);
  const [hoveredNode, setHoveredNode] = useState<GraphNode | null>(null);

  const graphRef = useRef<{
    nodes: (GraphNode & { x: number; y: number; vx: number; vy: number; radius: number })[];
    links: GraphLink[];
  }>({
    nodes: [],
    links: []
  });

  // Handle dynamic resize
  useEffect(() => {
    const updateSize = () => {
      const container = containerRef.current;
      const canvas = canvasRef.current;
      if (!container || !canvas) return;

      const rect = container.getBoundingClientRect();
      const dpr = window.devicePixelRatio || 1;
      canvas.width = rect.width * dpr;
      canvas.height = Math.max(540, rect.height) * dpr;
    };

    updateSize();
    window.addEventListener('resize', updateSize);
    return () => window.removeEventListener('resize', updateSize);
  }, []);

  // Initialize node layout
  useEffect(() => {
    const width = 800;
    const height = 540;
    const centerX = width / 2;
    const centerY = height / 2;

    const initializedNodes = initialNodes.map((node, i) => {
      const angle = (i / initialNodes.length) * Math.PI * 2;
      const radius = node.type === 'CAMPAIGN' ? 70 : 150 + (i % 3) * 50;
      return {
        ...node,
        x: centerX + Math.cos(angle) * radius + (Math.random() - 0.5) * 40,
        y: centerY + Math.sin(angle) * radius + (Math.random() - 0.5) * 40,
        vx: 0,
        vy: 0,
        radius: node.type === 'CAMPAIGN' ? 20 : node.type === 'DOMAIN' ? 14 : 10
      };
    });

    graphRef.current = {
      nodes: initializedNodes,
      links: initialLinks
    };
  }, [initialNodes, initialLinks]);

  // Physics animation loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;

    const runPhysics = () => {
      const dpr = window.devicePixelRatio || 1;
      const width = canvas.width / dpr;
      const height = canvas.height / dpr;
      const centerX = width / 2;
      const centerY = height / 2;

      const { nodes, links } = graphRef.current;

      // 1. Center attraction
      nodes.forEach(n => {
        const dx = centerX - n.x;
        const dy = centerY - n.y;
        n.vx += dx * 0.0004;
        n.vy += dy * 0.0004;
      });

      // 2. Repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const n1 = nodes[i];
          const n2 = nodes[j];
          const dx = n2.x - n1.x;
          const dy = n2.y - n1.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const minDist = n1.radius + n2.radius + 35;

          if (dist < minDist * 2.5) {
            const force = (minDist * 2.5 - dist) / dist * 0.06;
            n1.vx -= dx * force;
            n1.vy -= dy * force;
            n2.vx += dx * force;
            n2.vy += dy * force;
          }
        }
      }

      // 3. Link spring
      links.forEach(link => {
        const src = nodes.find(n => n.id === link.source);
        const tgt = nodes.find(n => n.id === link.target);
        if (src && tgt) {
          const dx = tgt.x - src.x;
          const dy = tgt.y - src.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const targetDist = 90;
          const force = (dist - targetDist) * 0.0025;

          src.vx += dx * force;
          src.vy += dy * force;
          tgt.vx -= dx * force;
          tgt.vy -= dy * force;
        }
      });

      // 4. Update
      nodes.forEach(n => {
        if (n === draggedNode) return;
        n.vx *= 0.88;
        n.vy *= 0.88;
        n.x += n.vx;
        n.y += n.vy;
      });

      // Render
      ctx.save();
      ctx.scale(dpr, dpr);
      ctx.clearRect(0, 0, width, height);

      // Light background fill
      ctx.fillStyle = '#f8fafc';
      ctx.fillRect(0, 0, width, height);

      // Subtle Grid Dots
      ctx.fillStyle = '#e2e8f0';
      const gridSize = 24;
      for (let x = (offset.x % gridSize); x < width; x += gridSize) {
        for (let y = (offset.y % gridSize); y < height; y += gridSize) {
          ctx.beginPath();
          ctx.arc(x, y, 1, 0, Math.PI * 2);
          ctx.fill();
        }
      }

      ctx.translate(offset.x, offset.y);
      ctx.scale(zoom, zoom);

      // Links
      links.forEach(link => {
        const src = nodes.find(n => n.id === link.source);
        const tgt = nodes.find(n => n.id === link.target);
        if (!src || !tgt) return;

        const isHighlighted = selectedNode && (selectedNode.id === src.id || selectedNode.id === tgt.id);

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = isHighlighted ? '#4f46e5' : '#cbd5e1';
        ctx.lineWidth = isHighlighted ? 2.5 : 1.2;
        ctx.stroke();

        if (isHighlighted) {
          const midX = (src.x + tgt.x) / 2;
          const midY = (src.y + tgt.y) / 2;
          ctx.fillStyle = '#4f46e5';
          ctx.font = 'bold 10px monospace';
          ctx.fillText(link.relationship.replace('_', ' '), midX, midY - 4);
        }
      });

      // Nodes
      nodes.forEach(node => {
        if (selectedTypeFilter !== 'ALL' && node.type !== selectedTypeFilter) return;
        if (selectedCampaignFilter !== 'ALL' && node.campaignId !== selectedCampaignFilter && node.id !== selectedCampaignFilter) return;

        const isSelected = selectedNode?.id === node.id;
        const isHovered = hoveredNode?.id === node.id;
        const style = TYPE_STYLES[node.type] || { fill: '#3b82f6', stroke: '#60a5fa', glow: 'rgba(59, 130, 246, 0.4)', label: 'Node' };

        // Outer Glow Ring
        if (isSelected || isHovered || node.type === 'CAMPAIGN') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + (isSelected ? 6 : 3), 0, Math.PI * 2);
          ctx.fillStyle = isSelected ? style.glow : 'rgba(99, 102, 241, 0.08)';
          ctx.fill();
        }

        // Main Circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = style.fill;
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#0f172a' : style.stroke;
        ctx.lineWidth = isSelected ? 2.5 : 1.5;
        ctx.stroke();

        // Label
        ctx.fillStyle = isSelected ? '#0f172a' : '#475569';
        ctx.font = node.type === 'CAMPAIGN' ? 'bold 11px sans-serif' : '10px monospace';
        ctx.textAlign = 'center';

        let displayLabel = node.label;
        if (displayLabel.length > 20 && node.type !== 'CAMPAIGN') {
          displayLabel = displayLabel.slice(0, 18) + '...';
        }
        ctx.fillText(displayLabel, node.x, node.y + node.radius + 12);
      });

      ctx.restore();
      animationFrameId = requestAnimationFrame(runPhysics);
    };

    animationFrameId = requestAnimationFrame(runPhysics);
    return () => cancelAnimationFrame(animationFrameId);
  }, [zoom, offset, selectedNode, hoveredNode, selectedTypeFilter, selectedCampaignFilter, draggedNode]);

  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - offset.x) / zoom;
    const mouseY = (e.clientY - rect.top - offset.y) / zoom;

    const clicked = graphRef.current.nodes.find(n => {
      const dist = Math.hypot(n.x - mouseX, n.y - mouseY);
      return dist <= n.radius + 8;
    });

    if (clicked) {
      setSelectedNode(clicked);
      setDraggedNode(clicked);
      if (onSelectNode) onSelectNode(clicked);
    } else {
      setIsDraggingCanvas(true);
      setDragStart({ x: e.clientX - offset.x, y: e.clientY - offset.y });
    }
  };

  const handleMouseMove = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - offset.x) / zoom;
    const mouseY = (e.clientY - rect.top - offset.y) / zoom;

    if (draggedNode) {
      draggedNode.x = mouseX;
      draggedNode.y = mouseY;
    } else if (isDraggingCanvas) {
      setOffset({
        x: e.clientX - dragStart.x,
        y: e.clientY - dragStart.y
      });
    } else {
      const hover = graphRef.current.nodes.find(n => {
        const dist = Math.hypot(n.x - mouseX, n.y - mouseY);
        return dist <= n.radius + 8;
      });
      setHoveredNode(hover || null);
    }
  };

  const handleMouseUp = () => {
    setDraggedNode(null);
    setIsDraggingCanvas(false);
  };

  const handleWheel = (e: React.WheelEvent<HTMLCanvasElement>) => {
    e.preventDefault();
    const zoomFactor = e.deltaY < 0 ? 1.08 : 0.92;
    setZoom(prev => Math.min(Math.max(prev * zoomFactor, 0.4), 2.5));
  };

  const connectedLinks = selectedNode
    ? graphRef.current.links.filter(l => l.source === selectedNode.id || l.target === selectedNode.id)
    : [];

  return (
    <div className="flex flex-col h-full bg-white rounded-xl border border-slate-200 overflow-hidden shadow-xs">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between px-5 py-3.5 bg-white border-b border-slate-200 gap-3">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 text-slate-900 text-xs font-bold">
            <Network className="w-4 h-4 text-indigo-600" />
            <span>Adversary Infrastructure & Campaign Graph</span>
          </div>
          <span className="text-xs text-slate-500 font-mono">
            {graphRef.current.nodes.length} Nodes • {graphRef.current.links.length} Relations
          </span>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-2 text-xs">
          <select
            value={selectedTypeFilter}
            onChange={(e) => setSelectedTypeFilter(e.target.value)}
            className="bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Entity Types</option>
            <option value="CAMPAIGN">Campaigns</option>
            <option value="DOMAIN">Domains</option>
            <option value="IP">IP Hosts</option>
            <option value="UPI_VPA">UPI VPAs</option>
            <option value="PHONE">Phone / WhatsApp</option>
            <option value="APK">Malware APKs</option>
          </select>

          <select
            value={selectedCampaignFilter}
            onChange={(e) => setSelectedCampaignFilter(e.target.value)}
            className="bg-slate-50 border border-slate-300 rounded-lg px-2.5 py-1.5 text-slate-700 focus:outline-none focus:border-indigo-500"
          >
            <option value="ALL">All Threat Syndicates</option>
            {campaigns.map(c => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>

          <div className="flex items-center space-x-1 bg-slate-100 p-0.5 rounded-lg">
            <button onClick={() => setZoom(z => Math.min(z * 1.2, 2.5))} className="p-1 hover:bg-slate-200 rounded text-slate-600" title="Zoom In">
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => setZoom(z => Math.max(z * 0.8, 0.4))} className="p-1 hover:bg-slate-200 rounded text-slate-600" title="Zoom Out">
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => { setZoom(1); setOffset({ x: 0, y: 0 }); }} className="p-1 hover:bg-slate-200 rounded text-slate-600" title="Reset View">
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas + Inspector */}
      <div ref={containerRef} className="relative flex-1 min-h-[560px] flex">
        <canvas
          ref={canvasRef}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onWheel={handleWheel}
          className="w-full h-full cursor-grab active:cursor-grabbing bg-slate-50"
        />

        {/* Legend */}
        <div className="absolute top-4 left-4 p-3.5 rounded-xl bg-white/95 border border-slate-200 text-xs text-slate-700 space-y-1.5 pointer-events-none shadow-sm backdrop-blur-xs">
          <div className="font-bold text-slate-900 text-xs uppercase tracking-wider mb-2 flex items-center space-x-1.5">
            <Layers className="w-3.5 h-3.5 text-indigo-600" />
            <span>Infrastructure Key</span>
          </div>
          {Object.entries(TYPE_STYLES).map(([type, style]) => (
            <div key={type} className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: style.fill }} />
              <span className="text-xs text-slate-600 font-medium">{style.label}</span>
            </div>
          ))}
        </div>

        {/* Node Detail Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 max-h-[90%] overflow-y-auto p-4 rounded-xl bg-white border border-slate-300 text-xs space-y-3.5 shadow-md">
            <div className="flex items-center justify-between border-b border-slate-100 pb-2">
              <div className="font-bold text-indigo-700 text-xs uppercase">
                {selectedNode.type.replace('_', ' ')}
              </div>
              <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-600 text-xs px-1">
                ✕
              </button>
            </div>

            <div>
              <div className="text-[10px] text-slate-500 uppercase font-semibold">Entity Value</div>
              <div className="font-mono text-slate-900 font-bold break-all text-xs mt-0.5">
                {selectedNode.label}
              </div>
            </div>

            {selectedNode.details && (
              <div className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 space-y-1 font-mono text-xs">
                {Object.entries(selectedNode.details).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-slate-500 capitalize">{k}:</span>
                    <span className="text-slate-900 font-semibold">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}

            <div>
              <div className="text-[10px] text-slate-500 uppercase font-semibold mb-1.5">
                Direct Connections ({connectedLinks.length})
              </div>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {connectedLinks.map((link, idx) => {
                  const otherId = link.source === selectedNode.id ? link.target : link.source;
                  const otherNode = graphRef.current.nodes.find(n => n.id === otherId);
                  return (
                    <div
                      key={idx}
                      onClick={() => otherNode && setSelectedNode(otherNode)}
                      className="p-2 rounded-lg bg-slate-50 hover:bg-slate-100 border border-slate-200 cursor-pointer flex items-center justify-between text-xs transition-colors"
                    >
                      <span className="font-mono text-slate-800 truncate max-w-[150px]">
                        {otherNode?.label || otherId}
                      </span>
                      <span className="text-[10px] px-1.5 py-0.5 rounded bg-indigo-50 text-indigo-700 font-semibold">
                        {link.relationship.replace('_', ' ')}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
