import React, { useRef, useEffect, useState } from 'react';
import { Network, ShieldAlert, Globe, Server, CreditCard, Phone, Smartphone, Eye, ZoomIn, ZoomOut, RotateCcw, Filter, ChevronRight, Layers } from 'lucide-react';
import { GraphNode, GraphLink, CampaignCluster, ThreatItem } from '../types/threat';

interface CampaignGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  campaigns: CampaignCluster[];
  onSelectThreat?: (threatId: string) => void;
  onSelectNode?: (node: GraphNode) => void;
}

const TYPE_COLORS: Record<GraphNode['type'], { fill: string; stroke: string; label: string }> = {
  CAMPAIGN: { fill: '#8b5cf6', stroke: '#c084fc', label: 'Campaign Syndicate' },
  DOMAIN: { fill: '#f43f5e', stroke: '#fb7185', label: 'Phishing Domain' },
  IP: { fill: '#f59e0b', stroke: '#fbbf24', label: 'Host IP / Bulletproof Server' },
  ASN: { fill: '#64748b', stroke: '#94a3b8', label: 'ASN / Routing Network' },
  UPI_VPA: { fill: '#06b6d4', stroke: '#22d3ee', label: 'Malicious UPI VPA' },
  PHONE: { fill: '#10b981', stroke: '#34d399', label: 'Mule Phone / WhatsApp' },
  APK: { fill: '#ec4899', stroke: '#f472b6', label: 'Banking Trojan APK' },
  SSL_CERT: { fill: '#3b82f6', stroke: '#60a5fa', label: 'Shared SSL Cert' }
};

export const CampaignGraph: React.FC<CampaignGraphProps> = ({
  nodes: initialNodes,
  links: initialLinks,
  campaigns,
  onSelectNode
}) => {
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

  // Maintain local mutable copy with coordinates for physics
  const graphRef = useRef<{
    nodes: (GraphNode & { x: number; y: number; vx: number; vy: number; radius: number })[];
    links: GraphLink[];
  }>({
    nodes: [],
    links: []
  });

  // Initialize nodes layout with radial positioning per campaign
  useEffect(() => {
    const width = 900;
    const height = 600;
    const centerX = width / 2;
    const centerY = height / 2;

    const initializedNodes = initialNodes.map((node, i) => {
      const angle = (i / initialNodes.length) * Math.PI * 2;
      const radius = node.type === 'CAMPAIGN' ? 80 : 160 + (i % 3) * 60;
      return {
        ...node,
        x: centerX + Math.cos(angle) * radius + (Math.random() - 0.5) * 50,
        y: centerY + Math.sin(angle) * radius + (Math.random() - 0.5) * 50,
        vx: 0,
        vy: 0,
        radius: node.type === 'CAMPAIGN' ? 22 : node.type === 'DOMAIN' ? 14 : 11
      };
    });

    graphRef.current = {
      nodes: initializedNodes,
      links: initialLinks
    };
  }, [initialNodes, initialLinks]);

  // Physics Simulation Loop
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let animationFrameId: number;

    const runPhysics = () => {
      const { nodes, links } = graphRef.current;
      const width = canvas.width;
      const height = canvas.height;
      const centerX = width / 2;
      const centerY = height / 2;

      // 1. Center attraction
      nodes.forEach(n => {
        const dx = centerX - n.x;
        const dy = centerY - n.y;
        n.vx += dx * 0.0005;
        n.vy += dy * 0.0005;
      });

      // 2. Node-node repulsion
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const n1 = nodes[i];
          const n2 = nodes[j];
          const dx = n2.x - n1.x;
          const dy = n2.y - n1.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const minDist = n1.radius + n2.radius + 40;

          if (dist < minDist * 2.5) {
            const force = (minDist * 2.5 - dist) / dist * 0.08;
            n1.vx -= dx * force;
            n1.vy -= dy * force;
            n2.vx += dx * force;
            n2.vy += dy * force;
          }
        }
      }

      // 3. Link spring attraction
      links.forEach(link => {
        const src = nodes.find(n => n.id === link.source);
        const tgt = nodes.find(n => n.id === link.target);
        if (src && tgt) {
          const dx = tgt.x - src.x;
          const dy = tgt.y - src.y;
          const dist = Math.sqrt(dx * dx + dy * dy) || 1;
          const targetDist = 90;
          const force = (dist - targetDist) * 0.003;

          src.vx += dx * force;
          src.vy += dy * force;
          tgt.vx -= dx * force;
          tgt.vy -= dy * force;
        }
      });

      // 4. Dampen and update position
      nodes.forEach(n => {
        if (n === draggedNode) return;
        n.vx *= 0.88;
        n.vy *= 0.88;
        n.x += n.vx;
        n.y += n.vy;
      });

      // RENDER
      ctx.clearRect(0, 0, width, height);

      ctx.save();
      ctx.translate(offset.x, offset.y);
      ctx.scale(zoom, zoom);

      // Draw Links
      links.forEach(link => {
        const src = nodes.find(n => n.id === link.source);
        const tgt = nodes.find(n => n.id === link.target);
        if (!src || !tgt) return;

        const isHighlighted = selectedNode && (selectedNode.id === src.id || selectedNode.id === tgt.id);

        ctx.beginPath();
        ctx.moveTo(src.x, src.y);
        ctx.lineTo(tgt.x, tgt.y);
        ctx.strokeStyle = isHighlighted ? 'rgba(6, 182, 212, 0.8)' : 'rgba(255, 255, 255, 0.12)';
        ctx.lineWidth = isHighlighted ? 2.5 : 1;
        ctx.setLineDash(link.relationship === 'ROUTES_THROUGH' ? [4, 4] : []);
        ctx.stroke();
        ctx.setLineDash([]);

        // Relationship label on highlight
        if (isHighlighted) {
          const midX = (src.x + tgt.x) / 2;
          const midY = (src.y + tgt.y) / 2;
          ctx.fillStyle = '#06b6d4';
          ctx.font = '9px Fira Code, monospace';
          ctx.fillText(link.relationship.replace('_', ' '), midX, midY - 4);
        }
      });

      // Draw Nodes
      nodes.forEach(node => {
        // Filter check
        if (selectedTypeFilter !== 'ALL' && node.type !== selectedTypeFilter) return;
        if (selectedCampaignFilter !== 'ALL' && node.campaignId !== selectedCampaignFilter && node.id !== selectedCampaignFilter) return;

        const isSelected = selectedNode?.id === node.id;
        const isHovered = hoveredNode?.id === node.id;
        const typeStyle = TYPE_COLORS[node.type] || { fill: '#64748b', stroke: '#94a3b8', label: 'Node' };

        // Outer glow
        if (isSelected || isHovered || node.type === 'CAMPAIGN') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + (isSelected ? 8 : 4), 0, Math.PI * 2);
          ctx.fillStyle = isSelected ? 'rgba(6, 182, 212, 0.25)' : `${typeStyle.fill}22`;
          ctx.fill();
        }

        // Main Node Circle
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = typeStyle.fill;
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#ffffff' : typeStyle.stroke;
        ctx.lineWidth = isSelected ? 3 : 1.5;
        ctx.stroke();

        // Node Label
        ctx.fillStyle = isSelected ? '#38bdf8' : '#e2e8f0';
        ctx.font = node.type === 'CAMPAIGN' ? 'bold 11px Inter, sans-serif' : '10px Fira Code, monospace';
        ctx.textAlign = 'center';
        
        // Truncate label for clean rendering
        let displayLabel = node.label;
        if (displayLabel.length > 22 && node.type !== 'CAMPAIGN') {
          displayLabel = displayLabel.slice(0, 19) + '...';
        }
        ctx.fillText(displayLabel, node.x, node.y + node.radius + 13);
      });

      ctx.restore();
      animationFrameId = requestAnimationFrame(runPhysics);
    };

    animationFrameId = requestAnimationFrame(runPhysics);
    return () => cancelAnimationFrame(animationFrameId);
  }, [zoom, offset, selectedNode, hoveredNode, selectedTypeFilter, selectedCampaignFilter, draggedNode]);

  // Canvas Mouse Interactions
  const handleMouseDown = (e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = (e.clientX - rect.left - offset.x) / zoom;
    const mouseY = (e.clientY - rect.top - offset.y) / zoom;

    const clicked = graphRef.current.nodes.find(n => {
      const dist = Math.hypot(n.x - mouseX, n.y - mouseY);
      return dist <= n.radius + 6;
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
        return dist <= n.radius + 6;
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

  // Connected nodes of selectedNode
  const connectedLinks = selectedNode
    ? graphRef.current.links.filter(l => l.source === selectedNode.id || l.target === selectedNode.id)
    : [];

  return (
    <div className="flex flex-col h-full bg-[#080b11] rounded-xl border border-white/10 overflow-hidden shadow-2xl">
      {/* Header controls bar */}
      <div className="flex flex-wrap items-center justify-between px-4 py-3 bg-[#0d121c] border-b border-white/10 gap-3">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-sm font-semibold">
            <Network className="w-4 h-4 text-cyan-400" />
            <span>Adversary Infrastructure & Campaign Graph</span>
          </div>
          <span className="text-xs text-slate-400 font-mono bg-white/5 px-2 py-0.5 rounded border border-white/5">
            {graphRef.current.nodes.length} Nodes • {graphRef.current.links.length} Relations
          </span>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-2">
          {/* Node Type Filter */}
          <div className="flex items-center space-x-1.5 text-xs text-slate-300">
            <Filter className="w-3.5 h-3.5 text-slate-400" />
            <select
              value={selectedTypeFilter}
              onChange={(e) => setSelectedTypeFilter(e.target.value)}
              className="bg-[#141b29] border border-white/10 text-xs rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">All Node Types</option>
              <option value="CAMPAIGN">Campaigns</option>
              <option value="DOMAIN">Domains</option>
              <option value="IP">IP Hosts</option>
              <option value="UPI_VPA">UPI VPAs</option>
              <option value="PHONE">Phone / WhatsApp</option>
              <option value="APK">Malware APKs</option>
            </select>
          </div>

          {/* Campaign Filter */}
          <select
            value={selectedCampaignFilter}
            onChange={(e) => setSelectedCampaignFilter(e.target.value)}
            className="bg-[#141b29] border border-white/10 text-xs rounded px-2 py-1 text-slate-200 focus:outline-none focus:border-cyan-500 font-mono"
          >
            <option value="ALL">All Syndicates</option>
            {campaigns.map(c => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>

          {/* Zoom controls */}
          <div className="flex items-center space-x-1 bg-[#141b29] p-0.5 rounded border border-white/10">
            <button
              onClick={() => setZoom(z => Math.min(z * 1.2, 2.5))}
              className="p-1 hover:bg-white/10 rounded text-slate-300"
              title="Zoom In"
            >
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => setZoom(z => Math.max(z * 0.8, 0.4))}
              className="p-1 hover:bg-white/10 rounded text-slate-300"
              title="Zoom Out"
            >
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => { setZoom(1); setOffset({ x: 0, y: 0 }); }}
              className="p-1 hover:bg-white/10 rounded text-slate-300"
              title="Reset View"
            >
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas + Inspector Drawer */}
      <div className="relative flex-1 min-h-[560px] flex">
        {/* Force Directed Graph Canvas */}
        <canvas
          ref={canvasRef}
          width={960}
          height={600}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onWheel={handleWheel}
          className="w-full h-full cursor-grab active:cursor-grabbing bg-grid-pattern bg-[#070a10]"
        />

        {/* Legend Overlay */}
        <div className="absolute top-4 left-4 p-3 rounded-lg bg-[#0d121c]/90 backdrop-blur-md border border-white/10 text-xs text-slate-300 space-y-1.5 pointer-events-none shadow-xl">
          <div className="font-semibold text-white text-[11px] uppercase tracking-wider mb-2 flex items-center space-x-1">
            <Layers className="w-3.5 h-3.5 text-cyan-400" />
            <span>Infrastructure Legend</span>
          </div>
          {Object.entries(TYPE_COLORS).map(([type, style]) => (
            <div key={type} className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: style.fill }} />
              <span className="text-[11px] font-mono text-slate-300">{style.label}</span>
            </div>
          ))}
        </div>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 max-h-[90%] overflow-y-auto p-4 rounded-xl bg-[#0f1522]/95 backdrop-blur-xl border border-cyan-500/30 shadow-2xl text-xs space-y-3 animate-in fade-in slide-in-from-right-4 duration-200">
            <div className="flex items-center justify-between border-b border-white/10 pb-2">
              <div className="flex items-center space-x-2">
                <span
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: TYPE_COLORS[selectedNode.type]?.fill || '#06b6d4' }}
                />
                <span className="font-mono font-bold text-white text-xs uppercase">
                  {selectedNode.type.replace('_', ' ')}
                </span>
              </div>
              <button
                onClick={() => setSelectedNode(null)}
                className="text-slate-400 hover:text-white px-1.5 py-0.5 rounded bg-white/5"
              >
                ✕
              </button>
            </div>

            <div>
              <div className="text-[10px] text-slate-400 uppercase font-mono">Entity Identifier</div>
              <div className="font-mono text-cyan-300 font-semibold break-all text-xs mt-0.5">
                {selectedNode.label}
              </div>
            </div>

            {selectedNode.severity && (
              <div>
                <div className="text-[10px] text-slate-400 uppercase font-mono">Threat Severity</div>
                <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-mono font-bold mt-1 ${
                  selectedNode.severity === 'CRITICAL' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/30' :
                  selectedNode.severity === 'HIGH' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/30' :
                  'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30'
                }`}>
                  <ShieldAlert className="w-3 h-3 mr-1" />
                  {selectedNode.severity}
                </span>
              </div>
            )}

            {selectedNode.details && (
              <div className="p-2.5 rounded bg-[#090d14] border border-white/5 space-y-1.5 font-mono text-[11px]">
                {Object.entries(selectedNode.details).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-slate-400 capitalize">{k}:</span>
                    <span className="text-slate-200 font-semibold">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}

            {/* Connected Relations */}
            <div>
              <div className="text-[10px] text-slate-400 uppercase font-mono mb-1.5 flex items-center justify-between">
                <span>Direct Graph Links</span>
                <span className="text-cyan-400">({connectedLinks.length})</span>
              </div>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {connectedLinks.map((link, idx) => {
                  const otherId = link.source === selectedNode.id ? link.target : link.source;
                  const otherNode = graphRef.current.nodes.find(n => n.id === otherId);
                  return (
                    <div
                      key={idx}
                      onClick={() => otherNode && setSelectedNode(otherNode)}
                      className="p-1.5 rounded bg-white/5 hover:bg-cyan-500/10 hover:border-cyan-500/30 border border-transparent cursor-pointer flex items-center justify-between text-[11px]"
                    >
                      <span className="font-mono text-slate-300 truncate max-w-[140px]">
                        {otherNode?.label || otherId}
                      </span>
                      <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-cyan-500/10 text-cyan-400">
                        {link.relationship.replace('_', ' ')}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Action */}
            <div className="pt-2 border-t border-white/10">
              <button
                onClick={() => alert(`Pivoting deeper on IOC: ${selectedNode.label}`)}
                className="w-full py-1.5 px-3 rounded bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-300 border border-cyan-500/30 font-medium text-xs flex items-center justify-center space-x-1.5 transition-all"
              >
                <span>Pivot & Correlate ASN/DNS</span>
                <ChevronRight className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
