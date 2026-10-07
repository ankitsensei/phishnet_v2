import React, { useRef, useEffect, useState } from 'react';
import { Network, ZoomIn, ZoomOut, RotateCcw, Filter, ChevronRight, Layers, Shield } from 'lucide-react';
import { GraphNode, GraphLink, CampaignCluster } from '../types/threat';

interface CampaignGraphProps {
  nodes: GraphNode[];
  links: GraphLink[];
  campaigns: CampaignCluster[];
  onSelectThreat?: (threatId: string) => void;
  onSelectNode?: (node: GraphNode) => void;
}

const TYPE_STYLES: Record<GraphNode['type'], { fill: string; stroke: string; label: string }> = {
  CAMPAIGN: { fill: '#ffffff', stroke: '#ffffff', label: 'Threat Syndicate' },
  DOMAIN: { fill: '#d4d4d8', stroke: '#ffffff', label: 'Cloned Domain' },
  IP: { fill: '#71717a', stroke: '#a1a1aa', label: 'Bulletproof Host IP' },
  ASN: { fill: '#3f3f46', stroke: '#71717a', label: 'Routing ASN' },
  UPI_VPA: { fill: '#e4e4e7', stroke: '#ffffff', label: 'Malicious UPI VPA' },
  PHONE: { fill: '#a1a1aa', stroke: '#e4e4e7', label: 'Mule Phone / WhatsApp' },
  APK: { fill: '#52525b', stroke: '#d4d4d8', label: 'Banking Trojan APK' },
  SSL_CERT: { fill: '#27272a', stroke: '#71717a', label: 'SSL Certificate' }
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

  const graphRef = useRef<{
    nodes: (GraphNode & { x: number; y: number; vx: number; vy: number; radius: number })[];
    links: GraphLink[];
  }>({
    nodes: [],
    links: []
  });

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
        radius: node.type === 'CAMPAIGN' ? 20 : node.type === 'DOMAIN' ? 13 : 10
      };
    });

    graphRef.current = {
      nodes: initializedNodes,
      links: initialLinks
    };
  }, [initialNodes, initialLinks]);

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

      // 2. Repulsion
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

      // 3. Link Attraction
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

      // 4. Update
      nodes.forEach(n => {
        if (n === draggedNode) return;
        n.vx *= 0.88;
        n.vy *= 0.88;
        n.x += n.vx;
        n.y += n.vy;
      });

      // Render
      ctx.clearRect(0, 0, width, height);

      ctx.save();
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
        ctx.strokeStyle = isHighlighted ? '#ffffff' : 'rgba(255, 255, 255, 0.15)';
        ctx.lineWidth = isHighlighted ? 2 : 1;
        ctx.setLineDash(link.relationship === 'ROUTES_THROUGH' ? [4, 4] : []);
        ctx.stroke();
        ctx.setLineDash([]);

        if (isHighlighted) {
          const midX = (src.x + tgt.x) / 2;
          const midY = (src.y + tgt.y) / 2;
          ctx.fillStyle = '#ffffff';
          ctx.font = '9px monospace';
          ctx.fillText(link.relationship.replace('_', ' '), midX, midY - 4);
        }
      });

      // Nodes
      nodes.forEach(node => {
        if (selectedTypeFilter !== 'ALL' && node.type !== selectedTypeFilter) return;
        if (selectedCampaignFilter !== 'ALL' && node.campaignId !== selectedCampaignFilter && node.id !== selectedCampaignFilter) return;

        const isSelected = selectedNode?.id === node.id;
        const isHovered = hoveredNode?.id === node.id;
        const style = TYPE_STYLES[node.type] || { fill: '#71717a', stroke: '#a1a1aa', label: 'Node' };

        // Outer Ring on Selection
        if (isSelected || isHovered || node.type === 'CAMPAIGN') {
          ctx.beginPath();
          ctx.arc(node.x, node.y, node.radius + (isSelected ? 6 : 3), 0, Math.PI * 2);
          ctx.fillStyle = isSelected ? 'rgba(255, 255, 255, 0.2)' : 'rgba(255, 255, 255, 0.08)';
          ctx.fill();
        }

        // Main Node
        ctx.beginPath();
        ctx.arc(node.x, node.y, node.radius, 0, Math.PI * 2);
        ctx.fillStyle = node.type === 'CAMPAIGN' ? '#ffffff' : style.fill;
        ctx.fill();
        ctx.strokeStyle = isSelected ? '#ffffff' : style.stroke;
        ctx.lineWidth = isSelected ? 2.5 : 1;
        ctx.stroke();

        // Label
        ctx.fillStyle = isSelected ? '#ffffff' : '#d4d4d8';
        ctx.font = node.type === 'CAMPAIGN' ? 'bold 11px sans-serif' : '10px monospace';
        ctx.textAlign = 'center';

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

  const connectedLinks = selectedNode
    ? graphRef.current.links.filter(l => l.source === selectedNode.id || l.target === selectedNode.id)
    : [];

  return (
    <div className="flex flex-col h-full bg-[#000000] rounded-lg border border-[#27272a] overflow-hidden">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between px-4 py-3 bg-[#09090b] border-b border-[#27272a] gap-3">
        <div className="flex items-center space-x-3">
          <div className="flex items-center space-x-2 text-white font-mono text-xs font-semibold">
            <Network className="w-4 h-4 text-white" />
            <span>Adversary Infrastructure & Campaign Graph</span>
          </div>
          <span className="text-[11px] text-[#71717a] font-mono">
            {graphRef.current.nodes.length} Nodes • {graphRef.current.links.length} Relations
          </span>
        </div>

        {/* Filters */}
        <div className="flex items-center space-x-2">
          <select
            value={selectedTypeFilter}
            onChange={(e) => setSelectedTypeFilter(e.target.value)}
            className="bg-[#121214] border border-[#27272a] text-xs rounded px-2.5 py-1 text-white focus:outline-none focus:border-white font-mono"
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
            className="bg-[#121214] border border-[#27272a] text-xs rounded px-2.5 py-1 text-white focus:outline-none focus:border-white font-mono"
          >
            <option value="ALL">All Threat Syndicates</option>
            {campaigns.map(c => (
              <option key={c.id} value={c.id}>{c.name}</option>
            ))}
          </select>

          <div className="flex items-center space-x-1 bg-[#121214] p-0.5 rounded border border-[#27272a]">
            <button onClick={() => setZoom(z => Math.min(z * 1.2, 2.5))} className="p-1 hover:bg-[#27272a] rounded text-[#a1a1aa] hover:text-white" title="Zoom In">
              <ZoomIn className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => setZoom(z => Math.max(z * 0.8, 0.4))} className="p-1 hover:bg-[#27272a] rounded text-[#a1a1aa] hover:text-white" title="Zoom Out">
              <ZoomOut className="w-3.5 h-3.5" />
            </button>
            <button onClick={() => { setZoom(1); setOffset({ x: 0, y: 0 }); }} className="p-1 hover:bg-[#27272a] rounded text-[#a1a1aa] hover:text-white" title="Reset View">
              <RotateCcw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      </div>

      {/* Main Canvas + Inspector */}
      <div className="relative flex-1 min-h-[560px] flex">
        <canvas
          ref={canvasRef}
          width={960}
          height={600}
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onWheel={handleWheel}
          className="w-full h-full cursor-grab active:cursor-grabbing bg-grid-mono bg-[#000000]"
        />

        {/* Legend */}
        <div className="absolute top-4 left-4 p-3 rounded bg-[#09090b] border border-[#27272a] text-xs text-[#a1a1aa] space-y-1.5 pointer-events-none">
          <div className="font-semibold text-white text-[11px] uppercase tracking-wider mb-2 flex items-center space-x-1">
            <Layers className="w-3.5 h-3.5 text-white" />
            <span>Infrastructure Graph Key</span>
          </div>
          {Object.entries(TYPE_STYLES).map(([type, style]) => (
            <div key={type} className="flex items-center space-x-2">
              <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: style.fill }} />
              <span className="text-[11px] font-mono text-[#d4d4d8]">{style.label}</span>
            </div>
          ))}
        </div>

        {/* Node Detail Drawer */}
        {selectedNode && (
          <div className="absolute top-4 right-4 w-80 max-h-[90%] overflow-y-auto p-4 rounded-lg bg-[#09090b] border border-white text-xs space-y-3 animate-in fade-in duration-150">
            <div className="flex items-center justify-between border-b border-[#27272a] pb-2">
              <div className="font-mono font-bold text-white text-xs uppercase">
                {selectedNode.type.replace('_', ' ')}
              </div>
              <button onClick={() => setSelectedNode(null)} className="text-[#71717a] hover:text-white px-1 rounded">
                ✕
              </button>
            </div>

            <div>
              <div className="text-[10px] text-[#71717a] uppercase font-mono">Entity Identifier</div>
              <div className="font-mono text-white font-semibold break-all text-xs mt-0.5">
                {selectedNode.label}
              </div>
            </div>

            {selectedNode.details && (
              <div className="p-2.5 rounded bg-[#121214] border border-[#27272a] space-y-1 font-mono text-[11px]">
                {Object.entries(selectedNode.details).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-[#71717a] capitalize">{k}:</span>
                    <span className="text-white font-semibold">{String(v)}</span>
                  </div>
                ))}
              </div>
            )}

            <div>
              <div className="text-[10px] text-[#71717a] uppercase font-mono mb-1.5 flex items-center justify-between">
                <span>Direct Graph Connections ({connectedLinks.length})</span>
              </div>
              <div className="space-y-1 max-h-40 overflow-y-auto">
                {connectedLinks.map((link, idx) => {
                  const otherId = link.source === selectedNode.id ? link.target : link.source;
                  const otherNode = graphRef.current.nodes.find(n => n.id === otherId);
                  return (
                    <div
                      key={idx}
                      onClick={() => otherNode && setSelectedNode(otherNode)}
                      className="p-1.5 rounded bg-[#121214] hover:bg-[#1f1f23] border border-[#27272a] cursor-pointer flex items-center justify-between text-[11px]"
                    >
                      <span className="font-mono text-[#d4d4d8] truncate max-w-[140px]">
                        {otherNode?.label || otherId}
                      </span>
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-[#27272a] text-white">
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
