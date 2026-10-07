import fs from 'fs';
import path from 'path';
import { ThreatItem, CampaignCluster, GraphNode, GraphLink, ModelMetrics, ThreatStatus } from '../src/types/threat';
import { INITIAL_THREATS, INITIAL_CAMPAIGNS, MOCK_GRAPH_DATA, BENCHMARK_METRICS } from '../src/data/mockThreats';

const DATA_DIR = path.join(process.cwd(), 'server', 'data');
const THREATS_FILE = path.join(DATA_DIR, 'threats.json');
const DISPATCHES_FILE = path.join(DATA_DIR, 'dispatches.json');

export interface TakedownDispatchRecord {
  id: string;
  threatId: string;
  targetDomain: string;
  targetBrand: string;
  channels: string[];
  dispatchedAt: string;
  dispatchedBy: string;
  status: 'PENDING_ACK' | 'ACKNOWLEDGED' | 'IN_PROCESS' | 'RESOLVED';
  trackingNumber: string;
  rfcNoticeExcerpt: string;
  evidenceSha256: string;
  recipients: string[];
}

class StorageEngine {
  private threats: ThreatItem[] = [];
  private campaigns: CampaignCluster[] = [];
  private graphNodes: GraphNode[] = [];
  private graphLinks: GraphLink[] = [];
  private dispatches: TakedownDispatchRecord[] = [];
  private metrics: ModelMetrics = BENCHMARK_METRICS;

  constructor() {
    this.init();
  }

  private init() {
    try {
      if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
      }

      if (fs.existsSync(THREATS_FILE)) {
        const data = fs.readFileSync(THREATS_FILE, 'utf-8');
        this.threats = JSON.parse(data);
      } else {
        this.threats = [...INITIAL_THREATS];
        this.saveThreats();
      }

      if (fs.existsSync(DISPATCHES_FILE)) {
        const data = fs.readFileSync(DISPATCHES_FILE, 'utf-8');
        this.dispatches = JSON.parse(data);
      } else {
        this.dispatches = [
          {
            id: 'disp-8901',
            threatId: 'thr-8901',
            targetDomain: 'sbi-yono-pan-kyc-update.live',
            targetBrand: 'SBI YONO',
            channels: ['CERT-In Form 7A', 'NPCI UPI Shield', 'NameSilo Registrar Abuse'],
            dispatchedAt: new Date(Date.now() - 3600000 * 2).toISOString().replace('T', ' ').slice(0, 19),
            dispatchedBy: 'CSIRT SOC Analyst #042',
            status: 'IN_PROCESS',
            trackingNumber: 'CERTIN-2026-T3-8901',
            rfcNoticeExcerpt: 'URGENT TAKEDOWN: Fraudulent SBI YONO Harvesting portal actively stealing MPIN & CVV.',
            evidenceSha256: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b',
            recipients: ['incident@cert-in.org.in', 'fraud-ops@npci.org.in', 'abuse@namesilo.com']
          }
        ];
        this.saveDispatches();
      }

      this.campaigns = [...INITIAL_CAMPAIGNS];
      this.graphNodes = [...MOCK_GRAPH_DATA.nodes];
      this.graphLinks = [...MOCK_GRAPH_DATA.links];
    } catch (err) {
      console.error('StorageEngine init error:', err);
      this.threats = [...INITIAL_THREATS];
      this.campaigns = [...INITIAL_CAMPAIGNS];
      this.graphNodes = [...MOCK_GRAPH_DATA.nodes];
      this.graphLinks = [...MOCK_GRAPH_DATA.links];
    }
  }

  private saveThreats() {
    try {
      fs.writeFileSync(THREATS_FILE, JSON.stringify(this.threats, null, 2), 'utf-8');
    } catch (err) {
      console.error('Error saving threats to disk:', err);
    }
  }

  private saveDispatches() {
    try {
      fs.writeFileSync(DISPATCHES_FILE, JSON.stringify(this.dispatches, null, 2), 'utf-8');
    } catch (err) {
      console.error('Error saving dispatches to disk:', err);
    }
  }

  // Threats
  public getAllThreats(): ThreatItem[] {
    return this.threats;
  }

  public getThreatById(id: string): ThreatItem | undefined {
    return this.threats.find(t => t.id === id);
  }

  public addThreat(threat: ThreatItem): ThreatItem {
    // Check if already exists
    const existingIndex = this.threats.findIndex(t => t.domain === threat.domain || t.id === threat.id);
    if (existingIndex >= 0) {
      this.threats[existingIndex] = { ...this.threats[existingIndex], ...threat };
      this.saveThreats();
      return this.threats[existingIndex];
    }

    this.threats.unshift(threat);
    this.saveThreats();

    // Auto-update graph with new nodes
    this.syncGraphWithThreat(threat);

    return threat;
  }

  public updateThreatStatus(id: string, status: ThreatStatus): ThreatItem | null {
    const threat = this.threats.find(t => t.id === id);
    if (!threat) return null;
    threat.status = status;
    threat.timeline.push({
      time: new Date().toLocaleTimeString(),
      event: `Status changed to ${status}`,
      actor: 'SOC Lead Analyst'
    });
    this.saveThreats();
    return threat;
  }

  public deleteThreat(id: string): boolean {
    const initialLen = this.threats.length;
    this.threats = this.threats.filter(t => t.id !== id);
    if (this.threats.length !== initialLen) {
      this.saveThreats();
      return true;
    }
    return false;
  }

  // Campaigns
  public getCampaigns(): CampaignCluster[] {
    return this.campaigns;
  }

  // Graph
  public getGraphData(): { nodes: GraphNode[]; links: GraphLink[] } {
    return {
      nodes: this.graphNodes,
      links: this.graphLinks
    };
  }

  private syncGraphWithThreat(threat: ThreatItem) {
    const domainNodeId = `dom-${threat.domain}`;
    if (!this.graphNodes.find(n => n.id === domainNodeId)) {
      this.graphNodes.push({
        id: domainNodeId,
        label: threat.domain,
        type: 'DOMAIN',
        severity: threat.severity,
        campaignId: threat.campaignId,
        details: { target: threat.targetBrand, score: threat.similarityScore }
      });
    }

    if (threat.ip) {
      const ipNodeId = `ip-${threat.ip}`;
      if (!this.graphNodes.find(n => n.id === ipNodeId)) {
        this.graphNodes.push({
          id: ipNodeId,
          label: `${threat.ip} (${threat.countryCode})`,
          type: 'IP',
          severity: threat.severity,
          campaignId: threat.campaignId
        });
      }
      if (!this.graphLinks.find(l => l.source === domainNodeId && l.target === ipNodeId)) {
        this.graphLinks.push({
          source: domainNodeId,
          target: ipNodeId,
          relationship: 'HOSTED_ON',
          confidence: 0.98
        });
      }
    }

    if (threat.extractedUPI_VPA && threat.extractedUPI_VPA.length > 0) {
      for (const vpa of threat.extractedUPI_VPA) {
        const vpaNodeId = `vpa-${vpa}`;
        if (!this.graphNodes.find(n => n.id === vpaNodeId)) {
          this.graphNodes.push({
            id: vpaNodeId,
            label: vpa,
            type: 'UPI_VPA',
            severity: 'CRITICAL',
            campaignId: threat.campaignId
          });
        }
        if (!this.graphLinks.find(l => l.source === domainNodeId && l.target === vpaNodeId)) {
          this.graphLinks.push({
            source: domainNodeId,
            target: vpaNodeId,
            relationship: 'COLLECTS_VIA',
            confidence: 0.95
          });
        }
      }
    }
  }

  // Dispatches
  public getDispatches(): TakedownDispatchRecord[] {
    return this.dispatches;
  }

  public recordDispatch(dispatch: TakedownDispatchRecord): TakedownDispatchRecord {
    this.dispatches.unshift(dispatch);
    this.saveDispatches();

    // Mark corresponding threat as TAKEDOWN_DISPATCHED
    this.updateThreatStatus(dispatch.threatId, 'TAKEDOWN_DISPATCHED');

    return dispatch;
  }

  // Metrics
  public getMetrics(): ModelMetrics {
    return this.metrics;
  }
}

export const db = new StorageEngine();
