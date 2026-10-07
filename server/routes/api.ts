import express, { Request, Response } from 'express';
import multer from 'multer';
import { db } from '../db';
import { performDeepScan } from '../services/networkScanner';
import { inspectApkBuffer } from '../services/apkInspector';
import { certStreamService } from '../services/certStreamer';
import { generateAllTakedownNotices, dispatchTakedown } from '../services/takedownService';
import { ThreatItem, ThreatStatus } from '../../src/types/threat';

const router = express.Router();
const upload = multer({ limits: { fileSize: 50 * 1024 * 1024 } }); // 50MB APK limit

// 1. Live Deep Scan (URL / HTML / SMS / UPI ID)
router.post('/scan', async (req: Request, res: Response) => {
  try {
    const { input, typeHint } = req.body;
    if (!input || typeof input !== 'string') {
      return res.status(400).json({ error: 'Missing or invalid "input" parameter' });
    }

    const scanResult = await performDeepScan(input, typeHint || 'URL');
    return res.json(scanResult);
  } catch (err: any) {
    console.error('Scan error:', err);
    return res.status(500).json({ error: 'Failed to analyze source: ' + err.message });
  }
});

// 2. APK Malice & Decompiler Analysis
router.post('/scan/apk', upload.single('file'), (req: Request, res: Response) => {
  try {
    let buffer: Buffer;
    let fileName = 'sample.apk';

    if (req.file) {
      buffer = req.file.buffer;
      fileName = req.file.originalname;
    } else if (req.body.content) {
      buffer = Buffer.from(req.body.content, 'utf-8');
      fileName = req.body.fileName || 'manifest.xml';
    } else {
      return res.status(400).json({ error: 'No APK file or manifest content uploaded' });
    }

    const result = inspectApkBuffer(buffer, fileName);
    return res.json(result);
  } catch (err: any) {
    console.error('APK inspect error:', err);
    return res.status(500).json({ error: 'Failed to inspect APK: ' + err.message });
  }
});

// 3. Threats Feed & Forensics
router.get('/threats', (req: Request, res: Response) => {
  try {
    let list = db.getAllThreats();
    const { brand, severity, status, q } = req.query;

    if (brand && brand !== 'ALL') {
      list = list.filter(t => t.targetBrand === brand);
    }
    if (severity && severity !== 'ALL') {
      list = list.filter(t => t.severity === severity);
    }
    if (status && status !== 'ALL') {
      list = list.filter(t => t.status === status);
    }
    if (q && typeof q === 'string') {
      const search = q.toLowerCase();
      list = list.filter(t =>
        t.domain.toLowerCase().includes(search) ||
        t.targetBrand.toLowerCase().includes(search) ||
        t.ip.includes(search) ||
        t.campaignName.toLowerCase().includes(search)
      );
    }

    return res.json({ count: list.length, threats: list });
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.post('/threats', (req: Request, res: Response) => {
  try {
    const threat: ThreatItem = req.body;
    if (!threat || !threat.domain) {
      return res.status(400).json({ error: 'Invalid threat payload' });
    }

    const saved = db.addThreat(threat);
    return res.status(201).json(saved);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.get('/threats/:id', (req: Request, res: Response) => {
  const threat = db.getThreatById(req.params.id);
  if (!threat) {
    return res.status(404).json({ error: 'Threat not found' });
  }
  return res.json(threat);
});

router.patch('/threats/:id/status', (req: Request, res: Response) => {
  try {
    const { status } = req.body;
    if (!status) {
      return res.status(400).json({ error: 'Missing status in body' });
    }

    const updated = db.updateThreatStatus(req.params.id, status as ThreatStatus);
    if (!updated) {
      return res.status(404).json({ error: 'Threat not found' });
    }
    return res.json(updated);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.delete('/threats/:id', (req: Request, res: Response) => {
  const success = db.deleteThreat(req.params.id);
  if (!success) {
    return res.status(404).json({ error: 'Threat not found' });
  }
  return res.json({ message: 'Threat removed successfully' });
});

// 4. Campaign Clusters & Adversary Graph
router.get('/campaigns', (_req: Request, res: Response) => {
  return res.json(db.getCampaigns());
});

router.get('/graph', (_req: Request, res: Response) => {
  return res.json(db.getGraphData());
});

// 5. Takedown Generator & Dispatch
router.get('/takedowns/:threatId', (req: Request, res: Response) => {
  const threat = db.getThreatById(req.params.threatId);
  if (!threat) {
    return res.status(404).json({ error: 'Threat not found' });
  }
  const notices = generateAllTakedownNotices(threat);
  return res.json({ threat, notices });
});

router.post('/takedown/dispatch', (req: Request, res: Response) => {
  try {
    const { threatId, channels, analystNotes, urgencyLevel } = req.body;
    if (!threatId || !channels || !Array.isArray(channels) || channels.length === 0) {
      return res.status(400).json({ error: 'Must provide threatId and at least one channel' });
    }

    const dispatchRecord = dispatchTakedown({
      threatId,
      channels,
      analystNotes,
      urgencyLevel
    });

    return res.status(201).json(dispatchRecord);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

router.get('/takedown/dispatches', (_req: Request, res: Response) => {
  return res.json(db.getDispatches());
});

// 6. Certificate Transparency Stream (SSE)
router.get('/ct/stream', (req: Request, res: Response) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  certStreamService.registerSseClient(res);
});

router.get('/ct/recent', (_req: Request, res: Response) => {
  return res.json(certStreamService.getRecentLogs());
});

// 7. ML Benchmark Evaluation & System Health
router.get('/benchmarks', (_req: Request, res: Response) => {
  return res.json(db.getMetrics());
});

router.get('/health', (_req: Request, res: Response) => {
  return res.json({
    status: 'HEALTHY',
    version: '2.0.0',
    timestamp: new Date().toISOString(),
    uptimeSeconds: Math.floor(process.uptime()),
    modules: {
      ctStream: 'ACTIVE',
      deepScanner: 'ACTIVE',
      apkDecompiler: 'ACTIVE',
      graphEngine: 'ACTIVE',
      takedownSwitch: 'ACTIVE'
    }
  });
});

export default router;
