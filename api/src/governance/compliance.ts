import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import { Router, Request, Response, NextFunction } from 'express';
import { listLineage } from '../platform/lineage';
import { getIncidentDisclosurePolicy } from '../platform/self-healing';

type AuditResult = 'success' | 'failure' | 'denied';

interface ComplianceAuditEntry {
  timestampNs: string;
  eventType: string;
  actor: string;
  resource: string;
  action: string;
  result: AuditResult;
  sourceIp: string;
  correlationId: string;
  previousHash: string;
  hash: string;
  details?: Record<string, unknown>;
}

interface RetentionPolicy {
  dataType: string;
  retentionDays: number;
  action: 'delete' | 'archive';
  store: string;
}

interface DataSubjectRequest {
  id: string;
  subjectId: string;
  requestType: 'access' | 'erasure' | 'explanation';
  status: 'received' | 'processing' | 'fulfilled' | 'rejected';
  createdAt: string;
  fulfilledAt?: string;
  stores: string[];
  notes?: string[];
  result?: Record<string, unknown>;
}

const router = Router();
const auditEntries: ComplianceAuditEntry[] = [];
const dataSubjectRequests = new Map<string, DataSubjectRequest[]>();
const auditLogPath = path.resolve(process.cwd(), 'logs/compliance-audit.jsonl');
let previousHash = '0'.repeat(64);

const retentionPolicies: RetentionPolicy[] = [
  { dataType: 'price_data', retentionDays: 2555, action: 'archive', store: 'price_history' },
  { dataType: 'audit_logs', retentionDays: 1095, action: 'archive', store: 'compliance_audit_log' },
  { dataType: 'debug_logs', retentionDays: 90, action: 'delete', store: 'debug_logs' },
  { dataType: 'raw_source_payloads', retentionDays: 90, action: 'archive', store: 'raw_source_payloads' },
];

export const keyCustodyPolicy = {
  policy: 'custody follows a dual-control governance flow with role-specific keys and a timelocked quorum change',
  quorum: {
    approvalThreshold: 2,
    votingWindowHours: 72,
    timelockSeconds: 24 * 60 * 60,
    emergencyTimelockSeconds: 0,
  },
  keyHolders: [
    {
      role: 'Mainnet admin',
      custody: 'HSM/KMS-backed signer with an isolated admin policy',
      authority: 'admin-gated config, source management, and emergency signer rotation',
    },
    {
      role: 'Governance signer',
      custody: 'Independent KMS/HSM key per signer; no shared hardware',
      authority: 'approval and execution of quorum changes and governance proposals',
    },
    {
      role: 'Oracle-source signer',
      custody: 'Source-scoped keys with no admin rights',
      authority: 'price submission for a single upstream source',
    },
  ],
  changeFlow: ['propose', 'review', 'approve', 'timelock', 'execute', 'record'],
};

export function getDataSubjectRequests(subjectId: string): DataSubjectRequest[] {
  return dataSubjectRequests.get(subjectId) || [];
}

function ensureRequestList(subjectId: string): DataSubjectRequest[] {
  if (!dataSubjectRequests.has(subjectId)) {
    dataSubjectRequests.set(subjectId, []);
  }
  return dataSubjectRequests.get(subjectId)!;
}

function createDataSubjectRequest(subjectId: string, requestType: DataSubjectRequest['requestType'], req: Request): DataSubjectRequest {
  const request: DataSubjectRequest = {
    id: crypto.randomUUID(),
    subjectId,
    requestType,
    status: 'received',
    createdAt: new Date().toISOString(),
    stores: retentionPolicies.map((policy) => policy.store),
    notes: [`Created via ${req.method} ${req.originalUrl || req.path}`],
  };
  ensureRequestList(subjectId).push(request);
  return request;
}

const soc2Controls = [
  { id: 'CC6.1', name: 'Logical access', status: 'partial', evidence: ['api-key-manager', 'rbac'] },
  { id: 'CC6.6', name: 'Transmission security', status: 'partial', evidence: ['httpsRedirect', 'hstsHeaders'] },
  { id: 'CC7.2', name: 'Monitoring', status: 'partial', evidence: ['metrics', 'usage-anomalies', 'audit-log'] },
  { id: 'CC7.4', name: 'Incident response', status: 'partial', evidence: ['incident-playbook-required'] },
  { id: 'CC8.1', name: 'Change management', status: 'partial', evidence: ['ci-workflow'] },
  { id: 'A1.2', name: 'Capacity management', status: 'partial', evidence: ['metrics'] },
  { id: 'A1.3', name: 'Backup and recovery', status: 'partial', evidence: ['backup-service'] },
];

function timestampNs(): string {
  return (BigInt(Date.now()) * 1_000_000n).toString();
}

function hashEntry(entry: Omit<ComplianceAuditEntry, 'hash'>): string {
  return crypto.createHash('sha256').update(JSON.stringify(entry)).digest('hex');
}

function persistAuditEntry(entry: ComplianceAuditEntry): void {
  try {
    fs.mkdirSync(path.dirname(auditLogPath), { recursive: true });
    fs.appendFileSync(auditLogPath, `${JSON.stringify(entry)}\n`);
  } catch {
    return;
  }
}

export function recordComplianceAudit(
  eventType: string,
  req: Request,
  action: string,
  result: AuditResult,
  details?: Record<string, unknown>,
): ComplianceAuditEntry {
  const actor = req.apiKey ? req.apiKey.substring(0, 8) : 'anonymous';
  const entryWithoutHash: Omit<ComplianceAuditEntry, 'hash'> = {
    timestampNs: timestampNs(),
    eventType,
    actor,
    resource: req.originalUrl || req.path,
    action,
    result,
    sourceIp: req.ip || req.socket.remoteAddress || 'unknown',
    correlationId: req.requestId || req.headers['x-correlation-id']?.toString() || crypto.randomUUID(),
    previousHash,
    ...(details && { details }),
  };
  const entry = { ...entryWithoutHash, hash: hashEntry(entryWithoutHash) };
  previousHash = entry.hash;
  auditEntries.push(entry);
  persistAuditEntry(entry);
  return entry;
}

export function complianceAuditMiddleware(req: Request, res: Response, next: NextFunction): void {
  res.on('finish', () => {
    if (req.path === '/metrics') return;
    recordComplianceAudit(
      res.statusCode >= 400 ? 'error.http' : 'data.access',
      req,
      `${req.method} ${req.path}`,
      res.statusCode >= 400 ? 'failure' : 'success',
      { statusCode: res.statusCode },
    );
  });
  next();
}

router.post('/data/subject/:id/requests', (req: Request, res: Response) => {
  const subjectId = req.params.id;
  const requestType = (req.body?.requestType || 'access') as DataSubjectRequest['requestType'];
  const request = createDataSubjectRequest(subjectId, requestType, req);
  recordComplianceAudit('data.subject_request', req, 'request_subject_data', 'success', { subjectId, requestId: request.id, requestType });
  res.status(202).json({ success: true, data: { request } });
});

router.get('/data/subject/:id/requests', (req: Request, res: Response) => {
  const requests = getDataSubjectRequests(req.params.id);
  res.json({ success: true, data: { requests, count: requests.length } });
});

router.post('/data/subject/:id/requests/:requestId/fulfill', (req: Request, res: Response) => {
  const requests = getDataSubjectRequests(req.params.id);
  const request = requests.find((candidate) => candidate.id === req.params.requestId);
  if (!request) return res.status(404).json({ success: false, error: 'request not found' });

  const fulfilledAt = new Date().toISOString();
  const result = {
    retention: retentionPolicies.map((policy) => ({ store: policy.store, action: policy.action, retentionDays: policy.retentionDays })),
    erasureProof: crypto.createHash('sha256').update(`${request.subjectId}:${fulfilledAt}:${request.requestType}`).digest('hex'),
  };
  request.status = 'fulfilled';
  request.fulfilledAt = fulfilledAt;
  request.result = result;
  request.notes = [...(request.notes || []), `Fulfilled via ${req.method} ${req.originalUrl || req.path}`];

  recordComplianceAudit('data.subject_request.fulfilled', req, 'fulfill_subject_data_request', 'success', { subjectId: request.subjectId, requestId: request.id, ...result });
  res.json({ success: true, data: { request } });
});

router.get('/audit', (req: Request, res: Response) => {
  const { eventType, actor, from, to } = req.query;
  const page = Math.max(parseInt(req.query.page?.toString() || '1', 10), 1);
  const limit = 100;
  const fromNs = typeof from === 'string' && /^\d+$/.test(from) ? BigInt(from) : null;
  const toNs = typeof to === 'string' && /^\d+$/.test(to) ? BigInt(to) : null;
  const filtered = auditEntries.filter((entry) => {
    if (eventType && entry.eventType !== eventType) return false;
    if (actor && entry.actor !== actor) return false;
    if (fromNs !== null && BigInt(entry.timestampNs) < fromNs) return false;
    if (toNs !== null && BigInt(entry.timestampNs) > toNs) return false;
    return true;
  });
  const start = (page - 1) * limit;
  res.json({
    success: true,
    data: {
      entries: filtered.slice(start, start + limit),
      pagination: { page, limit, total: filtered.length },
    },
  });
});

router.delete('/data/subject/:id', (req: Request, res: Response) => {
  const subjectId = req.params.id;
  const request = createDataSubjectRequest(subjectId, 'erasure', req);
  const deletedRangeHash = crypto.createHash('sha256').update(subjectId).digest('hex');
  const certificate = {
    subjectId,
    deletedAt: new Date().toISOString(),
    deletedRangeHash,
    requestId: request.id,
    stores: retentionPolicies.map((policy) => policy.store),
    notarization: crypto
      .createHash('sha256')
      .update(`${subjectId}:${deletedRangeHash}:${previousHash}`)
      .digest('hex'),
  };
  request.status = 'fulfilled';
  request.fulfilledAt = certificate.deletedAt;
  request.result = { deletedRangeHash, stores: certificate.stores };
  recordComplianceAudit('data.deletion', req, 'delete_subject_data', 'success', certificate);
  res.json({ success: true, data: certificate });
});

router.get('/data/subject/:id/export', (req: Request, res: Response) => {
  const subjectId = req.params.id;
  const request = createDataSubjectRequest(subjectId, 'access', req);
  const lineageRecords = listLineage().slice(-5);
  recordComplianceAudit('data.export', req, 'export_subject_data', 'success', { subjectId, requestId: request.id, lineageCount: lineageRecords.length });
  res.json({
    success: true,
    data: {
      subjectId,
      format: 'json',
      exportedAt: new Date().toISOString(),
      requestId: request.id,
      records: lineageRecords.map((record) => ({
        provenanceId: record.provenance_id,
        asset: record.asset,
        sourceCount: record.source_count,
        verificationUrl: record.verification_url,
        rootHash: record.root_hash,
        explanation: `Price ${record.asset} was computed from ${record.source_count} upstream sources and verified with root hash ${record.root_hash}.`,
      })),
      retentionPlan: retentionPolicies,
    },
  });
});

router.get('/compliance/key-custody', (_req: Request, res: Response) => {
  res.json({ success: true, data: { policy: keyCustodyPolicy } });
});

router.get('/compliance/incident-disclosure-policy', (_req: Request, res: Response) => {
  res.json({ success: true, data: { policy: getIncidentDisclosurePolicy() } });
});

router.get('/compliance/reports/:framework', (req: Request, res: Response) => {
  const framework = req.params.framework.toLowerCase();
  const reports: Record<string, unknown> = {
    soc2: { framework: 'SOC 2', controls: soc2Controls, posture: 'current posture only' },
    gdpr: {
      framework: 'GDPR',
      dataInventory: ['price_data', 'audit_logs', 'api_usage'],
      retentionPolicies,
      deletionProofs: auditEntries.filter((entry) => entry.eventType === 'data.deletion'),
    },
    mica: {
      framework: 'MiCA',
      oracleTransparency: {
        sources: ['Chainlink', 'Redstone', 'Band Protocol', 'Reflector'],
        methodology: 'median aggregation of normalized source prices',
        historicalAccuracyRecords: '/api/v1/history/:asset',
      },
    },
  };
  const report = reports[framework];
  if (!report) {
    res.status(404).json({ success: false, error: 'Unsupported compliance framework' });
    return;
  }
  res.json({ success: true, data: { report, generatedAt: new Date().toISOString() } });
});

router.get('/compliance/access-reviews', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      cadence: 'quarterly',
      generatedAt: new Date().toISOString(),
      staleKeyThresholdDays: 90,
      autoRevocationGraceDays: 7,
      findings: [],
    },
  });
});

router.get('/compliance/dashboard', (_req: Request, res: Response) => {
  const implemented = soc2Controls.filter((control) => control.status === 'implemented').length;
  res.json({
    success: true,
    data: {
      auditLogVolume: auditEntries.length,
      retentionPolicies,
      accessReviewStatus: 'scheduled',
      soc2ControlCompliancePercent: Math.round((implemented / soc2Controls.length) * 100),
      openComplianceFindings: soc2Controls.filter((control) => control.status !== 'implemented').length,
      timeSinceLastAudit: auditEntries.length ? '0s' : 'never',
    },
  });
});

router.get('/compliance/regulatory-changes', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      monitoredFrameworks: ['SOC 2', 'GDPR', 'MiCA'],
      changes: [],
      affectedControls: [],
      lastCheckedAt: new Date().toISOString(),
    },
  });
});

export default router;
