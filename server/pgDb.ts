import { Pool, PoolConfig } from 'pg';
import dotenv from 'dotenv';
import { ThreatItem, ThreatStatus } from '../src/types/threat';
import { TakedownDispatchRecord } from './db';

dotenv.config();

const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/phishnet_db';

class PostgresStore {
  private pool: Pool | null = null;
  public isConnected: boolean = false;

  constructor() {
    this.init();
  }

  private async init() {
    try {
      const config: PoolConfig = {
        connectionString,
        connectionTimeoutMillis: 2500,
        idleTimeoutMillis: 10000,
      };

      this.pool = new Pool(config);

      // Test connection
      const client = await this.pool.connect();
      this.isConnected = true;
      console.log('✅ [Postgres] Successfully connected to PostgreSQL database.');
      client.release();

      await this.runMigrations();
    } catch (err: any) {
      this.isConnected = false;
      console.log('ℹ️ [Postgres] PostgreSQL not detected or unreachable at ' + connectionString + '. Using resilient fallback storage.');
    }
  }

  private async runMigrations() {
    if (!this.pool || !this.isConnected) return;
    try {
      const query = `
        CREATE TABLE IF NOT EXISTS threats (
          id VARCHAR(64) PRIMARY KEY,
          url TEXT NOT NULL,
          domain VARCHAR(255) NOT NULL,
          target_brand VARCHAR(128) NOT NULL,
          threat_type VARCHAR(64) NOT NULL,
          discovery_source VARCHAR(64) NOT NULL,
          discovery_timestamp VARCHAR(64) NOT NULL,
          severity VARCHAR(32) NOT NULL,
          status VARCHAR(64) NOT NULL,
          similarity_score NUMERIC(5,2),
          p_hash_distance INT,
          structural_ssim NUMERIC(5,3),
          dom_edit_distance INT,
          logo_confidence NUMERIC(5,2),
          ip VARCHAR(64),
          asn VARCHAR(64),
          asn_name VARCHAR(255),
          country VARCHAR(128),
          country_code VARCHAR(8),
          registrar VARCHAR(255),
          ssl_issuer VARCHAR(255),
          ssl_serial VARCHAR(128),
          dns_nameservers JSONB,
          extracted_upi_vpa JSONB,
          extracted_phone_numbers JSONB,
          qr_code_payload TEXT,
          campaign_id VARCHAR(64),
          campaign_name VARCHAR(255),
          threat_actor_syndicate VARCHAR(255),
          evasion_tactics JSONB,
          screenshot_url TEXT,
          genuine_reference_url TEXT,
          evidence_hash VARCHAR(128),
          timeline JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS takedown_dispatches (
          id VARCHAR(64) PRIMARY KEY,
          threat_id VARCHAR(64) NOT NULL,
          target_domain VARCHAR(255) NOT NULL,
          target_brand VARCHAR(128) NOT NULL,
          channels JSONB,
          dispatched_at VARCHAR(64) NOT NULL,
          dispatched_by VARCHAR(128) NOT NULL,
          status VARCHAR(64) NOT NULL,
          tracking_number VARCHAR(128) NOT NULL,
          rfc_notice_excerpt TEXT,
          evidence_sha256 VARCHAR(128),
          recipients JSONB,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
      `;
      await this.pool.query(query);
      console.log('✅ [Postgres] Database schema migrations completed successfully.');
    } catch (err: any) {
      console.error('❌ [Postgres] Migration error:', err.message);
    }
  }

  public async saveThreat(threat: ThreatItem): Promise<boolean> {
    if (!this.pool || !this.isConnected) return false;
    try {
      const query = `
        INSERT INTO threats (
          id, url, domain, target_brand, threat_type, discovery_source, discovery_timestamp,
          severity, status, similarity_score, p_hash_distance, structural_ssim, dom_edit_distance,
          logo_confidence, ip, asn, asn_name, country, country_code, registrar, ssl_issuer,
          ssl_serial, dns_nameservers, extracted_upi_vpa, extracted_phone_numbers, qr_code_payload,
          campaign_id, campaign_name, threat_actor_syndicate, evasion_tactics, screenshot_url,
          genuine_reference_url, evidence_hash, timeline
        ) VALUES (
          $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19,
          $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30, $31, $32, $33, $34
        )
        ON CONFLICT (id) DO UPDATE SET
          status = EXCLUDED.status,
          similarity_score = EXCLUDED.similarity_score,
          timeline = EXCLUDED.timeline;
      `;
      await this.pool.query(query, [
        threat.id,
        threat.url,
        threat.domain,
        threat.targetBrand,
        threat.threatType,
        threat.discoverySource,
        threat.discoveryTimestamp,
        threat.severity,
        threat.status,
        threat.similarityScore,
        threat.pHashDistance,
        threat.structuralSSIM,
        threat.domEditDistance,
        threat.logoConfidence,
        threat.ip,
        threat.asn,
        threat.asnName,
        threat.country,
        threat.countryCode,
        threat.registrar,
        threat.sslIssuer,
        threat.sslSerial,
        JSON.stringify(threat.dnsNameservers || []),
        JSON.stringify(threat.extractedUPI_VPA || []),
        JSON.stringify(threat.extractedPhoneNumbers || []),
        threat.qrCodePayload || null,
        threat.campaignId || null,
        threat.campaignName || null,
        threat.threatActorSyndicate || null,
        JSON.stringify(threat.evasionTactics || {}),
        threat.screenshotUrl || null,
        threat.genuineReferenceUrl || null,
        threat.evidenceHash || null,
        JSON.stringify(threat.timeline || [])
      ]);
      return true;
    } catch (err: any) {
      console.error('❌ [Postgres] Save threat error:', err.message);
      return false;
    }
  }

  public async saveDispatch(dispatch: TakedownDispatchRecord): Promise<boolean> {
    if (!this.pool || !this.isConnected) return false;
    try {
      const query = `
        INSERT INTO takedown_dispatches (
          id, threat_id, target_domain, target_brand, channels, dispatched_at,
          dispatched_by, status, tracking_number, rfc_notice_excerpt, evidence_sha256, recipients
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status;
      `;
      await this.pool.query(query, [
        dispatch.id,
        dispatch.threatId,
        dispatch.targetDomain,
        dispatch.targetBrand,
        JSON.stringify(dispatch.channels || []),
        dispatch.dispatchedAt,
        dispatch.dispatchedBy,
        dispatch.status,
        dispatch.trackingNumber,
        dispatch.rfcNoticeExcerpt,
        dispatch.evidenceSha256,
        JSON.stringify(dispatch.recipients || [])
      ]);
      return true;
    } catch (err: any) {
      console.error('❌ [Postgres] Save dispatch error:', err.message);
      return false;
    }
  }

  public async updateStatus(threatId: string, status: ThreatStatus): Promise<boolean> {
    if (!this.pool || !this.isConnected) return false;
    try {
      await this.pool.query('UPDATE threats SET status = $1 WHERE id = $2', [status, threatId]);
      return true;
    } catch (err: any) {
      console.error('❌ [Postgres] Update threat status error:', err.message);
      return false;
    }
  }
}

export const pgStore = new PostgresStore();
