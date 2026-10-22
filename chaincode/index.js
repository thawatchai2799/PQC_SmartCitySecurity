'use strict';
const { Contract } = require('fabric-contract-api');
/**
 * CityAnchor chaincode - stores ONLY digests (never raw traffic / personal data).
 *   AnchorAlert(alertId, district, modelId, evidenceHash, ts)
 *   AnchorModel(round, modelHash, acceptedJSON, quarantinedJSON, screeningJSON)
 *   GetAlert(alertId) / GetModel(round) / VerifyAlert(alertId, evidenceHash)
 * Endorsement policy (set at deploy): MAJORITY of city-agency orgs.
 */
class CityAnchor extends Contract {
  async AnchorAlert(ctx, alertId, district, modelId, evidenceHash, ts) {
    const mspId = ctx.clientIdentity.getMSPID();          // enrolled agency only (MSP)
    const exists = await ctx.stub.getState(alertId);
    if (exists && exists.length) throw new Error(`alert ${alertId} already anchored`);
    const rec = { kind: 'ALERT', alertId, district, modelId, evidenceHash, ts, submitterMSP: mspId,
                  txId: ctx.stub.getTxID() };
    await ctx.stub.putState(alertId, Buffer.from(JSON.stringify(rec)));
    return JSON.stringify(rec);
  }
  async AnchorModel(ctx, round, modelHash, acceptedJSON, quarantinedJSON, screeningJSON) {
    const key = `MODEL_${round}`;
    const rec = { kind: 'MODEL_UPDATE', round: Number(round), modelHash, accepted: JSON.parse(acceptedJSON),
                  quarantined: JSON.parse(quarantinedJSON), screening: JSON.parse(screeningJSON),
                  submitterMSP: ctx.clientIdentity.getMSPID(), txId: ctx.stub.getTxID() };
    await ctx.stub.putState(key, Buffer.from(JSON.stringify(rec)));
    return JSON.stringify(rec);
  }
  async GetAlert(ctx, alertId) {
    const b = await ctx.stub.getState(alertId); if (!b || !b.length) throw new Error('not found'); return b.toString();
  }
  async GetModel(ctx, round) {
    const b = await ctx.stub.getState(`MODEL_${round}`); if (!b || !b.length) throw new Error('not found'); return b.toString();
  }
  async VerifyAlert(ctx, alertId, evidenceHash) {
    const b = await ctx.stub.getState(alertId); if (!b || !b.length) return JSON.stringify({ ok: false, reason: 'unknown alert' });
    const rec = JSON.parse(b.toString());
    return JSON.stringify({ ok: rec.evidenceHash === evidenceHash, anchored: rec });
  }
}
module.exports.contracts = [CityAnchor];
