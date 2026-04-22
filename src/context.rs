use philharmonic_connector_common::{ConnectorCallContext, ConnectorTokenClaims};
use philharmonic_types::UnixMillis;

pub(crate) fn build_call_context(
    claims: &ConnectorTokenClaims,
    now: UnixMillis,
) -> ConnectorCallContext {
    ConnectorCallContext {
        tenant_id: claims.tenant,
        instance_id: claims.inst,
        step_seq: claims.step,
        config_uuid: claims.config_uuid,
        issued_at: now,
        expires_at: claims.exp,
    }
}
