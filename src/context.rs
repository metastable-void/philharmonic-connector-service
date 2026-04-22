use philharmonic_connector_common::{ConnectorCallContext, ConnectorTokenClaims};

// `now` used to seed `issued_at`; since connector-common 0.2.0 the
// claim set carries `iat` and `now` is no longer needed here. The
// parameter is dropped from the signature rather than kept-unused.
pub(crate) fn build_call_context(claims: &ConnectorTokenClaims) -> ConnectorCallContext {
    ConnectorCallContext {
        tenant_id: claims.tenant,
        instance_id: claims.inst,
        step_seq: claims.step,
        config_uuid: claims.config_uuid,
        issued_at: claims.iat,
        expires_at: claims.exp,
    }
}
