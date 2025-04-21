use alloy_consensus::BlockHeader;
use alloy_primitives::B256;
use alloy_rpc_types_engine::{ExecutionPayloadEnvelopeV2, ExecutionPayloadV1};
use alloy_rpc_types_engine::{
    ExecutionData, ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4,
    PayloadAttributes,
};
use reth_chainspec::ChainSpec;
use reth_consensus::ConsensusError;
use reth_node_api::{
    payload::{
        validate_parent_beacon_block_root_presence, EngineApiMessageVersion,
        EngineObjectValidationError, MessageValidationKind, NewPayloadError, PayloadOrAttributes,
        PayloadTypes, VersionSpecificValidationError,
    },
    validate_version_specific_fields, BuiltPayload, EngineTypes, EngineValidator, NodePrimitives,
    PayloadValidator,
};
use reth_chainspec::ChainSpec;
use reth_seismic_consensus::isthmus;
use reth_seismic_hardforks::{OpHardfork, OpHardforks};
use reth_seismic_payload_builder::{
    OpBuiltPayload, OpExecutionPayloadValidator, OpPayloadBuilderAttributes,
};
use reth_seismic_primitives::{SeismicBlock, SeismicPrimitives, ADDRESS_L2_TO_L1_MESSAGE_PASSER};
use reth_primitives_traits::{RecoveredBlock, SealedBlock};
use reth_provider::StateProviderFactory;
use reth_trie_common::{HashedPostState, KeyHasher};
use std::sync::Arc;

/// The types used in the optimism beacon consensus engine.
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct SeismicEngineTypes<T: PayloadTypes = OpPayloadTypes> {
    _marker: std::marker::PhantomData<T>,
}

impl<
        T: PayloadTypes<
            ExecutionData = ExecutionData,
            BuiltPayload: BuiltPayload<Primitives: NodePrimitives<Block = SeismicBlock>>,
        >,
    > PayloadTypes for SeismicEngineTypes<T>
{
    type ExecutionData = T::ExecutionData;
    type BuiltPayload = T::BuiltPayload;
    type PayloadAttributes = T::PayloadAttributes;
    type PayloadBuilderAttributes = T::PayloadBuilderAttributes;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> <T as PayloadTypes>::ExecutionData {
        ExecutionData::from_block_unchecked(block.hash(), &block.into_block())
    }
}

impl<T: PayloadTypes<ExecutionData = ExecutionData>> EngineTypes for SeismicEngineTypes<T>
where
    T::BuiltPayload: BuiltPayload<Primitives: NodePrimitives<Block = SeismicBlock>>
        + TryInto<ExecutionPayloadV1>
        + TryInto<ExecutionPayloadEnvelopeV2>
        + TryInto<ExecutionPayloadEnvelopeV3>
        + TryInto<ExecutionPayloadEnvelopeV4>,
{
    type ExecutionPayloadEnvelopeV1 = ExecutionPayloadV1;
    type ExecutionPayloadEnvelopeV2 = ExecutionPayloadEnvelopeV2;
    type ExecutionPayloadEnvelopeV3 = ExecutionPayloadEnvelopeV3;
    type ExecutionPayloadEnvelopeV4 = ExecutionPayloadEnvelopeV4;
}

/// A default payload type for [`SeismicEngineTypes`]
#[derive(Debug, Default, Clone, serde::Deserialize, serde::Serialize)]
#[non_exhaustive]
pub struct OpPayloadTypes<N: NodePrimitives = SeismicPrimitives>(core::marker::PhantomData<N>);

impl<N: NodePrimitives> PayloadTypes for OpPayloadTypes<N>
where
    OpBuiltPayload<N>: BuiltPayload<Primitives: NodePrimitives<Block = SeismicBlock>>,
{
    type ExecutionData = ExecutionData;
    type BuiltPayload = OpBuiltPayload<N>;
    type PayloadAttributes = PayloadAttributes;
    type PayloadBuilderAttributes = OpPayloadBuilderAttributes<N::SignedTx>;

    fn block_to_payload(
        block: SealedBlock<
            <<Self::BuiltPayload as BuiltPayload>::Primitives as NodePrimitives>::Block,
        >,
    ) -> Self::ExecutionData {
        ExecutionData::from_block_unchecked(block.hash(), &block.into_block())
    }
}

/// Validator for Optimism engine API.
#[derive(Debug, Clone)]
pub struct SeismicEngineValidator<P> {
    inner: OpExecutionPayloadValidator<ChainSpec>,
    provider: P,
    hashed_addr_l2tol1_msg_passer: B256,
}

impl<P> SeismicEngineValidator<P> {
    /// Instantiates a new validator.
    pub fn new<KH: KeyHasher>(chain_spec: Arc<ChainSpec>, provider: P) -> Self {
        let hashed_addr_l2tol1_msg_passer = KH::hash_key(ADDRESS_L2_TO_L1_MESSAGE_PASSER);
        Self {
            inner: OpExecutionPayloadValidator::new(chain_spec),
            provider,
            hashed_addr_l2tol1_msg_passer,
        }
    }

    /// Returns the chain spec used by the validator.
    #[inline]
    fn chain_spec(&self) -> &ChainSpec {
        self.inner.chain_spec()
    }
}

impl<P> PayloadValidator for SeismicEngineValidator<P>
where
    P: StateProviderFactory + Unpin + 'static,
{
    type Block = SeismicBlock;
    type ExecutionData = ExecutionData;

    fn ensure_well_formed_payload(
        &self,
        payload: Self::ExecutionData,
    ) -> Result<RecoveredBlock<Self::Block>, NewPayloadError> {
        let sealed_block =
            self.inner.ensure_well_formed_payload(payload).map_err(NewPayloadError::other)?;
        sealed_block.try_recover().map_err(|e| NewPayloadError::Other(e.into()))
    }

    fn validate_block_post_execution_with_hashed_state(
        &self,
        state_updates: &HashedPostState,
        block: &RecoveredBlock<Self::Block>,
    ) -> Result<(), ConsensusError> {
        if self.chain_spec().is_isthmus_active_at_timestamp(block.timestamp()) {
            let state = self.provider.state_by_block_hash(block.parent_hash()).map_err(|err| {
                ConsensusError::Other(format!("failed to verify block post-execution: {err}"))
            })?;
            let predeploy_storage_updates = state_updates
                .storages
                .get(&self.hashed_addr_l2tol1_msg_passer)
                .cloned()
                .unwrap_or_default();
            isthmus::verify_withdrawals_root_prehashed(
                predeploy_storage_updates,
                state,
                block.header(),
            )
            .map_err(|err| {
                ConsensusError::Other(format!("failed to verify block post-execution: {err}"))
            })?
        }

        Ok(())
    }
}

impl<Types, P> EngineValidator<Types> for SeismicEngineValidator<P>
where
    Types: PayloadTypes<PayloadAttributes = PayloadAttributes, ExecutionData = ExecutionData>,
    P: StateProviderFactory + Unpin + 'static,
{
    fn validate_version_specific_fields(
        &self,
        version: EngineApiMessageVersion,
        payload_or_attrs: PayloadOrAttributes<'_, Self::ExecutionData, PayloadAttributes>,
    ) -> Result<(), EngineObjectValidationError> {
        validate_withdrawals_presence(
            self.chain_spec(),
            version,
            payload_or_attrs.message_validation_kind(),
            payload_or_attrs.timestamp(),
            payload_or_attrs.withdrawals().is_some(),
        )?;
        validate_parent_beacon_block_root_presence(
            self.chain_spec(),
            version,
            payload_or_attrs.message_validation_kind(),
            payload_or_attrs.timestamp(),
            payload_or_attrs.parent_beacon_block_root().is_some(),
        )
    }

    fn ensure_well_formed_attributes(
        &self,
        version: EngineApiMessageVersion,
        attributes: &PayloadAttributes,
    ) -> Result<(), EngineObjectValidationError> {
        validate_version_specific_fields(
            self.chain_spec(),
            version,
            PayloadOrAttributes::<Self::ExecutionData, PayloadAttributes>::PayloadAttributes(
                attributes,
            ),
        )?;

        if attributes.gas_limit.is_none() {
            return Err(EngineObjectValidationError::InvalidParams(
                "MissingGasLimitInPayloadAttributes".to_string().into(),
            ))
        }

        if self
            .chain_spec()
            .is_holocene_active_at_timestamp(attributes.payload_attributes.timestamp)
        {
            let (elasticity, denominator) =
                attributes.decode_eip_1559_params().ok_or_else(|| {
                    EngineObjectValidationError::InvalidParams(
                        "MissingEip1559ParamsInPayloadAttributes".to_string().into(),
                    )
                })?;
            if elasticity != 0 && denominator == 0 {
                return Err(EngineObjectValidationError::InvalidParams(
                    "Eip1559ParamsDenominatorZero".to_string().into(),
                ))
            }
        }

        Ok(())
    }
}

/// Validates the presence of the `withdrawals` field according to the payload timestamp.
///
/// After Canyon, withdrawals field must be [Some].
/// Before Canyon, withdrawals field must be [None];
///
/// Canyon activates the Shanghai EIPs, see the Canyon specs for more details:
/// <https://github.com/ethereum-optimism/optimism/blob/ab926c5fd1e55b5c864341c44842d6d1ca679d99/specs/superchain-upgrades.md#canyon>
pub fn validate_withdrawals_presence(
    chain_spec: &ChainSpec,
    version: EngineApiMessageVersion,
    message_validation_kind: MessageValidationKind,
    timestamp: u64,
    has_withdrawals: bool,
) -> Result<(), EngineObjectValidationError> {
    let is_shanghai = chain_spec.fork(OpHardfork::Canyon).active_at_timestamp(timestamp);

    match version {
        EngineApiMessageVersion::V1 => {
            if has_withdrawals {
                return Err(message_validation_kind
                    .to_error(VersionSpecificValidationError::WithdrawalsNotSupportedInV1))
            }
            if is_shanghai {
                return Err(message_validation_kind
                    .to_error(VersionSpecificValidationError::NoWithdrawalsPostShanghai))
            }
        }
        EngineApiMessageVersion::V2 | EngineApiMessageVersion::V3 | EngineApiMessageVersion::V4 => {
            if is_shanghai && !has_withdrawals {
                return Err(message_validation_kind
                    .to_error(VersionSpecificValidationError::NoWithdrawalsPostShanghai))
            }
            if !is_shanghai && has_withdrawals {
                return Err(message_validation_kind
                    .to_error(VersionSpecificValidationError::HasWithdrawalsPreShanghai))
            }
        }
    };

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::engine;
    use alloy_primitives::{b64, Address, B256, B64};
    use alloy_rpc_types_engine::PayloadAttributes;
    use reth_node_builder::EngineValidator;
    use reth_chainspec::BASE_SEPOLIA;
    use reth_provider::noop::NoopProvider;
    use reth_trie_common::KeccakKeyHasher;

    fn get_chainspec() -> Arc<ChainSpec> {
        Arc::new(ChainSpec {
            inner: ChainSpec {
                chain: BASE_SEPOLIA.inner.chain,
                genesis: BASE_SEPOLIA.inner.genesis.clone(),
                genesis_header: BASE_SEPOLIA.inner.genesis_header.clone(),
                paris_block_and_final_difficulty: BASE_SEPOLIA
                    .inner
                    .paris_block_and_final_difficulty,
                hardforks: BASE_SEPOLIA.inner.hardforks.clone(),
                base_fee_params: BASE_SEPOLIA.inner.base_fee_params.clone(),
                prune_delete_limit: 10000,
                ..Default::default()
            },
        })
    }

    const fn get_attributes(eip_1559_params: Option<B64>, timestamp: u64) -> PayloadAttributes {
        PayloadAttributes {
            gas_limit: Some(1000),
            eip_1559_params,
            transactions: None,
            no_tx_pool: None,
            payload_attributes: PayloadAttributes {
                timestamp,
                prev_randao: B256::ZERO,
                suggested_fee_recipient: Address::ZERO,
                withdrawals: Some(vec![]),
                parent_beacon_block_root: Some(B256::ZERO),
            },
        }
    }

    #[test]
    fn test_well_formed_attributes_pre_holocene() {
        let validator =
            SeismicEngineValidator::new::<KeccakKeyHasher>(get_chainspec(), NoopProvider::default());
        let attributes = get_attributes(None, 1732633199);

        let result = <engine::SeismicEngineValidator<_> as EngineValidator<
            SeismicEngineTypes,
        >>::ensure_well_formed_attributes(
            &validator, EngineApiMessageVersion::V3, &attributes
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_well_formed_attributes_holocene_no_eip1559_params() {
        let validator =
            SeismicEngineValidator::new::<KeccakKeyHasher>(get_chainspec(), NoopProvider::default());
        let attributes = get_attributes(None, 1732633200);

        let result = <engine::SeismicEngineValidator<_> as EngineValidator<
            SeismicEngineTypes,
        >>::ensure_well_formed_attributes(
            &validator, EngineApiMessageVersion::V3, &attributes
        );
        assert!(matches!(result, Err(EngineObjectValidationError::InvalidParams(_))));
    }

    #[test]
    fn test_well_formed_attributes_holocene_eip1559_params_zero_denominator() {
        let validator =
            SeismicEngineValidator::new::<KeccakKeyHasher>(get_chainspec(), NoopProvider::default());
        let attributes = get_attributes(Some(b64!("0000000000000008")), 1732633200);

        let result = <engine::SeismicEngineValidator<_> as EngineValidator<
            SeismicEngineTypes,
        >>::ensure_well_formed_attributes(
            &validator, EngineApiMessageVersion::V3, &attributes
        );
        assert!(matches!(result, Err(EngineObjectValidationError::InvalidParams(_))));
    }

    #[test]
    fn test_well_formed_attributes_holocene_valid() {
        let validator =
            SeismicEngineValidator::new::<KeccakKeyHasher>(get_chainspec(), NoopProvider::default());
        let attributes = get_attributes(Some(b64!("0000000800000008")), 1732633200);

        let result = <engine::SeismicEngineValidator<_> as EngineValidator<
            SeismicEngineTypes,
        >>::ensure_well_formed_attributes(
            &validator, EngineApiMessageVersion::V3, &attributes
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_well_formed_attributes_holocene_valid_all_zero() {
        let validator =
            SeismicEngineValidator::new::<KeccakKeyHasher>(get_chainspec(), NoopProvider::default());
        let attributes = get_attributes(Some(b64!("0000000000000000")), 1732633200);

        let result = <engine::SeismicEngineValidator<_> as EngineValidator<
            SeismicEngineTypes,
        >>::ensure_well_formed_attributes(
            &validator, EngineApiMessageVersion::V3, &attributes
        );
        assert!(result.is_ok());
    }
}
