use alloy_rpc_types_engine::{
    ExecutionPayloadEnvelopeV3, ExecutionPayloadEnvelopeV4, ExecutionPayloadV3,
};
use op_alloy_rpc_types_engine::{OpExecutionPayloadEnvelopeV3, OpExecutionPayloadEnvelopeV4};

#[cfg(feature = "optimism")]
use op_alloy_rpc_types_engine::{OpExecutionPayloadEnvelopeV3, OpExecutionPayloadEnvelopeV4};

/// The execution payload envelope type.
pub trait PayloadEnvelopeExt: Send + Sync + std::fmt::Debug {
    /// Returns the execution payload V3 from the payload
    fn execution_payload(&self) -> ExecutionPayloadV3;
}

<<<<<<< HEAD
#[cfg(feature = "optimism")]
=======
>>>>>>> 5ef21cdfec9801b12dd740acc00970c5c778a2f2
impl PayloadEnvelopeExt for OpExecutionPayloadEnvelopeV3 {
    fn execution_payload(&self) -> ExecutionPayloadV3 {
        self.execution_payload.clone()
    }
}

<<<<<<< HEAD
#[cfg(feature = "optimism")]
=======
>>>>>>> 5ef21cdfec9801b12dd740acc00970c5c778a2f2
impl PayloadEnvelopeExt for OpExecutionPayloadEnvelopeV4 {
    fn execution_payload(&self) -> ExecutionPayloadV3 {
        self.execution_payload.clone()
    }
}

impl PayloadEnvelopeExt for ExecutionPayloadEnvelopeV3 {
    fn execution_payload(&self) -> ExecutionPayloadV3 {
        self.execution_payload.clone()
    }
}

impl PayloadEnvelopeExt for ExecutionPayloadEnvelopeV4 {
    fn execution_payload(&self) -> ExecutionPayloadV3 {
        self.execution_payload.clone()
    }
}
