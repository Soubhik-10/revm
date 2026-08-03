//! EIP-8141 frame transaction execution payload.

use alloy_eip8141::{
    Frame, FrameSignature, FRAME_TX_DATA_TOKEN_STANDARD_COST, FRAME_TX_INTRINSIC_COST,
    FRAME_TX_PER_FRAME_COST, FRAME_TX_TOTAL_COST_FLOOR_PER_TOKEN,
};
use primitives::{B256, U256};
use std::vec::Vec;

/// The consensus-decoded data REVM needs to execute an EIP-8141 frame transaction.
///
/// Envelope encoding and hashing remain owned by the consensus library. `signature_hash` is the
/// canonical type-`0x06` signing hash calculated there and supplied to REVM for protocol signature
/// validation and `TXPARAM`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "camelCase"))]
pub struct FrameTransaction {
    /// Ordered top-level frames.
    pub frames: Vec<Frame>,
    /// Signature and witness entries exposed to validation code.
    pub signatures: Vec<FrameSignature>,
    /// Canonical EIP-8141 signature hash.
    pub signature_hash: B256,
}

impl FrameTransaction {
    /// Returns the sum of all top-level frame gas allocations.
    pub fn total_frame_gas_limit(&self) -> Option<u64> {
        self.frames
            .iter()
            .try_fold(0u64, |total, frame| total.checked_add(frame.gas_limit))
    }

    /// Returns gas charged for protocol validation of all signatures.
    pub fn signature_verification_gas(&self) -> Option<u64> {
        self.signatures.iter().try_fold(0u64, |total, signature| {
            total.checked_add(signature.verification_gas())
        })
    }

    /// Counts EIP-8141 charged calldata tokens (zero byte = 1, non-zero byte = 4).
    pub fn calldata_tokens(&self) -> u64 {
        fn tokens(bytes: &[u8]) -> u64 {
            bytes.iter().fold(0u64, |total, byte| {
                total.saturating_add(if *byte == 0 { 1 } else { 4 })
            })
        }

        let frame_tokens = self.frames.iter().fold(0u64, |total, frame| {
            total.saturating_add(tokens(&frame.data))
        });
        self.signatures
            .iter()
            .fold(frame_tokens, |total, signature| {
                total
                    .saturating_add(tokens(&signature.signer))
                    .saturating_add(tokens(&signature.msg))
                    .saturating_add(tokens(&signature.signature))
            })
    }

    /// Returns the byte length of the charged calldata fields.
    pub fn calldata_len(&self) -> u64 {
        let frame_len = self.frames.iter().fold(0u64, |total, frame| {
            total.saturating_add(frame.data.len() as u64)
        });
        self.signatures.iter().fold(frame_len, |total, signature| {
            total
                .saturating_add(signature.signer.len() as u64)
                .saturating_add(signature.msg.len() as u64)
                .saturating_add(signature.signature.len() as u64)
        })
    }

    /// Calculates the transaction intrinsic gas, excluding top-level frame allocations.
    pub fn intrinsic_gas(&self) -> Option<u64> {
        let frame_cost = (self.frames.len() as u64).checked_mul(FRAME_TX_PER_FRAME_COST)?;
        let calldata_cost = self
            .calldata_tokens()
            .checked_mul(FRAME_TX_DATA_TOKEN_STANDARD_COST)?;
        FRAME_TX_INTRINSIC_COST
            .checked_add(frame_cost)?
            .checked_add(calldata_cost)?
            .checked_add(self.signature_verification_gas()?)
    }

    /// Calculates the derived transaction gas limit.
    pub fn gas_limit(&self) -> Option<u64> {
        let standard = self.intrinsic_gas()?.checked_add(self.total_frame_gas_limit()?)?;
        Some(standard.max(self.calldata_floor_gas()?))
    }

    /// Calculates the EIP-7623 total-cost floor for the charged frame transaction data.
    pub fn calldata_floor_gas(&self) -> Option<u64> {
        let frame_cost = (self.frames.len() as u64).checked_mul(FRAME_TX_PER_FRAME_COST)?;
        let calldata_floor = self
            .calldata_tokens()
            .checked_mul(FRAME_TX_TOTAL_COST_FLOOR_PER_TOKEN)?;
        FRAME_TX_INTRINSIC_COST
            .checked_add(frame_cost)?
            .checked_add(self.signature_verification_gas()?)?
            .checked_add(calldata_floor)
    }

    /// Calculates the maximum fee exposure checked when a payer approves payment.
    ///
    /// `blob_base_fee` is used for blob costs because `max_fee_per_blob_gas` is only
    /// an inclusion bound for EIP-8141 transactions.
    pub fn max_cost(&self, max_fee_per_gas: u128, blob_gas: u64, blob_base_fee: u128) -> U256 {
        U256::from(self.gas_limit().unwrap_or(u64::MAX))
            .saturating_mul(U256::from(max_fee_per_gas))
            .saturating_add(U256::from(blob_gas).saturating_mul(U256::from(blob_base_fee)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_eip8141::{FrameMode, SignatureScheme};
    use primitives::Bytes;

    #[test]
    fn gas_accounting_matches_execution_specs_schedule() {
        let transaction = FrameTransaction {
            frames: vec![Frame {
                mode: FrameMode::Default,
                gas_limit: 100,
                data: Bytes::from_static(&[0, 1]),
                ..Default::default()
            }],
            signatures: vec![FrameSignature {
                scheme: SignatureScheme::Arbitrary,
                signature: Bytes::from_static(&[0, 1]),
                ..Default::default()
            }],
            ..Default::default()
        };

        // Two zero bytes and two non-zero bytes are ten calldata tokens. Arbitrary
        // signatures carry the fixed protocol-verification charge from EIP-8141.
        assert_eq!(transaction.calldata_tokens(), 10);
        assert_eq!(transaction.signature_verification_gas(), Some(100));
        assert_eq!(transaction.intrinsic_gas(), Some(15_615));
        assert_eq!(transaction.gas_limit(), Some(15_715));
        assert_eq!(transaction.calldata_floor_gas(), Some(15_675));
    }
}
