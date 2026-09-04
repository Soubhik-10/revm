//! EIP-8141 frame transaction execution payload.

use crate::cfg::GasParams;
use alloy_eip8141::{Frame, FrameSignature, FRAME_TX_INTRINSIC_COST, FRAME_TX_PER_FRAME_COST};
use primitives::{eip2780, hardfork::SpecId, Address, B256, U256};
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
    /// EIP-8141 priority-fee cap.
    pub max_priority_fee_per_gas: U256,
    /// EIP-8141 fee cap. Unlike ordinary transaction fee caps, this is a full
    /// 256-bit RLP quantity because approval bounds use the transaction gas cap.
    pub max_fee_per_gas: U256,
    /// EIP-8141 blob-fee inclusion cap.
    pub max_fee_per_blob_gas: U256,
}

impl FrameTransaction {
    /// Calculates the EIP-1559 effective price without narrowing EIP-8141's
    /// 256-bit fee fields.
    #[inline]
    pub fn effective_gas_price(&self, base_fee: u128) -> U256 {
        self.max_fee_per_gas.min(
            U256::from(base_fee)
                .checked_add(self.max_priority_fee_per_gas)
                .unwrap_or(U256::MAX),
        )
    }

    /// Returns the sum of all top-level frame gas allocations.
    pub fn total_frame_gas_limit(&self) -> Option<u64> {
        self.frames.iter().try_fold(0u64, |total, frame| {
            total
                .checked_add(frame.limits.execution)?
                .checked_add(frame.limits.state)
        })
    }

    /// Returns the sum of all top-level frame execution-gas allocations.
    pub fn total_frame_execution_gas_limit(&self) -> Option<u64> {
        self.frames.iter().try_fold(0u64, |total, frame| {
            total.checked_add(frame.limits.execution)
        })
    }

    /// Returns the sum of all top-level frame state-gas allocations.
    pub fn total_frame_state_gas_limit(&self) -> Option<u64> {
        self.frames
            .iter()
            .try_fold(0u64, |total, frame| total.checked_add(frame.limits.state))
    }

    /// Returns gas charged for protocol validation of all signatures.
    pub fn signature_verification_gas(&self) -> Option<u64> {
        self.signatures.iter().try_fold(0u64, |total, signature| {
            total.checked_add(signature.verification_gas())
        })
    }

    /// Counts EIP-8141 charged calldata tokens (zero byte = 1, non-zero byte = 4).
    pub fn calldata_tokens(&self) -> u64 {
        self.calldata_tokens_with_multipliers(1, 4)
    }

    /// Counts charged calldata tokens with fork-specific zero/non-zero byte multipliers.
    pub fn calldata_tokens_with_multipliers(
        &self,
        zero_byte_multiplier: u64,
        non_zero_byte_multiplier: u64,
    ) -> u64 {
        let tokens = |bytes: &[u8]| {
            bytes.iter().fold(0u64, |total, byte| {
                total.saturating_add(if *byte == 0 {
                    zero_byte_multiplier
                } else {
                    non_zero_byte_multiplier
                })
            })
        };
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

    /// Returns the EIP-2780 value-transfer charge for frames with an explicit target other than
    /// the transaction sender.
    pub fn value_transfer_gas(&self, sender: Address, _gas_params: &GasParams) -> u64 {
        self.frames.iter().fold(0u64, |total, frame| {
            let cost = if !frame.value.is_zero()
                && !frame.target.is_empty()
                && frame.target_address() != Some(sender)
            {
                // EIP-8141 uses EIP-2780's transaction value charge for
                // value-bearing frames. This is distinct from CALLVALUE,
                // which includes the call stipend and is used by the EVM
                // CALL path.
                eip2780::TX_VALUE_COST
            } else {
                0
            };
            total.saturating_add(cost)
        })
    }

    /// Calculates the transaction intrinsic gas, excluding top-level frame allocations.
    pub fn intrinsic_gas(&self, sender: Address) -> Option<u64> {
        self.intrinsic_gas_with_params(sender, &GasParams::new_spec(SpecId::AMSTERDAM))
    }

    /// Calculates intrinsic gas using the active fork's gas parameters.
    pub fn intrinsic_gas_with_params(
        &self,
        sender: Address,
        gas_params: &GasParams,
    ) -> Option<u64> {
        let frame_cost = (self.frames.len() as u64).checked_mul(FRAME_TX_PER_FRAME_COST)?;
        let calldata_cost = self
            .calldata_tokens_with_multipliers(1, gas_params.tx_token_non_zero_byte_multiplier())
            .checked_mul(gas_params.tx_token_cost())?;
        FRAME_TX_INTRINSIC_COST
            .checked_add(frame_cost)?
            .checked_add(calldata_cost)?
            .checked_add(self.signature_verification_gas()?)
            .and_then(|gas| gas.checked_add(self.value_transfer_gas(sender, gas_params)))
    }

    /// Calculates the derived transaction gas limit.
    pub fn gas_limit(&self, sender: Address) -> Option<u64> {
        self.gas_limit_with_params(sender, &GasParams::new_spec(SpecId::AMSTERDAM))
    }

    /// Calculates the derived transaction gas limit using the active fork's gas parameters.
    pub fn gas_limit_with_params(&self, sender: Address, gas_params: &GasParams) -> Option<u64> {
        let standard = self
            .intrinsic_gas_with_params(sender, gas_params)?
            .checked_add(self.total_frame_gas_limit()?)?;
        let floor = self
            .calldata_floor_gas_with_params(sender, gas_params)?
            .checked_add(self.total_frame_state_gas_limit()?)?;
        Some(standard.max(floor))
    }

    /// Calculates the calldata floor using the default Amsterdam gas parameters.
    pub fn calldata_floor_gas(&self, sender: Address) -> Option<u64> {
        self.calldata_floor_gas_with_params(sender, &GasParams::new_spec(SpecId::AMSTERDAM))
    }

    /// Calculates the calldata floor using the active fork's gas parameters.
    pub fn calldata_floor_gas_with_params(
        &self,
        sender: Address,
        gas_params: &GasParams,
    ) -> Option<u64> {
        let frame_cost = (self.frames.len() as u64).checked_mul(FRAME_TX_PER_FRAME_COST)?;
        let calldata_floor = self
            .calldata_tokens_with_multipliers(
                gas_params.tx_floor_token_zero_byte_multiplier(),
                gas_params.tx_token_non_zero_byte_multiplier(),
            )
            .checked_mul(gas_params.tx_floor_cost_per_token())?;
        FRAME_TX_INTRINSIC_COST
            .checked_add(frame_cost)?
            .checked_add(self.signature_verification_gas()?)?
            .checked_add(calldata_floor)?
            .checked_add(self.value_transfer_gas(sender, gas_params))
    }

    /// Calculates the maximum fee exposure checked when a payer approves payment.
    ///
    /// `blob_base_fee` is used for blob costs because `max_fee_per_blob_gas` is only
    /// an inclusion bound for EIP-8141 transactions.
    pub fn checked_max_cost(
        &self,
        sender: Address,
        blob_gas: u64,
        blob_base_fee: u128,
    ) -> Option<U256> {
        self.checked_max_cost_with_params(
            sender,
            &GasParams::new_spec(SpecId::AMSTERDAM),
            blob_gas,
            blob_base_fee,
        )
    }

    /// Calculates maximum fee exposure using the active fork's gas parameters.
    pub fn checked_max_cost_with_params(
        &self,
        sender: Address,
        gas_params: &GasParams,
        blob_gas: u64,
        blob_base_fee: u128,
    ) -> Option<U256> {
        U256::from(self.gas_limit_with_params(sender, gas_params)?)
            .checked_mul(self.max_fee_per_gas)?
            .checked_add(U256::from(blob_gas).checked_mul(U256::from(blob_base_fee))?)
    }

    /// Calculates the validated maximum fee exposure.
    ///
    /// Frame transactions whose maximum cost overflows are rejected during validation.
    pub fn max_cost(&self, sender: Address, blob_gas: u64, blob_base_fee: u128) -> U256 {
        self.checked_max_cost(sender, blob_gas, blob_base_fee)
            .expect("EIP-8141 maximum cost must be validated before execution")
    }

    /// Calculates validated maximum fee exposure using the active fork's gas parameters.
    pub fn max_cost_with_params(
        &self,
        sender: Address,
        gas_params: &GasParams,
        blob_gas: u64,
        blob_base_fee: u128,
    ) -> U256 {
        self.checked_max_cost_with_params(sender, gas_params, blob_gas, blob_base_fee)
            .expect("EIP-8141 maximum cost must be validated before execution")
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
                limits: alloy_eip8141::FrameLimits {
                    execution: 100,
                    state: 0,
                },
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

        // Two zero bytes and two non-zero bytes are ten standard calldata tokens.
        // Arbitrary signatures carry the fixed protocol-verification charge from EIP-8141.
        assert_eq!(transaction.calldata_tokens(), 10);
        assert_eq!(transaction.signature_verification_gas(), Some(100));
        assert_eq!(transaction.intrinsic_gas(Address::ZERO), Some(12_615));
        assert_eq!(transaction.gas_limit(Address::ZERO), Some(12_831));
        assert_eq!(transaction.calldata_floor_gas(Address::ZERO), Some(12_831));
    }

    #[test]
    fn effective_gas_price_preserves_full_width_fee_caps() {
        let transaction = FrameTransaction {
            max_priority_fee_per_gas: U256::from(u128::MAX) + U256::from(2),
            max_fee_per_gas: U256::from(u128::MAX) + U256::from(3),
            ..Default::default()
        };

        assert_eq!(
            transaction.effective_gas_price(1),
            U256::from(u128::MAX) + U256::from(3)
        );
    }
}
