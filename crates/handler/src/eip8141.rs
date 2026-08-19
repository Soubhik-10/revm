//! EIP-8141 frame transaction validation and execution.

use crate::{EvmTr, Handler};
use alloy_eip8141::{
    FrameMode, FrameReceipt, FrameStatus, SignatureScheme, APPROVE_SCOPE_MASK, ENTRY_POINT,
    EXPIRY_VERIFIER, EXPIRY_VERIFIER_RUNTIME, MAX_FRAMES,
};
use context::{ContextTr, LocalContextTr};
use context_interface::{
    context::take_error,
    journaled_state::{account::JournaledAccountTr, WarmAccessSnapshot},
    local::{FrameApprovalState, FrameTransactionRuntime},
    result::{ExecutionResult, InvalidTransaction, ResultGas},
    Block, Cfg, Host, JournalTr, Transaction,
};
use interpreter::{
    interpreter_action::FrameInit, CallInput, CallInputs, CallScheme, CallValue, FrameInput,
    InstructionResult, SharedMemory,
};
use primitives::{hex, keccak256, Address, Bytes, KECCAK_EMPTY, U256};
use state::Bytecode as StateBytecode;
use std::{boxed::Box, vec::Vec};

struct AtomicBatch {
    checkpoint: context_interface::journaled_state::JournalCheckpoint,
    approval: FrameApprovalState,
    warm_accesses: WarmAccessSnapshot,
    receipt_start: usize,
}

fn invalid<ERROR: From<InvalidTransaction>>(message: &'static str) -> ERROR {
    InvalidTransaction::Str(message.into()).into()
}

/// Executes an EIP-8141 transaction through the mainnet handler's frame loop.
pub fn run<H: Handler + ?Sized>(
    handler: &mut H,
    evm: &mut H::Evm,
) -> Result<ExecutionResult<H::HaltReason>, H::Error> {
    handler.validate_env(evm)?;
    if !evm.ctx_ref().local().supports_eip8141() || !evm.ctx_ref().journal().supports_eip8141() {
        return Err(invalid(
            "EIP-8141 requires frame-capable local context and journal implementations",
        ));
    }
    validate_structure::<H>(evm)?;
    validate_sender_and_signatures::<H>(evm)?;
    handler.load_accounts(evm)?;

    let sender = evm.ctx_ref().tx().caller();
    // EIP-8141 starts with the sender warm. The protocol entry point is not
    // pre-warmed and must only be recorded if execution actually accesses it.
    evm.ctx()
        .journal_mut()
        .load_account(sender)
        .map_err(H::Error::from)?;
    evm.ctx()
        .local_mut()
        .set_frame_transaction(Some(FrameTransactionRuntime {
            resolved_target: sender,
            ..Default::default()
        }));

    let (intrinsic, floor_gas, frame_count) = {
        let frame_tx = evm
            .ctx_ref()
            .tx()
            .frame_transaction()
            .expect("validated frame tx");
        let gas_params = evm.ctx_ref().cfg().gas_params();
        (
            frame_tx.intrinsic_gas_with_params(gas_params).expect("validated gas"),
            frame_tx
                .calldata_floor_gas_with_params(gas_params)
                .expect("validated gas"),
            frame_tx.frames.len(),
        )
    };
    tracing::info!(
        target: "revm::eip8141",
        sender = ?sender,
        nonce = evm.ctx_ref().tx().nonce(),
        frame_count,
        intrinsic,
        floor_gas,
        "Starting EIP-8141 frame transaction"
    );
    let mut receipts = Vec::with_capacity(frame_count);
    let mut frame_state_gas = Vec::with_capacity(frame_count);
    let mut frame_refunds = Vec::with_capacity(frame_count);
    let mut batch: Option<AtomicBatch> = None;
    let mut frame_index = 0usize;

    while frame_index < frame_count {
        let (frame, target) = {
            let tx = evm.ctx_ref().tx();
            let frame = tx.frame_transaction().unwrap().frames[frame_index].clone();
            let target = frame
                .target_address()
                .or_else(|| frame.target.is_empty().then_some(tx.caller()))
                .expect("validated target");
            (frame, target)
        };
        let sender_approved = evm
            .ctx_ref()
            .local()
            .frame_transaction()
            .unwrap()
            .approval
            .sender_approved;
        if frame.mode == FrameMode::Sender && !sender_approved {
            return Err(invalid(
                "EIP-8141 SENDER frame executed before execution approval",
            ));
        }

        tracing::info!(
            target: "revm::eip8141",
            frame_index,
            mode = ?frame.mode,
            target = ?target,
            gas_limit = frame.gas_limit,
            flags = frame.flags,
            atomic = frame.is_atomic_batch(),
            sender_approved,
            "Starting EIP-8141 frame"
        );

        if batch.is_none() && frame.is_atomic_batch() {
            let checkpoint = evm.ctx().journal_mut().checkpoint();
            let runtime = evm.ctx_ref().local().frame_transaction().unwrap();
            batch = Some(AtomicBatch {
                checkpoint,
                approval: runtime.approval,
                warm_accesses: evm.ctx_ref().journal().warm_access_snapshot(),
                receipt_start: receipts.len(),
            });
            tracing::info!(
                target: "revm::eip8141",
                frame_index,
                "Opened atomic frame batch checkpoint"
            );
        }
        {
            let runtime = evm.ctx().local_mut().frame_transaction_mut().unwrap();
            runtime.current_frame_index = frame_index;
            runtime.resolved_target = target;
            runtime.root_approval = None;
            runtime.approval_stack.clear();
        }

        let frame_checkpoint = evm.ctx().journal_mut().checkpoint();
        let log_start = evm.ctx_ref().journal().logs().len();
        let (target_code_hash, frame_input) = frame_input::<H>(evm, &frame, target)?;
        let uses_default_code = frame.mode == FrameMode::Verify
            && target_code_hash == KECCAK_EMPTY
            && target != EXPIRY_VERIFIER;

        let (result, spent, state_gas, refund) = if uses_default_code {
            let valid = default_verification_is_valid::<H>(evm, target, frame.allowed_scope());
            let runtime = evm.ctx().local_mut().frame_transaction_mut().unwrap();
            runtime.enter_scope();
            let approval_result = if valid {
                evm.ctx()
                    .approve_frame(target, U256::from(frame.allowed_scope()))
            } else {
                Err(context_interface::host::FrameHostError::Revert)
            };
            let success = approval_result.is_ok();
            evm.ctx()
                .local_mut()
                .frame_transaction_mut()
                .unwrap()
                .exit_scope(success);
            (
                if success {
                    InstructionResult::Return
                } else {
                    InstructionResult::Revert
                },
                0,
                0,
                0,
            )
        } else {
            let memory =
                SharedMemory::new_with_buffer(evm.ctx_ref().local().shared_memory_buffer().clone());
            let mut frame_result = handler.run_exec_loop(
                evm,
                FrameInit {
                    depth: 0,
                    memory,
                    frame_input,
                },
            )?;
            let result = frame_result.instruction_result();
            let gas = frame_result.gas_mut();
            // Each EIP-8141 frame is a top-level call. Apply the same EIP-8037
            // finalization as the ordinary transaction top frame: reverted state-gas
            // charges are unwound, refunds are discarded, and exceptional halts consume
            // all regular gas.
            if !result.is_ok() {
                gas.rollback_state_gas();
                gas.set_refunded(0);
            }
            if !result.is_ok_or_revert() {
                gas.spend_all();
            }
            let spent = frame
                .gas_limit
                .saturating_sub(gas.remaining())
                .saturating_sub(gas.reservoir());
            let state_gas = gas.state_gas_spent().max(0) as u64;
            let refund = if result.is_ok() {
                gas.refunded().max(0) as u64
            } else {
                0
            };
            (result, spent, state_gas, refund)
        };

        take_error::<H::Error, _>(evm.ctx().error())?;
        let success = result.is_ok();
        tracing::info!(
            target: "revm::eip8141",
            frame_index,
            mode = ?frame.mode,
            result = ?result,
            success,
            gas_used = spent,
            state_gas,
            refund,
            "Finished EIP-8141 frame"
        );
        if success {
            evm.ctx().journal_mut().checkpoint_commit();
            evm.ctx()
                .local_mut()
                .frame_transaction_mut()
                .unwrap()
                .commit_root_approval();
            if let Some(atomic) = batch.as_mut() {
                atomic.warm_accesses = evm.ctx_ref().journal().warm_access_snapshot();
            }
        } else {
            evm.ctx().journal_mut().checkpoint_revert(frame_checkpoint);
        }
        evm.ctx().journal_mut().clear_transient_storage();

        if frame.mode == FrameMode::Verify && !success {
            return Err(invalid("EIP-8141 VERIFY frame failed"));
        }

        let logs = if success {
            evm.ctx_ref().journal().logs()[log_start..].to_vec()
        } else {
            Vec::new()
        };
        let status = if success {
            FrameStatus::Success
        } else {
            FrameStatus::Failure
        };
        receipts.push(FrameReceipt {
            status,
            gas_used: spent,
            logs,
        });
        frame_state_gas.push(state_gas);
        frame_refunds.push(refund);
        evm.ctx()
            .local_mut()
            .frame_transaction_mut()
            .unwrap()
            .statuses
            .push(status);

        if !success {
            if let Some(atomic) = batch.take() {
                tracing::info!(
                    target: "revm::eip8141",
                    frame_index,
                    "Reverting failed atomic frame batch"
                );
                evm.ctx().journal_mut().checkpoint_revert(atomic.checkpoint);
                evm.ctx()
                    .journal_mut()
                    .restore_warm_access_snapshot(&atomic.warm_accesses);
                let runtime = evm.ctx().local_mut().frame_transaction_mut().unwrap();
                runtime.approval = atomic.approval;
                runtime.root_approval = None;
                runtime.approval_stack.clear();
                // The failing frame keeps its own gas accounting. Earlier successful frames in
                // the batch become failures and lose state-gas credit when their state is rolled
                // back, while their regular gas remains charged.
                for index in atomic.receipt_start..receipts.len() - 1 {
                    receipts[index].status = FrameStatus::Failure;
                    receipts[index].logs.clear();
                    frame_state_gas[index] = 0;
                    frame_refunds[index] = 0;
                    runtime.statuses[index] = FrameStatus::Failure;
                }
                let mut end = frame_index;
                loop {
                    let atomic = evm.ctx_ref().tx().frame_transaction().unwrap().frames[end]
                        .is_atomic_batch();
                    if !atomic {
                        break;
                    }
                    end += 1;
                }
                for _ in frame_index + 1..=end {
                    receipts.push(FrameReceipt {
                        status: FrameStatus::SkippedAtomicBatch,
                        gas_used: 0,
                        logs: Vec::new(),
                    });
                    frame_state_gas.push(0);
                    frame_refunds.push(0);
                    evm.ctx()
                        .local_mut()
                        .frame_transaction_mut()
                        .unwrap()
                        .statuses
                        .push(FrameStatus::SkippedAtomicBatch);
                }
                tracing::info!(
                    target: "revm::eip8141",
                    failed_frame = frame_index,
                    skipped_through = end,
                    "Marked remaining atomic frames as skipped"
                );
                frame_index = end + 1;
                continue;
            }
        } else if !frame.is_atomic_batch() && batch.take().is_some() {
            evm.ctx().journal_mut().checkpoint_commit();
        }
        frame_index += 1;
    }

    let payer = evm
        .ctx_ref()
        .local()
        .frame_transaction()
        .unwrap()
        .approval
        .payer
        .ok_or_else(|| invalid::<H::Error>("EIP-8141 transaction did not approve a payer"))?;
    let total_frame_spent = receipts.iter().fold(0u64, |total, receipt| {
        total.saturating_add(receipt.gas_used)
    });
    let total_spent = intrinsic.saturating_add(total_frame_spent);
    let refund_counter = frame_refunds.into_iter().fold(0u64, u64::saturating_add);
    let refund =
        refund_counter.min(total_spent / evm.ctx_ref().cfg().gas_params().max_refund_quotient());
    let result_gas = ResultGas::default()
        .with_total_gas_spent(total_spent)
        .with_refunded(refund)
        .with_floor_gas(floor_gas)
        .with_state_gas_spent(frame_state_gas.into_iter().fold(0u64, u64::saturating_add));
    tracing::info!(
        target: "revm::eip8141",
        payer = ?payer,
        frame_count,
        intrinsic,
        floor_gas,
        total_frame_spent,
        total_spent,
        refund,
        tx_gas_used = result_gas.tx_gas_used(),
        "Settling EIP-8141 frame transaction"
    );
    settle_fees::<H>(evm, payer, result_gas.tx_gas_used())?;
    take_error::<H::Error, _>(evm.ctx().error())?;

    evm.ctx().journal_mut().commit_tx();
    evm.ctx().local_mut().clear();
    evm.frame_stack().clear();
    let logs = receipts
        .iter()
        .flat_map(|receipt| receipt.logs.iter().cloned())
        .collect();
    Ok(ExecutionResult::FrameTransaction {
        gas: result_gas,
        payer,
        logs,
        frame_receipts: receipts,
    })
}

fn validate_structure<H: Handler + ?Sized>(evm: &mut H::Evm) -> Result<(), H::Error> {
    let ctx = evm.ctx_ref();
    let tx = ctx.tx();
    let frame_tx = tx
        .frame_transaction()
        .ok_or_else(|| invalid::<H::Error>("missing EIP-8141 frame transaction payload"))?;
    let has_access_list = tx
        .access_list()
        .is_some_and(|mut access_list| access_list.next().is_some());
    if tx.kind() != primitives::TxKind::Call(tx.caller())
        || !tx.value().is_zero()
        || !tx.input().is_empty()
        || has_access_list
        || tx.authorization_list_len() != 0
    {
        return Err(InvalidTransaction::Eip8141InvalidFields.into());
    }
    if frame_tx.frames.is_empty() || frame_tx.frames.len() > MAX_FRAMES {
        return Err(invalid("EIP-8141 frame count must be in 1..=64"));
    }
    let gas_params = ctx.cfg().gas_params();
    let gas_limit = frame_tx
        .gas_limit_with_params(gas_params)
        .ok_or_else(|| invalid::<H::Error>("EIP-8141 derived gas limit overflow"))?;
    if tx.gas_limit() != gas_limit {
        return Err(invalid("EIP-8141 transaction gas limit is not canonical"));
    }
    let floor = frame_tx
        .calldata_floor_gas_with_params(gas_params)
        .ok_or_else(|| invalid::<H::Error>("EIP-8141 calldata floor overflow"))?;
    if floor > gas_limit {
        return Err(InvalidTransaction::GasFloorMoreThanGasLimit {
            gas_floor: floor,
            gas_limit,
        }
        .into());
    }
    if gas_limit > ctx.cfg().tx_gas_limit_cap() {
        return Err(InvalidTransaction::TxGasLimitGreaterThanCap {
            gas_limit,
            cap: ctx.cfg().tx_gas_limit_cap(),
        }
        .into());
    }
    if frame_tx
        .frames
        .iter()
        .any(|frame| frame.flags & !(APPROVE_SCOPE_MASK | 0x04) != 0)
    {
        return Err(invalid("EIP-8141 reserved frame flag is set"));
    }
    let mut expiry_frames = 0usize;
    for (index, frame) in frame_tx.frames.iter().enumerate() {
        if !frame.has_valid_target_encoding() {
            return Err(invalid("EIP-8141 frame target must be empty or 20 bytes"));
        }
        if frame.mode != FrameMode::Sender && !frame.value.is_zero() {
            return Err(invalid("only EIP-8141 SENDER frames may transfer value"));
        }
        let target = frame
            .target_address()
            .or_else(|| frame.target.is_empty().then_some(tx.caller()));
        if frame.allowed_scope() & 0x02 != 0 && target != Some(tx.caller()) {
            return Err(invalid(
                "EIP-8141 execution approval target must be the sender",
            ));
        }
        if frame.is_atomic_batch() && frame.mode == FrameMode::Verify {
            return Err(invalid("EIP-8141 atomic flag is invalid on VERIFY frames"));
        }
        if frame.is_atomic_batch()
            && (index + 1 == frame_tx.frames.len()
                || frame_tx.frames[index + 1].mode == FrameMode::Verify)
        {
            return Err(invalid(
                "EIP-8141 atomic batch must be followed by a non-VERIFY frame",
            ));
        }
        if frame.is_expiry_verifier() {
            if index != 0 {
                return Err(invalid("EIP-8141 expiry verifier must be the first frame"));
            }
            expiry_frames += 1;
            if !frame.has_valid_expiry_verifier_fields() {
                return Err(invalid("malformed EIP-8141 expiry verifier frame"));
            }
        }
    }
    if expiry_frames > 1 {
        return Err(invalid("multiple EIP-8141 expiry verifier frames"));
    }
    for signature in &frame_tx.signatures {
        match signature.scheme {
            SignatureScheme::Arbitrary if !signature.signer.is_empty() => {
                return Err(invalid("EIP-8141 arbitrary signature signer must be empty"));
            }
            SignatureScheme::Secp256k1 | SignatureScheme::P256
                if !signature.signer.is_empty() && signature.signer.len() != 20 =>
            {
                return Err(invalid(
                    "EIP-8141 protocol signature signer must be empty or 20 bytes",
                ));
            }
            _ => {}
        }
        if !signature.msg.is_empty() && signature.msg.len() != 32 {
            return Err(invalid(
                "EIP-8141 signature message must be empty or 32 bytes",
            ));
        }
        if signature.msg.len() == 32 && signature.msg.iter().all(|byte| *byte == 0) {
            return Err(invalid(
                "EIP-8141 explicit signature message cannot be zero",
            ));
        }
    }
    tracing::info!(
        target: "revm::eip8141",
        sender = ?tx.caller(),
        frame_count = frame_tx.frames.len(),
        signature_count = frame_tx.signatures.len(),
        gas_limit,
        calldata_floor_gas = floor,
        "Validated EIP-8141 transaction structure"
    );
    Ok(())
}

fn validate_sender_and_signatures<H: Handler + ?Sized>(evm: &mut H::Evm) -> Result<(), H::Error> {
    let (sender, nonce, nonce_check_disabled, signatures, signature_hash) = {
        let ctx = evm.ctx_ref();
        let tx = ctx.tx();
        let frame_tx = tx.frame_transaction().unwrap();
        (
            tx.caller(),
            tx.nonce(),
            ctx.cfg().is_nonce_check_disabled(),
            frame_tx.signatures.clone(),
            frame_tx.signature_hash,
        )
    };
    let state_nonce = evm
        .ctx()
        .journal_mut()
        .load_account_with_code(sender)
        .map_err(H::Error::from)?
        .info
        .nonce;
    if !nonce_check_disabled {
        if nonce > state_nonce {
            return Err(InvalidTransaction::NonceTooHigh {
                tx: nonce,
                state: state_nonce,
            }
            .into());
        }
        if nonce < state_nonce {
            return Err(InvalidTransaction::NonceTooLow {
                tx: nonce,
                state: state_nonce,
            }
            .into());
        }
        if nonce == u64::MAX {
            return Err(InvalidTransaction::NonceOverflowInTransaction.into());
        }
    }

    for signature in &signatures {
        let message = if signature.msg.is_empty() {
            signature_hash.0
        } else {
            let mut message = [0u8; 32];
            message.copy_from_slice(&signature.msg);
            message
        };
        let expected = if signature.signer.is_empty() {
            sender
        } else if signature.scheme == SignatureScheme::Arbitrary {
            Address::ZERO
        } else {
            signature.signer_address().expect("validated signer")
        };
        let valid = match signature.scheme {
            SignatureScheme::Arbitrary => true,
            SignatureScheme::Secp256k1 => {
                if signature.signature.len() != 65 || signature.signature[0] > 1 {
                    false
                } else {
                    let r = U256::from_be_slice(&signature.signature[1..33]);
                    let s = U256::from_be_slice(&signature.signature[33..65]);
                    let curve_order = U256::from_be_bytes(hex!(
                        "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
                    ));
                    let half_curve_order = U256::from_be_bytes(hex!(
                        "7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0"
                    ));
                    if r.is_zero() || r >= curve_order || s.is_zero() || s > half_curve_order {
                        return Err(invalid("EIP-8141 signature validation failed"));
                    }
                    let mut rs = [0u8; 64];
                    rs.copy_from_slice(&signature.signature[1..]);
                    precompile::crypto()
                        .secp256k1_ecrecover(&rs, signature.signature[0], &message)
                        .map(|word| Address::from_slice(&word[12..]))
                        .ok()
                        == Some(expected)
                }
            }
            SignatureScheme::P256 => {
                if signature.signature.len() != 128 {
                    false
                } else {
                    let mut sig = [0u8; 64];
                    let mut public_key = [0u8; 64];
                    sig.copy_from_slice(&signature.signature[..64]);
                    public_key.copy_from_slice(&signature.signature[64..]);
                    let s = U256::from_be_slice(&signature.signature[32..64]);
                    let p256_order = U256::from_be_bytes(hex!(
                        "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"
                    ));
                    let p256_half_order = p256_order >> 1;
                    if s.is_zero() || s > p256_half_order {
                        false
                    } else {
                        Address::from_slice(&keccak256(public_key)[12..]) == expected
                            && precompile::crypto().secp256r1_verify_signature(
                                &message,
                                &sig,
                                &public_key,
                            )
                    }
                }
            }
        };
        if !valid {
            return Err(invalid("EIP-8141 signature validation failed"));
        }
        tracing::info!(
            target: "revm::eip8141",
            scheme = ?signature.scheme,
            signer = ?expected,
            "Validated EIP-8141 signature"
        );
    }
    tracing::info!(
        target: "revm::eip8141",
        sender = ?sender,
        nonce,
        signature_count = signatures.len(),
        "Validated EIP-8141 sender and signatures"
    );
    Ok(())
}

fn frame_input<H: Handler + ?Sized>(
    evm: &mut H::Evm,
    frame: &alloy_eip8141::Frame,
    target: Address,
) -> Result<(primitives::B256, FrameInput), H::Error> {
    let gas_params = evm.ctx_ref().cfg().gas_params();
    let warm_access_cost = gas_params.warm_storage_read_cost();
    let cold_account_additional_cost = gas_params.cold_account_additional_cost();
    let account = evm
        .ctx()
        .journal_mut()
        .load_account_with_code(target)
        .map_err(H::Error::from)?;
    let mut entry_gas = account_access_gas(
        account.is_cold,
        warm_access_cost,
        cold_account_additional_cost,
    );
    let target_code_hash = account.info.code_hash();
    let mut bytecode_address = target;
    let mut bytecode = account.info.code.clone().unwrap_or_default();
    let mut bytecode_hash = target_code_hash;
    if let Some(delegated) = bytecode.eip7702_address() {
        let delegated_account = evm
            .ctx()
            .journal_mut()
            .load_account_with_code(delegated)
            .map_err(H::Error::from)?;
        entry_gas = entry_gas.saturating_add(account_access_gas(
            delegated_account.is_cold,
            warm_access_cost,
            cold_account_additional_cost,
        ));
        bytecode_address = delegated;
        bytecode_hash = delegated_account.info.code_hash();
        bytecode = delegated_account.info.code.clone().unwrap_or_default();
    }
    if frame.mode == FrameMode::Verify && target == EXPIRY_VERIFIER {
        bytecode_address = EXPIRY_VERIFIER;
        bytecode = StateBytecode::new_legacy(Bytes::copy_from_slice(&EXPIRY_VERIFIER_RUNTIME));
        bytecode_hash = keccak256(EXPIRY_VERIFIER_RUNTIME);
    }
    let sender = evm.ctx_ref().tx().caller();
    let caller = if frame.mode == FrameMode::Sender {
        sender
    } else {
        ENTRY_POINT
    };
    Ok((
        target_code_hash,
        FrameInput::Call(Box::new(CallInputs {
            input: CallInput::Bytes(frame.data.clone()),
            gas_limit: frame.gas_limit,
            target_address: target,
            bytecode_address,
            known_bytecode: (bytecode_hash, bytecode),
            caller,
            value: if frame.mode == FrameMode::Verify {
                CallValue::Apparent(U256::ZERO)
            } else {
                CallValue::Transfer(frame.value)
            },
            scheme: if frame.mode == FrameMode::Verify {
                CallScheme::StaticCall
            } else {
                CallScheme::Call
            },
            is_static: frame.mode == FrameMode::Verify,
            return_memory_offset: 0..0,
            reservoir: 0,
            entry_gas,
            charged_new_account_state_gas: false,
        })),
    ))
}

#[inline]
fn account_access_gas(
    is_cold: bool,
    warm_access_cost: u64,
    cold_account_additional_cost: u64,
) -> u64 {
    if is_cold {
        warm_access_cost.saturating_add(cold_account_additional_cost)
    } else {
        warm_access_cost
    }
}

fn default_verification_is_valid<H: Handler + ?Sized>(
    evm: &H::Evm,
    target: Address,
    scope: u8,
) -> bool {
    let tx = evm.ctx_ref().tx();
    let frame_tx = tx.frame_transaction().unwrap();
    let signature_index = if scope & 0x02 != 0 { 0 } else { 1 };
    let Some(signature) = frame_tx.signatures.get(signature_index) else {
        return false;
    };
    signature.scheme == SignatureScheme::Secp256k1
        && signature.msg.is_empty()
        && scope != 0
        && (signature.signer.is_empty() && tx.caller() == target
            || signature.signer_address() == Some(target))
}

fn settle_fees<H: Handler + ?Sized>(
    evm: &mut H::Evm,
    payer: Address,
    gas_used: u64,
) -> Result<(), H::Error> {
    if evm.ctx_ref().cfg().is_fee_charge_disabled() {
        return Ok(());
    }
    let (max_cost, actual_cost, beneficiary, beneficiary_reward) = {
        let ctx = evm.ctx_ref();
        let tx = ctx.tx();
        let frame_tx = tx.frame_transaction().unwrap();
        let blob_gas = tx.total_blob_gas();
        let max_cost = frame_tx.max_cost(
            tx.max_fee_per_gas(),
            blob_gas,
            ctx.block().blob_gasprice().unwrap_or_default(),
        );
        let effective_gas_price = tx.effective_gas_price(ctx.block().basefee() as u128);
        let actual_cost = U256::from(gas_used)
            .saturating_mul(U256::from(effective_gas_price))
            .saturating_add(
                U256::from(blob_gas)
                    .saturating_mul(U256::from(ctx.block().blob_gasprice().unwrap_or_default())),
            );
        let priority_price = effective_gas_price.saturating_sub(ctx.block().basefee() as u128);
        (
            max_cost,
            actual_cost,
            ctx.block().beneficiary(),
            U256::from(gas_used).saturating_mul(U256::from(priority_price)),
        )
    };
    evm.ctx()
        .journal_mut()
        .load_account_mut(payer)
        .map_err(H::Error::from)?
        .incr_balance(max_cost.saturating_sub(actual_cost));
    evm.ctx()
        .journal_mut()
        .load_account_mut(beneficiary)
        .map_err(H::Error::from)?
        .incr_balance(beneficiary_reward);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ExecuteEvm, MainBuilder, MainContext};
    use alloy_eip8141::{Frame, FrameSignature};
    use alloy_signer::{Signature, SignerSync};
    use alloy_signer_local::PrivateKeySigner;
    use bytecode::opcode::{APPROVE, PUSH0, PUSH1, REVERT, SSTORE, STOP};
    use context::{result::EVMError, transaction::FrameTransaction, Context, TxEnv};
    use database::{CacheDB, EmptyDB};
    use primitives::{address, hardfork::SpecId, TxKind, B256};
    use state::{AccountInfo, Bytecode};

    const SENDER: Address = address!("1000000000000000000000000000000000000001");
    const STORAGE_TARGET: Address = address!("2000000000000000000000000000000000000002");
    const REVERT_TARGET: Address = address!("3000000000000000000000000000000000000003");

    fn encoded_target(target: Address) -> Bytes {
        Bytes::copy_from_slice(target.as_slice())
    }

    fn account_with_code(code: impl Into<Bytes>) -> AccountInfo {
        AccountInfo::default().with_code(Bytecode::new_legacy(code.into()))
    }

    fn tx_env(caller: Address, frame_transaction: FrameTransaction) -> TxEnv {
        let gas_limit = frame_transaction.gas_limit().unwrap();
        TxEnv::builder()
            .tx_type(Some(0x06))
            .caller(caller)
            .kind(TxKind::Call(caller))
            .gas_limit(gas_limit)
            .gas_priority_fee(Some(0))
            .frame_transaction(frame_transaction)
            .build()
            .unwrap()
    }

    fn signature_bytes(signature: &Signature) -> Bytes {
        let mut bytes = Vec::with_capacity(65);
        bytes.push(u8::from(signature.v()));
        bytes.extend_from_slice(&signature.r().to_be_bytes::<32>());
        bytes.extend_from_slice(&signature.s().to_be_bytes::<32>());
        bytes.into()
    }

    fn signed_entry(
        signer: &PrivateKeySigner,
        signer_field: Bytes,
        message: B256,
    ) -> FrameSignature {
        let signature = signer.sign_hash_sync(&message).unwrap();
        FrameSignature {
            scheme: SignatureScheme::Secp256k1,
            signer: signer_field,
            msg: Bytes::new(),
            signature: signature_bytes(&signature),
        }
    }

    #[test]
    fn approve_opcode_sets_payer_and_bumps_sender_nonce() {
        // APPROVE expects offset, length, scope from the top of the stack.
        let approve_code = [PUSH1, 0x03, PUSH0, PUSH0, APPROVE];
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(SENDER, account_with_code(approve_code));

        let payload = FrameTransaction {
            frames: vec![Frame {
                mode: FrameMode::Default,
                flags: 0x03,
                target: Bytes::new(),
                gas_limit: 10_000,
                value: U256::ZERO,
                data: Bytes::new(),
            }],
            signatures: Vec::new(),
            signature_hash: B256::ZERO,
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(SENDER, payload)).unwrap();
        let ExecutionResult::FrameTransaction {
            payer,
            frame_receipts,
            ..
        } = output.result
        else {
            panic!("expected frame transaction result")
        };
        assert_eq!(payer, SENDER);
        assert_eq!(frame_receipts.len(), 1);
        assert_eq!(frame_receipts[0].status, FrameStatus::Success);
        assert_eq!(output.state[&SENDER].info.nonce, 1);
    }

    #[test]
    fn default_code_uses_second_signature_for_payment_only_approval() {
        let sender = PrivateKeySigner::random();
        let sponsor = PrivateKeySigner::random();
        let signature_hash = keccak256("frame transaction default verification");
        let signatures = vec![
            signed_entry(&sender, Bytes::new(), signature_hash),
            signed_entry(&sponsor, encoded_target(sponsor.address()), signature_hash),
        ];
        let frames = vec![
            Frame {
                mode: FrameMode::Verify,
                flags: 0x02,
                target: Bytes::new(),
                gas_limit: 2_000,
                value: U256::ZERO,
                data: Bytes::new(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x01,
                target: encoded_target(sponsor.address()),
                gas_limit: 2_000,
                value: U256::ZERO,
                data: Bytes::new(),
            },
        ];
        let payload = FrameTransaction {
            frames,
            signatures,
            signature_hash,
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(CacheDB::<EmptyDB>::default())
            .build_mainnet();

        let output = evm.transact(tx_env(sender.address(), payload)).unwrap();
        let ExecutionResult::FrameTransaction {
            payer,
            frame_receipts,
            ..
        } = output.result
        else {
            panic!("expected frame transaction result")
        };
        assert_eq!(payer, sponsor.address());
        assert!(frame_receipts
            .iter()
            .all(|receipt| receipt.status == FrameStatus::Success));
        assert_eq!(output.state[&sender.address()].info.nonce, 1);
    }

    #[test]
    fn failed_atomic_batch_rolls_back_state_and_skips_remaining_frames() {
        let approve_code = [PUSH1, 0x03, PUSH0, PUSH0, APPROVE];
        let store_code = [PUSH1, 0x02, PUSH0, SSTORE, STOP];
        let revert_code = [PUSH0, PUSH0, REVERT];
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(SENDER, account_with_code(approve_code));
        db.insert_account_info(STORAGE_TARGET, account_with_code(store_code));
        db.insert_account_storage(STORAGE_TARGET, U256::ZERO, U256::from(1))
            .unwrap();
        db.insert_account_info(REVERT_TARGET, account_with_code(revert_code));

        let payload = FrameTransaction {
            frames: vec![
                Frame::new(
                    FrameMode::Default,
                    0x03,
                    Bytes::new(),
                    10_000,
                    U256::ZERO,
                    Bytes::new(),
                ),
                Frame::new(
                    FrameMode::Default,
                    0x04,
                    encoded_target(STORAGE_TARGET),
                    100_000,
                    U256::ZERO,
                    Bytes::new(),
                ),
                Frame::new(
                    FrameMode::Default,
                    0x04,
                    encoded_target(REVERT_TARGET),
                    10_000,
                    U256::ZERO,
                    Bytes::new(),
                ),
                Frame::new(
                    FrameMode::Default,
                    0,
                    encoded_target(STORAGE_TARGET),
                    100_000,
                    U256::ZERO,
                    Bytes::new(),
                ),
            ],
            signatures: Vec::new(),
            signature_hash: B256::ZERO,
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(SENDER, payload)).unwrap();
        let ExecutionResult::FrameTransaction { frame_receipts, .. } = output.result else {
            panic!("expected frame transaction result")
        };
        assert_eq!(
            frame_receipts
                .iter()
                .map(|receipt| receipt.status)
                .collect::<Vec<_>>(),
            vec![
                FrameStatus::Success,
                FrameStatus::Failure,
                FrameStatus::Failure,
                FrameStatus::SkippedAtomicBatch,
            ]
        );
        assert!(frame_receipts[1].gas_used > 0);
        assert_eq!(frame_receipts[3].gas_used, 0);
        let stored = output
            .state
            .get(&STORAGE_TARGET)
            .and_then(|account| account.storage.get(&U256::ZERO))
            .map(|slot| slot.present_value)
            .unwrap_or_default();
        assert_eq!(stored, U256::from(1));
    }

    #[test]
    fn max_blob_fee_without_blobs_has_frame_transaction_error() {
        let payload = FrameTransaction {
            frames: vec![Frame {
                gas_limit: 1,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut tx = tx_env(SENDER, payload);
        tx.max_fee_per_blob_gas = 1;
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(CacheDB::<EmptyDB>::default())
            .build_mainnet();

        assert!(matches!(
            evm.transact(tx),
            Err(EVMError::Transaction(
                InvalidTransaction::Eip8141InvalidFields
            ))
        ));
    }
}
