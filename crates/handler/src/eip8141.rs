//! EIP-8141 frame transaction validation and execution.

use crate::{EvmTr, Handler};
use alloy_eip8141::{
    FrameGasUsed, FrameMode, FrameReceipt, FrameStatus, SignatureScheme, ENTRY_POINT,
    EXPIRY_VERIFIER, EXPIRY_VERIFIER_RUNTIME, FRAME_FLAGS_MASK, MAX_FRAMES, SECP256K1N, SECP256R1N,
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
use primitives::{keccak256, Address, Bytes, KECCAK_EMPTY, U256};
use state::Bytecode as StateBytecode;
use std::{boxed::Box, vec::Vec};

struct AtomicBatch {
    checkpoint: context_interface::journaled_state::JournalCheckpoint,
    approval: FrameApprovalState,
    warm_accesses: WarmAccessSnapshot,
    state_gas_checkpoint: usize,
    receipt_start: usize,
}

fn invalid<ERROR: From<InvalidTransaction>>(message: &'static str) -> ERROR {
    InvalidTransaction::Str(message.into()).into()
}

/// Executes an EIP-8141 transaction through the mainnet handler's frame loop.
/// The outer orchestration handles approvals, frame-local budgets, and atomic
/// batches; bytecode execution uses the same interpreter loop as ordinary calls.
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
    validate_signatures::<H>(evm)?;
    validate_sender::<H>(evm)?;
    handler.load_accounts(evm)?;

    let sender = evm.ctx_ref().tx().caller();
    // EIP-8141 starts with the sender warm. The protocol entry point is not
    // pre-warmed and must only be recorded if execution actually accesses it.
    evm.ctx()
        .journal_mut()
        .load_account(sender)
        .map_err(H::Error::from)?;

    let (intrinsic, floor_gas, frame_count) = {
        let frame_tx = evm
            .ctx_ref()
            .tx()
            .frame_transaction()
            .expect("validated frame tx");
        let gas_params = evm.ctx_ref().cfg().gas_params();
        let sender = evm.ctx_ref().tx().caller();
        (
            frame_tx
                .intrinsic_gas_with_params(sender, gas_params)
                .expect("validated gas"),
            frame_tx
                .calldata_floor_gas_with_params(sender, gas_params)
                .expect("validated gas"),
            frame_tx.frames.len(),
        )
    };
    evm.ctx()
        .local_mut()
        .set_frame_transaction(Some(FrameTransactionRuntime::with_capacity(
            sender,
            frame_count,
        )));
    let (receipts, frame_refunds) = execute_frames(handler, evm, frame_count)?;
    finish_transaction::<H>(evm, intrinsic, floor_gas, receipts, frame_refunds)
}

/// Runs the ordered top-level frames and applies atomic batch boundaries.
fn execute_frames<H: Handler + ?Sized>(
    handler: &mut H,
    evm: &mut H::Evm,
    frame_count: usize,
) -> Result<(Vec<FrameReceipt>, Vec<u64>), H::Error> {
    let mut receipts = Vec::with_capacity(frame_count);
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

        if batch.is_none() && frame.is_atomic_batch() {
            let checkpoint = evm.ctx().journal_mut().checkpoint();
            let runtime = evm.ctx_ref().local().frame_transaction().unwrap();
            batch = Some(AtomicBatch {
                checkpoint,
                approval: runtime.approval,
                warm_accesses: evm.ctx_ref().journal().warm_access_snapshot(),
                state_gas_checkpoint: runtime.state_gas_checkpoint(),
                receipt_start: receipts.len(),
            });
        }
        {
            let runtime = evm.ctx().local_mut().frame_transaction_mut().unwrap();
            runtime.current_frame_index = frame_index;
            runtime.resolved_target = target;
            runtime.root_approval = None;
            runtime.approval_stack.clear();
            debug_assert_eq!(runtime.state_gas_used.len(), frame_index);
            runtime.state_gas_used.push(0);
        }

        let frame_checkpoint = evm.ctx().journal_mut().checkpoint();
        let log_start = evm.ctx_ref().journal().logs().len();
        let entry_gas = {
            let gas_params = evm.ctx_ref().cfg().gas_params();
            account_access_gas(
                evm.ctx_ref().journal().is_account_cold(target),
                gas_params.warm_storage_read_cost(),
                gas_params.cold_account_additional_cost(),
            )
        };

        let (result, spent, state_gas, refund) =
            execute_frame(handler, evm, &frame, target, entry_gas)?;

        take_error::<H::Error, _>(evm.ctx().error())?;
        let success = result.is_ok();
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
            gas_used: FrameGasUsed {
                execution: spent,
                state: state_gas,
            },
            logs,
        });
        frame_refunds.push(refund);
        {
            let runtime = evm.ctx().local_mut().frame_transaction_mut().unwrap();
            runtime.statuses.push(status);
            runtime.execution_gas_used.push(spent);
            runtime.state_gas_used[frame_index] = state_gas;
        }

        if !success {
            if let Some(atomic) = batch.take() {
                evm.ctx().journal_mut().checkpoint_revert(atomic.checkpoint);
                evm.ctx()
                    .journal_mut()
                    .restore_warm_access_snapshot(&atomic.warm_accesses);
                let runtime = evm.ctx().local_mut().frame_transaction_mut().unwrap();
                runtime.approval = atomic.approval;
                runtime.root_approval = None;
                runtime.approval_stack.clear();
                runtime.revert_state_gas(atomic.state_gas_checkpoint);
                // The failing frame keeps its own gas accounting. Earlier frames remain
                // successful in the receipt, but their rolled-back state changes no longer earn
                // state-gas credit or retain logs.
                for index in atomic.receipt_start..receipts.len() - 1 {
                    receipts[index].logs.clear();
                    receipts[index].gas_used.state = 0;
                    frame_refunds[index] = 0;
                    runtime.state_gas_used[index] = 0;
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
                        gas_used: FrameGasUsed {
                            execution: 0,
                            state: 0,
                        },
                        logs: Vec::new(),
                    });
                    frame_refunds.push(0);
                    let runtime = evm.ctx().local_mut().frame_transaction_mut().unwrap();
                    runtime.statuses.push(FrameStatus::SkippedAtomicBatch);
                    runtime.execution_gas_used.push(0);
                    runtime.state_gas_used.push(0);
                }
                frame_index = end + 1;
                continue;
            }
        } else if !frame.is_atomic_batch() && batch.take().is_some() {
            evm.ctx().journal_mut().checkpoint_commit();
        }
        frame_index += 1;
    }

    Ok((receipts, frame_refunds))
}

/// Executes one top-level frame through default verification or the shared interpreter loop.
fn execute_frame<H: Handler + ?Sized>(
    handler: &mut H,
    evm: &mut H::Evm,
    frame: &alloy_eip8141::Frame,
    target: Address,
    entry_gas: u64,
) -> Result<(InstructionResult, u64, u64, u64), H::Error> {
    // The frame target is only accessed after the entry charge succeeds. In
    // particular, an underfunded cold access must not load the target or add it
    // to the EIP-7928 block access list.
    Ok(if frame.limits.execution < entry_gas {
        (InstructionResult::OutOfGas, frame.limits.execution, 0, 0)
    } else {
        let (target_code_hash, frame_input, loaded_entry_gas) =
            frame_input::<H>(evm, frame, target)?;
        debug_assert_eq!(entry_gas, loaded_entry_gas);
        let uses_default_code = frame.mode == FrameMode::Verify
            && target_code_hash == KECCAK_EMPTY
            && !evm
                .ctx_ref()
                .journal()
                .precompile_addresses()
                .contains(&target)
            && target != EXPIRY_VERIFIER;

        if uses_default_code {
            let mut gas = interpreter::Gas::new_with_regular_gas_and_isolated_state_gas(
                frame.limits.execution,
                frame.limits.state,
            );
            let entry_gas_sufficient = gas.record_regular_cost(entry_gas);
            if !entry_gas_sufficient {
                gas.spend_all();
            }
            let valid = entry_gas_sufficient
                && default_verification_is_valid::<H>(evm, target, frame.allowed_scope());
            evm.ctx()
                .local_mut()
                .frame_transaction_mut()
                .unwrap()
                .enter_scope();
            let approval_result = if valid {
                evm.ctx().approve_frame_with_state_gas(
                    target,
                    U256::from(frame.allowed_scope()),
                    gas.reservoir(),
                )
            } else if entry_gas_sufficient {
                Err(context_interface::host::FrameHostError::Revert)
            } else {
                Err(context_interface::host::FrameHostError::OutOfGas)
            };
            let result = match approval_result {
                Ok(state_gas) if gas.record_state_cost(state_gas) => InstructionResult::Return,
                Ok(_) | Err(context_interface::host::FrameHostError::OutOfGas) => {
                    gas.spend_all();
                    InstructionResult::OutOfGas
                }
                Err(context_interface::host::FrameHostError::Revert) => InstructionResult::Revert,
                Err(context_interface::host::FrameHostError::Invalid) => {
                    InstructionResult::OpcodeNotFound
                }
                Err(context_interface::host::FrameHostError::Fatal) => {
                    InstructionResult::FatalExternalError
                }
            };
            let success = result.is_ok();
            evm.ctx()
                .local_mut()
                .frame_transaction_mut()
                .unwrap()
                .exit_scope(success);
            (
                result,
                frame.limits.execution.saturating_sub(gas.remaining()),
                if success {
                    frame.limits.state.saturating_sub(gas.reservoir())
                } else {
                    0
                },
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
            // Frame execution and state gas are independent budgets. The
            // state budget must not be subtracted from execution gas used.
            let spent = frame.limits.execution.saturating_sub(gas.remaining());
            let state_gas = if result.is_ok() {
                frame.limits.state.saturating_sub(gas.reservoir())
            } else {
                0
            };
            let refund = if result.is_ok() {
                gas.refunded().max(0) as u64
            } else {
                0
            };
            (result, spent, state_gas, refund)
        }
    })
}

/// Settles the final per-frame gas accounting and transaction fees.
fn finish_transaction<H: Handler + ?Sized>(
    evm: &mut H::Evm,
    intrinsic: u64,
    floor_gas: u64,
    mut receipts: Vec<FrameReceipt>,
    frame_refunds: Vec<u64>,
) -> Result<ExecutionResult<H::HaltReason>, H::Error> {
    let payer = evm
        .ctx_ref()
        .local()
        .frame_transaction()
        .unwrap()
        .approval
        .payer
        .ok_or_else(|| invalid::<H::Error>("EIP-8141 transaction did not approve a payer"))?;
    let total_frame_spent = receipts.iter().fold(0u64, |total, receipt| {
        total.saturating_add(receipt.gas_used.execution)
    });
    let final_frame_state_gas = &evm
        .ctx_ref()
        .local()
        .frame_transaction()
        .unwrap()
        .state_gas_used;
    for (receipt, state_gas) in receipts.iter_mut().zip(final_frame_state_gas) {
        receipt.gas_used.state = *state_gas;
    }
    let total_state_gas = final_frame_state_gas
        .iter()
        .copied()
        .fold(0u64, u64::saturating_add);
    // Receipts and fee settlement use the combined execution + state gas. The
    // block adapter derives the regular/state dimensions separately from this
    // value and uses their bottleneck for the block header gas_used.
    let total_spent = intrinsic
        .saturating_add(total_frame_spent)
        .saturating_add(total_state_gas);
    let refund_counter = frame_refunds.into_iter().fold(0u64, u64::saturating_add);
    let refund =
        refund_counter.min(total_spent / evm.ctx_ref().cfg().gas_params().max_refund_quotient());
    let result_gas = ResultGas::default()
        .with_total_gas_spent(total_spent)
        .with_refunded(refund)
        .with_floor_gas(floor_gas)
        .with_state_gas_spent(total_state_gas);
    settle_fees::<H>(evm, payer, result_gas.frame_tx_gas_used())?;
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
    let sender = tx.caller();
    let gas_limit = frame_tx
        .gas_limit_with_params(sender, gas_params)
        .ok_or_else(|| invalid::<H::Error>("EIP-8141 derived gas limit overflow"))?;
    if tx.gas_limit() != gas_limit {
        return Err(invalid("EIP-8141 transaction gas limit is not canonical"));
    }
    let floor = frame_tx
        .calldata_floor_gas_with_params(sender, gas_params)
        .ok_or_else(|| invalid::<H::Error>("EIP-8141 calldata floor overflow"))?;
    if floor > gas_limit {
        return Err(InvalidTransaction::GasFloorMoreThanGasLimit {
            gas_floor: floor,
            gas_limit,
        }
        .into());
    }
    let execution_reservation = frame_tx
        .intrinsic_gas_with_params(sender, gas_params)
        .and_then(|intrinsic| intrinsic.checked_add(frame_tx.total_frame_execution_gas_limit()?))
        .ok_or_else(|| invalid::<H::Error>("EIP-8141 execution gas reservation overflow"))?
        .max(floor);
    if execution_reservation > ctx.cfg().tx_gas_limit_cap() {
        return Err(InvalidTransaction::TxGasLimitGreaterThanCap {
            gas_limit: execution_reservation,
            cap: ctx.cfg().tx_gas_limit_cap(),
        }
        .into());
    }
    let blob_cost = U256::from(tx.total_blob_gas())
        .checked_mul(U256::from(ctx.block().blob_gasprice().unwrap_or_default()))
        .ok_or(InvalidTransaction::OverflowPaymentInTransaction)?;
    if U256::from(gas_limit)
        .checked_mul(frame_tx.max_fee_per_gas)
        .and_then(|execution_cost| execution_cost.checked_add(blob_cost))
        .is_none()
    {
        return Err(InvalidTransaction::OverflowPaymentInTransaction.into());
    }
    if frame_tx
        .frames
        .iter()
        .any(|frame| frame.flags & !FRAME_FLAGS_MASK != 0)
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
        if (frame.is_atomic_batch() || (index > 0 && frame_tx.frames[index - 1].is_atomic_batch()))
            && frame.allowed_scope() != 0
        {
            return Err(invalid(
                "EIP-8141 atomic batch frames cannot carry approval scope",
            ));
        }
        if frame.is_expiry_verifier() {
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
    Ok(())
}

fn validate_signatures<H: Handler + ?Sized>(evm: &H::Evm) -> Result<(), H::Error> {
    let tx = evm.ctx_ref().tx();
    let sender = tx.caller();
    let frame_tx = tx.frame_transaction().expect("validated frame tx");
    let signature_hash = frame_tx.signature_hash;
    for signature in &frame_tx.signatures {
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
                    let half_curve_order = SECP256K1N >> 1;
                    if r.is_zero() || r >= SECP256K1N || s.is_zero() || s > half_curve_order {
                        return Err(invalid("EIP-8141 signature validation failed"));
                    }
                    let mut rs = [0u8; 64];
                    rs.copy_from_slice(&signature.signature[1..]);
                    let recovered = precompile::crypto()
                        .secp256k1_ecrecover(&rs, signature.signature[0], &message)
                        .map(|word| Address::from_slice(&word[12..]))
                        .ok();
                    if recovered.is_some() && recovered != Some(expected) {
                        return Err(invalid("EIP-8141 signature signer does not match"));
                    }
                    recovered == Some(expected)
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
                    let r = U256::from_be_slice(&signature.signature[..32]);
                    let s = U256::from_be_slice(&signature.signature[32..64]);
                    let p256_half_order = SECP256R1N >> 1;
                    if r.is_zero() || r >= SECP256R1N || s.is_zero() || s > p256_half_order {
                        return Err(invalid("EIP-8141 signature validation failed"));
                    }
                    let recovered = Address::from_slice(&keccak256(public_key)[12..]);
                    if recovered != expected {
                        return Err(invalid("EIP-8141 signature signer does not match"));
                    }
                    precompile::crypto().secp256r1_verify_signature(&message, &sig, &public_key)
                }
            }
        };
        if !valid {
            return Err(invalid("EIP-8141 signature validation failed"));
        }
    }

    Ok(())
}

fn validate_sender<H: Handler + ?Sized>(evm: &mut H::Evm) -> Result<(), H::Error> {
    let sender = evm.ctx_ref().tx().caller();
    let nonce = evm.ctx_ref().tx().nonce();
    let nonce_check_disabled = evm.ctx_ref().cfg().is_nonce_check_disabled();
    // EIP-8141 static validation, including every signature, precedes the
    // sender-state lookup. Invalid transactions may legitimately omit the
    // sender from an attached block access list, so loading it first can
    // incorrectly turn a transaction error into a BAL database error.
    if !nonce_check_disabled {
        let state_nonce = evm
            .ctx()
            .journal_mut()
            .load_account_with_code(sender)
            .map_err(H::Error::from)?
            .info
            .nonce;
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

    Ok(())
}

fn frame_input<H: Handler + ?Sized>(
    evm: &mut H::Evm,
    frame: &alloy_eip8141::Frame,
    target: Address,
) -> Result<(primitives::B256, FrameInput, u64), H::Error> {
    let gas_params = evm.ctx_ref().cfg().gas_params();
    let warm_access_cost = gas_params.warm_storage_read_cost();
    let cold_account_additional_cost = gas_params.cold_account_additional_cost();
    let new_account_state_gas = gas_params.new_account_state_gas();
    let account = evm
        .ctx()
        .journal_mut()
        .load_account_with_code(target)
        .map_err(H::Error::from)?;
    let entry_gas = account_access_gas(
        account.is_cold,
        warm_access_cost,
        cold_account_additional_cost,
    );
    let entry_state_gas =
        if frame.mode == FrameMode::Sender && !frame.value.is_zero() && account.info.is_empty() {
            new_account_state_gas
        } else {
            0
        };
    let target_code_hash = account.info.code_hash();
    let mut bytecode_address = target;
    let mut bytecode = account.info.code.clone().unwrap_or_default();
    let mut bytecode_hash = target_code_hash;
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
            gas_limit: frame.limits.execution,
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
            reservoir: frame.limits.state,
            state_gas_isolated: true,
            entry_gas,
            entry_state_gas,
            charged_new_account_state_gas: entry_state_gas != 0,
        })),
        entry_gas,
    ))
}

#[inline]
const fn account_access_gas(
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
        let max_cost = frame_tx.max_cost_with_params(
            tx.caller(),
            ctx.cfg().gas_params(),
            blob_gas,
            ctx.block().blob_gasprice().unwrap_or_default(),
        );
        let effective_gas_price = frame_tx.effective_gas_price(ctx.block().basefee() as u128);
        let actual_cost = U256::from(gas_used)
            .saturating_mul(effective_gas_price)
            .saturating_add(
                U256::from(blob_gas)
                    .saturating_mul(U256::from(ctx.block().blob_gasprice().unwrap_or_default())),
            );
        let priority_price = effective_gas_price.saturating_sub(U256::from(ctx.block().basefee()));
        (
            max_cost,
            actual_cost,
            ctx.block().beneficiary(),
            U256::from(gas_used).saturating_mul(priority_price),
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
    use alloy_eip8141::{Frame, FrameLimits, FrameSignature};
    use alloy_signer::{Signature, SignerSync};
    use alloy_signer_local::PrivateKeySigner;
    use bytecode::opcode::{
        APPROVE, CALLDATALOAD, FRAMEDATACOPY, PUSH0, PUSH1, REVERT, SIGDATACOPY, SSTORE, STOP,
    };
    use context::{result::EVMError, transaction::FrameTransaction, Context, TxEnv};
    use database::{CacheDB, EmptyDB};
    use primitives::{address, eip7825, eip8037, hardfork::SpecId, TxKind, B256};
    use state::{AccountInfo, Bytecode};

    const SENDER: Address = address!("1000000000000000000000000000000000000001");
    const STORAGE_TARGET: Address = address!("2000000000000000000000000000000000000002");
    const REVERT_TARGET: Address = address!("3000000000000000000000000000000000000003");
    const VALUE_TARGET: Address = address!("4000000000000000000000000000000000000004");
    const ECRECOVER: Address = address!("0000000000000000000000000000000000000001");

    const NEW_ACCOUNT_STATE_GAS: u64 = eip8037::NEW_ACCOUNT_BYTES * eip8037::CPSB_GLAMSTERDAM;
    const NEW_SLOT_STATE_GAS: u64 = eip8037::SSTORE_SET_BYTES * eip8037::CPSB_GLAMSTERDAM;

    fn encoded_target(target: Address) -> Bytes {
        Bytes::copy_from_slice(target.as_slice())
    }

    fn account_with_code(code: impl Into<Bytes>) -> AccountInfo {
        AccountInfo::default().with_code(Bytecode::new_legacy(code.into()))
    }

    fn tx_env(caller: Address, frame_transaction: FrameTransaction) -> TxEnv {
        let gas_limit = frame_transaction.gas_limit(caller).unwrap();
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
                limits: FrameLimits {
                    execution: 10_000,
                    state: 0,
                },
                value: U256::ZERO,
                data: Bytes::new(),
            }],
            signatures: Vec::new(),
            signature_hash: B256::ZERO,
            ..Default::default()
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
                limits: FrameLimits {
                    execution: 2_000,
                    state: 0,
                },
                value: U256::ZERO,
                data: Bytes::new(),
            },
            Frame {
                mode: FrameMode::Verify,
                flags: 0x01,
                target: encoded_target(sponsor.address()),
                limits: FrameLimits {
                    execution: 3_000,
                    state: NEW_ACCOUNT_STATE_GAS,
                },
                value: U256::ZERO,
                data: Bytes::new(),
            },
        ];
        let payload = FrameTransaction {
            frames,
            signatures,
            signature_hash,
            ..Default::default()
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
    fn default_code_halts_when_target_access_exceeds_execution_limit() {
        let sender = PrivateKeySigner::random();
        let signature_hash = keccak256("frame transaction default entry gas");
        let payload = FrameTransaction {
            frames: vec![Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Bytes::new(),
                limits: FrameLimits {
                    execution: 99,
                    state: NEW_ACCOUNT_STATE_GAS,
                },
                value: U256::ZERO,
                data: Bytes::new(),
            }],
            signatures: vec![signed_entry(&sender, Bytes::new(), signature_hash)],
            signature_hash,
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(CacheDB::<EmptyDB>::default())
            .build_mainnet();

        assert!(matches!(
            evm.transact(tx_env(sender.address(), payload)),
            Err(EVMError::Transaction(InvalidTransaction::Str(_)))
        ));
    }

    #[test]
    fn payment_approval_halts_when_new_sender_state_gas_is_insufficient() {
        let sender = PrivateKeySigner::random();
        let signature_hash = keccak256("frame transaction approval state gas");
        let payload = FrameTransaction {
            frames: vec![Frame {
                mode: FrameMode::Verify,
                flags: 0x03,
                target: Bytes::new(),
                limits: FrameLimits {
                    execution: 100,
                    state: NEW_ACCOUNT_STATE_GAS - 1,
                },
                value: U256::ZERO,
                data: Bytes::new(),
            }],
            signatures: vec![signed_entry(&sender, Bytes::new(), signature_hash)],
            signature_hash,
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(CacheDB::<EmptyDB>::default())
            .build_mainnet();

        assert!(matches!(
            evm.transact(tx_env(sender.address(), payload)),
            Err(EVMError::Transaction(InvalidTransaction::Str(_)))
        ));
    }

    #[test]
    fn value_frame_charges_new_account_state_gas_once() {
        let approve_code = [PUSH1, 0x03, PUSH0, PUSH0, APPROVE];
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(
            SENDER,
            account_with_code(approve_code).with_balance(U256::from(1)),
        );
        let payload = FrameTransaction {
            frames: vec![
                Frame {
                    mode: FrameMode::Default,
                    flags: 0x03,
                    target: Bytes::new(),
                    limits: FrameLimits {
                        execution: 10_000,
                        state: 0,
                    },
                    value: U256::ZERO,
                    data: Bytes::new(),
                },
                Frame {
                    mode: FrameMode::Sender,
                    flags: 0,
                    target: encoded_target(VALUE_TARGET),
                    limits: FrameLimits {
                        execution: 3_000,
                        state: NEW_ACCOUNT_STATE_GAS,
                    },
                    value: U256::from(1),
                    data: Bytes::new(),
                },
            ],
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(SENDER, payload)).unwrap();
        let ExecutionResult::FrameTransaction { frame_receipts, .. } = output.result else {
            panic!("expected frame transaction result")
        };
        assert_eq!(frame_receipts[1].status, FrameStatus::Success);
        assert_eq!(frame_receipts[1].gas_used.state, NEW_ACCOUNT_STATE_GAS);
        assert_eq!(output.state[&VALUE_TARGET].info.balance, U256::from(1));
    }

    #[test]
    fn verify_frame_dispatches_active_precompile_before_default_code() {
        let approve_code = [PUSH1, 0x03, PUSH0, PUSH0, APPROVE];
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(SENDER, account_with_code(approve_code));
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
                    FrameMode::Verify,
                    0,
                    encoded_target(ECRECOVER),
                    4_000,
                    U256::ZERO,
                    Bytes::new(),
                ),
            ],
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(SENDER, payload)).unwrap();
        let ExecutionResult::FrameTransaction { frame_receipts, .. } = output.result else {
            panic!("expected frame transaction result")
        };
        assert_eq!(frame_receipts[1].status, FrameStatus::Success);
        assert_eq!(frame_receipts[1].gas_used.execution, 3_100);
    }

    #[test]
    fn cross_frame_refill_reduces_the_owning_receipt() {
        let approve_code = [PUSH1, 0x03, PUSH0, PUSH0, APPROVE];
        let store_calldata_code = [PUSH0, CALLDATALOAD, PUSH0, SSTORE, STOP];
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(SENDER, account_with_code(approve_code));
        db.insert_account_info(STORAGE_TARGET, account_with_code(store_calldata_code));
        let mut create_data = vec![0; 32];
        create_data[31] = 1;
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
                Frame {
                    mode: FrameMode::Default,
                    target: encoded_target(STORAGE_TARGET),
                    limits: FrameLimits {
                        execution: 100_000,
                        state: NEW_SLOT_STATE_GAS,
                    },
                    data: create_data.into(),
                    ..Default::default()
                },
                Frame {
                    mode: FrameMode::Default,
                    target: encoded_target(STORAGE_TARGET),
                    limits: FrameLimits {
                        execution: 100_000,
                        state: 0,
                    },
                    data: Bytes::from(vec![0; 32]),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(SENDER, payload)).unwrap();
        let ExecutionResult::FrameTransaction { frame_receipts, .. } = output.result else {
            panic!("expected frame transaction result")
        };
        assert_eq!(frame_receipts[1].gas_used.state, 0);
        assert_eq!(frame_receipts[2].gas_used.state, 0);
    }

    #[test]
    fn cross_frame_refill_is_not_spendable_by_the_restoring_frame() {
        let approve_code = [PUSH1, 0x03, PUSH0, PUSH0, APPROVE];
        let store_two_slots_code = [
            PUSH0,
            CALLDATALOAD,
            PUSH0,
            SSTORE,
            PUSH1,
            0x20,
            CALLDATALOAD,
            PUSH1,
            0x01,
            SSTORE,
            STOP,
        ];
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(SENDER, account_with_code(approve_code));
        db.insert_account_info(STORAGE_TARGET, account_with_code(store_two_slots_code));
        let mut create_data = vec![0; 64];
        create_data[31] = 1;
        let mut restore_then_create_data = vec![0; 64];
        restore_then_create_data[63] = 1;
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
                Frame {
                    mode: FrameMode::Default,
                    target: encoded_target(STORAGE_TARGET),
                    limits: FrameLimits {
                        execution: 200_000,
                        state: NEW_SLOT_STATE_GAS,
                    },
                    data: create_data.into(),
                    ..Default::default()
                },
                Frame {
                    mode: FrameMode::Default,
                    target: encoded_target(STORAGE_TARGET),
                    limits: FrameLimits {
                        execution: 200_000,
                        state: 0,
                    },
                    data: restore_then_create_data.into(),
                    ..Default::default()
                },
            ],
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(SENDER, payload)).unwrap();
        let ExecutionResult::FrameTransaction { frame_receipts, .. } = output.result else {
            panic!("expected frame transaction result")
        };
        assert_eq!(frame_receipts[1].gas_used.state, NEW_SLOT_STATE_GAS);
        assert_eq!(frame_receipts[2].status, FrameStatus::Failure);
        assert_eq!(frame_receipts[2].gas_used.state, 0);
    }

    #[test]
    fn frame_copy_opcodes_charge_their_fixed_cost_once() {
        let code = [
            PUSH0,
            PUSH0,
            PUSH0,
            PUSH0,
            FRAMEDATACOPY,
            PUSH0,
            PUSH0,
            PUSH0,
            PUSH0,
            SIGDATACOPY,
            PUSH1,
            0x03,
            PUSH0,
            PUSH0,
            APPROVE,
        ];
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(SENDER, account_with_code(code));
        let payload = FrameTransaction {
            frames: vec![Frame::new(
                FrameMode::Default,
                0x03,
                Bytes::new(),
                1_000,
                U256::ZERO,
                Bytes::new(),
            )],
            signatures: vec![FrameSignature {
                scheme: SignatureScheme::Arbitrary,
                ..Default::default()
            }],
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(SENDER, payload)).unwrap();
        let ExecutionResult::FrameTransaction { frame_receipts, .. } = output.result else {
            panic!("expected frame transaction result")
        };
        assert_eq!(frame_receipts[0].gas_used.execution, 129);
    }

    #[test]
    fn max_cost_overflow_uses_actual_max_gas() {
        let mut payload = FrameTransaction {
            frames: vec![Frame {
                limits: FrameLimits {
                    execution: 0,
                    state: 1,
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let intrinsic = payload.intrinsic_gas(SENDER).unwrap();
        payload.frames[0].limits.execution = eip7825::TX_GAS_LIMIT_CAP - intrinsic;
        payload.max_fee_per_gas = U256::MAX / U256::from(eip7825::TX_GAS_LIMIT_CAP);
        assert_eq!(
            payload.gas_limit(SENDER),
            Some(eip7825::TX_GAS_LIMIT_CAP + 1)
        );
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(CacheDB::<EmptyDB>::default())
            .build_mainnet();

        assert!(matches!(
            evm.transact(tx_env(SENDER, payload)),
            Err(EVMError::Transaction(
                InvalidTransaction::OverflowPaymentInTransaction
            ))
        ));
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
            ..Default::default()
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
                FrameStatus::Success,
                FrameStatus::Failure,
                FrameStatus::SkippedAtomicBatch,
            ]
        );
        assert!(frame_receipts[1].gas_used.execution > 0);
        assert_eq!(frame_receipts[3].gas_used.execution, 0);
        let stored = output
            .state
            .get(&STORAGE_TARGET)
            .and_then(|account| account.storage.get(&U256::ZERO))
            .map(|slot| slot.present_value)
            .unwrap_or_default();
        assert_eq!(stored, U256::from(1));
    }

    #[test]
    fn entry_charge_halt_unrolls_atomic_batch() {
        let sender = PrivateKeySigner::random();
        let signature_hash = keccak256("entry charge halt unrolls atomic batch");
        let worker_code = [PUSH1, 0x01, PUSH1, 0x01, SSTORE];
        let halting_target = address!("5000000000000000000000000000000000000005");
        let worker_execution_gas = primitives::eip8038::COLD_ACCOUNT_ACCESS
            + 2 * context_interface::cfg::gas::VERYLOW
            + primitives::eip8038::WARM_ACCESS
            + primitives::eip8038::COLD_STORAGE_ACCESS_ADDITIONAL
            + primitives::eip8038::STORAGE_WRITE;
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(
            sender.address(),
            AccountInfo::default().with_balance(U256::MAX),
        );
        db.insert_account_info(STORAGE_TARGET, account_with_code(worker_code));
        db.insert_account_info(
            halting_target,
            AccountInfo::default().with_balance(U256::from(1)),
        );

        let payload = FrameTransaction {
            frames: vec![
                Frame {
                    mode: FrameMode::Verify,
                    flags: 0x03,
                    limits: FrameLimits {
                        execution: primitives::eip8038::WARM_ACCESS,
                        state: 0,
                    },
                    ..Default::default()
                },
                Frame {
                    mode: FrameMode::Default,
                    flags: 0x04,
                    target: encoded_target(STORAGE_TARGET),
                    limits: FrameLimits {
                        execution: worker_execution_gas,
                        state: NEW_SLOT_STATE_GAS,
                    },
                    value: U256::ZERO,
                    data: Bytes::new(),
                },
                Frame::new(
                    FrameMode::Default,
                    0x04,
                    encoded_target(halting_target),
                    primitives::eip8038::COLD_ACCOUNT_ACCESS - 1,
                    U256::ZERO,
                    Bytes::new(),
                ),
                Frame::new(
                    FrameMode::Default,
                    0,
                    encoded_target(STORAGE_TARGET),
                    worker_execution_gas,
                    U256::ZERO,
                    Bytes::new(),
                ),
            ],
            signatures: vec![signed_entry(&sender, Bytes::new(), signature_hash)],
            signature_hash,
            ..Default::default()
        };
        let intrinsic_gas = payload.intrinsic_gas(sender.address()).unwrap();
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet();

        let output = evm.transact(tx_env(sender.address(), payload)).unwrap();
        let ExecutionResult::FrameTransaction {
            gas,
            frame_receipts,
            ..
        } = output.result
        else {
            panic!("expected frame transaction result")
        };
        assert_eq!(
            frame_receipts
                .iter()
                .map(|receipt| receipt.status)
                .collect::<Vec<_>>(),
            vec![
                FrameStatus::Success,
                FrameStatus::Success,
                FrameStatus::Failure,
                FrameStatus::SkippedAtomicBatch,
            ]
        );
        assert_eq!(
            frame_receipts[0].gas_used.execution,
            primitives::eip8038::WARM_ACCESS
        );
        assert_eq!(frame_receipts[1].gas_used.execution, worker_execution_gas);
        assert_eq!(frame_receipts[1].gas_used.state, 0);
        assert_eq!(
            frame_receipts[2].gas_used.execution,
            primitives::eip8038::COLD_ACCOUNT_ACCESS - 1
        );
        assert_eq!(frame_receipts[3].gas_used.execution, 0);
        assert_eq!(gas.state_gas_spent_final(), 0);
        assert_eq!(
            gas.total_gas_spent(),
            intrinsic_gas
                + primitives::eip8038::WARM_ACCESS
                + worker_execution_gas
                + primitives::eip8038::COLD_ACCOUNT_ACCESS
                - 1
        );
        let stored = output
            .state
            .get(&STORAGE_TARGET)
            .and_then(|account| account.storage.get(&U256::from(1)))
            .map(|slot| slot.present_value)
            .unwrap_or_default();
        assert_eq!(stored, U256::ZERO);
        assert!(
            !output.state.contains_key(&halting_target),
            "a target whose entry charge fails must not be accessed"
        );
    }

    #[test]
    fn max_blob_fee_without_blobs_has_frame_transaction_error() {
        let payload = FrameTransaction {
            max_fee_per_blob_gas: U256::from(1),
            frames: vec![Frame {
                limits: FrameLimits {
                    execution: 1,
                    state: 0,
                },
                ..Default::default()
            }],
            ..Default::default()
        };
        let tx = tx_env(SENDER, payload);
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

    #[test]
    fn full_width_priority_fee_is_validated_without_narrowing() {
        let payload = FrameTransaction {
            frames: vec![Frame {
                limits: FrameLimits {
                    execution: 1,
                    state: 0,
                },
                ..Default::default()
            }],
            max_priority_fee_per_gas: U256::MAX,
            max_fee_per_gas: U256::MAX - U256::from(1),
            ..Default::default()
        };
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(CacheDB::<EmptyDB>::default())
            .build_mainnet();

        assert!(matches!(
            evm.transact(tx_env(SENDER, payload)),
            Err(EVMError::Transaction(
                InvalidTransaction::PriorityFeeGreaterThanMaxFee
            ))
        ));
    }
}
