use crate::{Inspector, InspectorEvmTr, JournalExt};
use context::journaled_state::JournalCheckpoint;
use context::{result::ExecutionResult, ContextTr, JournalEntry, JournalTr};
use handler::{
    eip8141::{self, DefaultFrameStage, FrameValidationResult},
    evm::FrameTr,
    execution::runtime_oog_unwind,
    post_execution::build_result_gas,
    EvmTr, FrameResult, Handler, ItemOrResult,
};
use interpreter::{
    instructions::{GasTable, InstructionTable},
    interpreter_types::LoopControl,
    FrameInput, GasTracker, Host, InitialAndFloorGas, InstructionResult, Interpreter,
    InterpreterAction, InterpreterTypes,
};
use primitives::hints_util::cold_path;

/// Trait that extends [`Handler`] with inspection functionality.
///
/// Similar how [`Handler::run`] method serves as the entry point,
/// [`InspectorHandler::inspect_run`] method serves as the entry point for inspection.
/// For system calls, [`InspectorHandler::inspect_run_system_call`] provides inspection
/// support similar to [`Handler::run_system_call`].
///
/// Notice that when inspection is run it skips few functions from handler, this can be
/// a problem if custom EVM is implemented and some of skipped functions have changed logic.
/// For custom EVM, those changed functions would need to be also changed in [`InspectorHandler`].
///
/// List of functions that are skipped in [`InspectorHandler`]:
/// * [`Handler::run`] replaced with [`InspectorHandler::inspect_run`]
/// * [`Handler::run_without_catch_error`] replaced with [`InspectorHandler::inspect_run_without_catch_error`]
/// * [`Handler::execution`] replaced with [`InspectorHandler::inspect_execution`]
/// * [`Handler::run_exec_loop`] replaced with [`InspectorHandler::inspect_run_exec_loop`]
///   * `run_exec_loop` calls `inspect_frame_init` and `inspect_frame_run` that call inspector inside.
/// * [`Handler::run_system_call`] replaced with [`InspectorHandler::inspect_run_system_call`]
pub trait InspectorHandler: Handler
where
    Self::Evm:
        InspectorEvmTr<Inspector: Inspector<<<Self as Handler>::Evm as EvmTr>::Context, Self::IT>>,
{
    /// The interpreter types used by this handler.
    type IT: InterpreterTypes;

    /// Validates and discards a policy-selected EIP-8141 prefix with full
    /// inspector coverage, including synthetic default-code VERIFY frames.
    fn inspect_validate_prefix(
        &mut self,
        evm: &mut Self::Evm,
        prefix_end: usize,
    ) -> Result<FrameValidationResult, Self::Error> {
        eip8141::validate_prefix_with_callbacks(
            self,
            evm,
            prefix_end,
            |handler, evm, frame| handler.inspect_run_exec_loop(evm, frame),
            |_, evm, stage, frame_input, result| {
                let (context, inspector) = evm.ctx_inspector();
                match stage {
                    DefaultFrameStage::Start => {
                        *result = frame_start(context, inspector, frame_input);
                    }
                    DefaultFrameStage::End => {
                        if let Some(result) = result {
                            frame_end(context, inspector, frame_input, result);
                        }
                    }
                }
            },
        )
    }

    /// Entry point for inspection.
    ///
    /// This method is acts as [`Handler::run`] method for inspection.
    fn inspect_run(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        match self.inspect_run_without_catch_error(evm) {
            Ok(output) => Ok(output),
            Err(e) => self.catch_error(evm, e),
        }
    }

    /// Run inspection without catching error.
    ///
    /// This method is acts as [`Handler::run_without_catch_error`] method for inspection.
    fn inspect_run_without_catch_error(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        let init_and_floor_gas = self.validate(evm)?;
        // Create the transaction-level gas tracker from the validated
        // intrinsic gas (mirrors `Handler::run_without_catch_error`).
        let mut gas = self.tx_gas(evm, &init_and_floor_gas);
        // Pre-execution returns the EIP-7702 refund and the EIP-2780 runtime
        // gas phase checkpoint. `None` — from pre-execution or execution —
        // means the runtime gas phase ran out of gas: the transaction is
        // included as an out-of-gas halt without entering execution.
        let pre_execution = self.pre_execution(evm, &mut gas)?;

        let mut refund = 0;
        let mut exec_result = None;
        if let Some(pre_execution) = pre_execution {
            refund = pre_execution.eip7702_refund as i64;
            exec_result = self.inspect_execution(evm, pre_execution.checkpoint, &mut gas)?;
        }
        let mut frame_result = match exec_result {
            Some(exec_result) => exec_result,
            None => self.runtime_oog_result(evm, &init_and_floor_gas, &mut gas)?,
        };
        let result_gas = self.post_execution(evm, &mut frame_result, init_and_floor_gas, refund)?;
        self.execution_result(evm, frame_result, result_gas)
    }

    /// Run execution loop with inspection support
    ///
    /// This method acts as [`Handler::execution`] method for inspection.
    fn inspect_execution(
        &mut self,
        evm: &mut Self::Evm,
        checkpoint: JournalCheckpoint,
        gas: &mut GasTracker,
    ) -> Result<Option<FrameResult>, Self::Error> {
        // Create the first frame action from the transaction-level gas
        // (mirrors `Handler::execution`).
        let Some(first_frame_input) = self.first_frame_input(evm, gas)? else {
            runtime_oog_unwind(evm.ctx(), checkpoint)?;
            return Ok(None);
        };
        // The runtime gas phase is complete: commit its state changes.
        evm.ctx().journal_mut().checkpoint_commit();

        // Run execution loop
        let mut frame_result = self.inspect_run_exec_loop(evm, first_frame_input)?;

        // Handle last frame result
        self.last_frame_result(evm, &mut frame_result, gas)?;
        Ok(Some(frame_result))
    }

    /* FRAMES */

    /// Run inspection on execution loop.
    ///
    /// This method acts as [`Handler::run_exec_loop`] method for inspection.
    ///
    /// It will call:
    /// * [`Inspector::call`],[`Inspector::create`] to inspect call, create and eofcreate.
    /// * [`Inspector::call_end`],[`Inspector::create_end`] to inspect call, create and eofcreate end.
    /// * [`Inspector::initialize_interp`] to inspect initialized interpreter.
    fn inspect_run_exec_loop(
        &mut self,
        evm: &mut Self::Evm,
        first_frame_input: <<Self::Evm as EvmTr>::Frame as FrameTr>::FrameInit,
    ) -> Result<FrameResult, Self::Error> {
        let res = evm.inspect_frame_init(first_frame_input)?;

        if let ItemOrResult::Result(frame_result) = res {
            return Ok(frame_result);
        }

        loop {
            let call_or_result = evm.inspect_frame_run()?;

            let result = match call_or_result {
                ItemOrResult::Item(init) => {
                    match evm.inspect_frame_init(init)? {
                        ItemOrResult::Item(_) => {
                            continue;
                        }
                        // Do not pop the frame since no new frame was created
                        ItemOrResult::Result(result) => result,
                    }
                }
                ItemOrResult::Result(result) => result,
            };

            if let Some(result) = evm.frame_return_result(result)? {
                return Ok(result);
            }
        }
    }

    /// Run system call with inspection support.
    ///
    /// This method acts as [`Handler::run_system_call`] method for inspection.
    /// Similar to [`InspectorHandler::inspect_run`] but skips validation and pre-execution phases,
    /// going directly to execution with inspection support.
    fn inspect_run_system_call(
        &mut self,
        evm: &mut Self::Evm,
    ) -> Result<ExecutionResult<Self::HaltReason>, Self::Error> {
        // dummy values that are not used.
        let init_and_floor_gas = InitialAndFloorGas::new(0, 0);
        let mut gas = self.tx_gas(evm, &init_and_floor_gas);
        // System calls skip pre-execution, so the checkpoint that
        // `inspect_execution` settles is opened here.
        let checkpoint = evm.ctx().journal_mut().checkpoint();
        // call execution with inspection and then output.
        match self
            .inspect_execution(evm, checkpoint, &mut gas)
            .and_then(|exec_result| {
                let exec_result = match exec_result {
                    Some(exec_result) => exec_result,
                    // Unreachable in practice: system calls carry no value and
                    // target non-delegated system contracts, so no runtime
                    // charges apply.
                    None => self.runtime_oog_result(evm, &init_and_floor_gas, &mut gas)?,
                };
                // System calls have no intrinsic gas; build ResultGas from frame result.
                let gas = exec_result.gas();
                let result_gas = build_result_gas(false, gas, init_and_floor_gas);
                self.execution_result(evm, exec_result, result_gas)
            }) {
            out @ Ok(_) => out,
            Err(e) => self.catch_error(evm, e),
        }
    }
}

/// Handles the start of a frame by calling the appropriate inspector method.
pub fn frame_start<CTX, INTR: InterpreterTypes>(
    context: &mut CTX,
    inspector: &mut impl Inspector<CTX, INTR, FrameInput, FrameResult>,
    frame_input: &mut FrameInput,
) -> Option<FrameResult> {
    // Generic hook before variant dispatch
    if let Some(result) = inspector.frame_start(context, frame_input) {
        return Some(result);
    }
    // Variant-specific dispatch
    match frame_input {
        FrameInput::Call(i) => {
            if let Some(output) = inspector.call(context, i) {
                return Some(FrameResult::Call(output));
            }
        }
        FrameInput::Create(i) => {
            if let Some(output) = inspector.create(context, i) {
                return Some(FrameResult::Create(output));
            }
        }
        FrameInput::Empty => unreachable!(),
    }
    None
}

/// Handles the end of a frame by calling the appropriate inspector method.
pub fn frame_end<CTX, INTR: InterpreterTypes>(
    context: &mut CTX,
    inspector: &mut impl Inspector<CTX, INTR, FrameInput, FrameResult>,
    frame_input: &FrameInput,
    frame_output: &mut FrameResult,
) {
    // Variant-specific dispatch first
    match frame_output {
        FrameResult::Call(outcome) => {
            let FrameInput::Call(i) = frame_input else {
                panic!("FrameInput::Call expected {frame_input:?}");
            };
            inspector.call_end(context, i, outcome);
        }
        FrameResult::Create(outcome) => {
            let FrameInput::Create(i) = frame_input else {
                panic!("FrameInput::Create expected {frame_input:?}");
            };
            inspector.create_end(context, i, outcome);
        }
    }
    // Generic hook after variant dispatch
    inspector.frame_end(context, frame_input, frame_output);
}

/// Run Interpreter loop with inspection support.
///
/// This function is used to inspect the Interpreter loop.
/// It will call [`Inspector::step`] and [`Inspector::step_end`] after each instruction.
/// And [`Inspector::log`],[`Inspector::selfdestruct`] for each log and selfdestruct instruction.
pub fn inspect_instructions<CTX, IT>(
    context: &mut CTX,
    interpreter: &mut Interpreter<IT>,
    mut inspector: impl Inspector<CTX, IT>,
    instructions: &InstructionTable<IT, CTX>,
    gas_table: &GasTable,
) -> InterpreterAction
where
    CTX: ContextTr<Journal: JournalExt> + Host,
    IT: InterpreterTypes,
{
    let mut instruction_journal_i = None;
    loop {
        inspector.step(interpreter, context);
        if interpreter.bytecode.is_end() {
            cold_path();
            break;
        }

        instruction_journal_i = Some(context.journal().journal().len());
        let logs_i = context.journal().logs().len();
        if let Err(e) = interpreter.step(instructions, gas_table, context) {
            cold_path();
            if interpreter.bytecode.action().is_none() {
                interpreter.halt(e);
            }
        }

        if context.journal().logs().len() != logs_i {
            cold_path();
            inspect_logs(Some(interpreter), context, &mut inspector, logs_i);
        }

        inspector.step_end(interpreter, context);

        if interpreter.bytecode.is_end() {
            cold_path();
            break;
        }
    }

    let next_action = interpreter.take_next_action();

    // Handle selfdestruct.
    if let InterpreterAction::Return(result) = &next_action {
        if result.result == InstructionResult::SelfDestruct {
            if let Some(journal_i) = instruction_journal_i {
                inspect_selfdestruct(context, &mut inspector, journal_i);
            }
        }
    }

    next_action
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::CountInspector;
    use alloy_eip8141::{Frame, FrameLimits, FrameMode, FrameSignature, SignatureScheme};
    use alloy_signer::{Signature, SignerSync};
    use alloy_signer_local::PrivateKeySigner;
    use context::{transaction::FrameTransaction, Context, ContextSetters, LocalContextTr, TxEnv};
    use database::{CacheDB, EmptyDB};
    use handler::{MainBuilder, MainContext, MainnetHandler};
    use primitives::{eip8037, hardfork::SpecId, keccak256, Bytes, TxKind, U256};
    use state::{AccountInfo, Bytecode};

    fn signature_bytes(signature: &Signature) -> Bytes {
        let mut bytes = Vec::with_capacity(65);
        bytes.push(u8::from(signature.v()));
        bytes.extend_from_slice(&signature.r().to_be_bytes::<32>());
        bytes.extend_from_slice(&signature.s().to_be_bytes::<32>());
        bytes.into()
    }

    fn signature(
        signer: &PrivateKeySigner,
        signer_field: Bytes,
        message: primitives::B256,
    ) -> FrameSignature {
        FrameSignature {
            scheme: SignatureScheme::Secp256k1,
            signer: signer_field,
            msg: Bytes::new(),
            signature: signature_bytes(&signer.sign_hash_sync(&message).unwrap()),
        }
    }

    #[test]
    fn inspected_prefix_stops_at_payment_verification() {
        let sender = PrivateKeySigner::random();
        let sponsor = PrivateKeySigner::random();
        let suffix_target = primitives::address!("3000000000000000000000000000000000000003");
        let signature_hash = keccak256("inspected EIP-8141 prefix");
        let encoded_sponsor = Bytes::copy_from_slice(sponsor.address().as_slice());
        let transaction = FrameTransaction {
            frames: vec![
                Frame::new(
                    FrameMode::Verify,
                    0x02,
                    Bytes::new(),
                    FrameLimits {
                        execution: 2_000,
                        state: 0,
                    },
                    U256::ZERO,
                    Bytes::new(),
                ),
                Frame::new(
                    FrameMode::Verify,
                    0x01,
                    encoded_sponsor,
                    FrameLimits {
                        execution: 3_000,
                        state: eip8037::NEW_ACCOUNT_BYTES * eip8037::CPSB_GLAMSTERDAM,
                    },
                    U256::ZERO,
                    Bytes::new(),
                ),
                Frame::new(
                    FrameMode::Sender,
                    0,
                    Bytes::copy_from_slice(suffix_target.as_slice()),
                    FrameLimits {
                        execution: 3_000,
                        state: 0,
                    },
                    U256::ZERO,
                    Bytes::new(),
                ),
                Frame::new(
                    FrameMode::Sender,
                    0,
                    Bytes::copy_from_slice(suffix_target.as_slice()),
                    FrameLimits {
                        execution: 3_000,
                        state: 0,
                    },
                    U256::ZERO,
                    Bytes::new(),
                ),
            ],
            signatures: vec![
                signature(&sender, Bytes::new(), signature_hash),
                signature(
                    &sponsor,
                    Bytes::copy_from_slice(sponsor.address().as_slice()),
                    signature_hash,
                ),
            ],
            signature_hash,
            ..Default::default()
        };
        let gas_limit = transaction.gas_limit(sender.address()).unwrap();
        let tx = TxEnv::builder()
            .tx_type(Some(0x06))
            .caller(sender.address())
            .kind(TxKind::Call(sender.address()))
            .gas_limit(gas_limit)
            .gas_priority_fee(Some(0))
            .frame_transaction(transaction)
            .build()
            .unwrap();

        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(
            sender.address(),
            AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(&[
                0x60, 0x02, 0x5f, 0x5f, 0xaa, 0x00,
            ]))),
        );
        db.insert_account_info(
            suffix_target,
            AccountInfo::default().with_code(Bytecode::new_legacy(Bytes::from_static(&[0xfe]))),
        );
        let mut inspector = CountInspector::new();
        let mut evm = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.set_spec_and_mainnet_gas_params(SpecId::BOGOTA))
            .with_db(db)
            .build_mainnet_with_inspector(&mut inspector);
        evm.ctx.set_tx(tx);

        let mut handler: MainnetHandler<
            _,
            context::result::EVMError<core::convert::Infallible>,
            _,
        > = MainnetHandler::default();
        let result = handler.inspect_validate_prefix(&mut evm, 2).unwrap();
        assert_eq!(result.payer, sponsor.address());
        assert_eq!(result.prefix_end, 2);
        assert!(evm.ctx_ref().local().frame_transaction().is_none());
        assert!(handler.inspect_validate_prefix(&mut evm, 3).is_err());
        assert!(evm.ctx_ref().local().frame_transaction().is_none());
        drop(evm);
        assert_eq!(inspector.call_count(), 4);
        assert_eq!(inspector.call_end_count(), 4);
        assert_eq!(inspector.get_count(0xaa), 2);
        assert_eq!(inspector.get_count(0xfe), 0);
    }
}

/// Forwards the logs journaled since `logs_i` to the inspector.
///
/// `interpreter` is `Some` on the instruction path, where the logs belong to
/// the instruction that just ran and so go to [`Inspector::log_full`]; the
/// frame-init paths report a value transfer that has no interpreter of its own
/// and go to [`Inspector::log`].
///
/// Cold: callers check `logs_i` against the journal length first, and most
/// instructions journal no log at all.
#[inline(never)]
#[cold]
pub(crate) fn inspect_logs<CTX, IT>(
    interpreter: Option<&mut Interpreter<IT>>,
    context: &mut CTX,
    inspector: &mut impl Inspector<CTX, IT>,
    logs_i: usize,
) where
    CTX: ContextTr<Journal: JournalExt>,
    IT: InterpreterTypes,
{
    let logs = context.journal_mut().logs()[logs_i..].to_vec();
    match interpreter {
        Some(interpreter) => {
            for log in logs {
                inspector.log_full(interpreter, context, log);
            }
        }
        None => {
            for log in logs {
                inspector.log(context, log);
            }
        }
    }
}

#[inline(never)]
#[cold]
fn inspect_selfdestruct<CTX, IT>(
    context: &mut CTX,
    inspector: &mut impl Inspector<CTX, IT>,
    journal_i: usize,
) where
    CTX: ContextTr<Journal: JournalExt> + Host,
    IT: InterpreterTypes,
{
    let entry = context
        .journal_mut()
        .journal()
        .get(journal_i..)
        .and_then(|entries| entries.last());

    if let Some(
        JournalEntry::AccountDestroyed {
            address: contract,
            target: to,
            had_balance: balance,
            ..
        }
        | JournalEntry::BalanceTransfer {
            from: contract,
            to,
            balance,
            ..
        },
    ) = entry
    {
        inspector.selfdestruct(*contract, *to, *balance);
    }
}
