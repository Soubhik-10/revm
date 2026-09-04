//! EIP-8141 frame transaction instructions.

use crate::{
    interpreter_types::{InputsTr, InterpreterTypes as ITy, MemoryTr, RuntimeFlag, StackTr},
    InstructionContext as Ictx, InstructionExecResult as Result, InstructionResult,
};
use context_interface::{host::FrameHostError, Host};
use primitives::{Bytes, B256, U256};

use super::system::copy_cost_and_memory_resize;

#[inline]
const fn host_error(error: FrameHostError) -> InstructionResult {
    match error {
        FrameHostError::Invalid => InstructionResult::OpcodeNotFound,
        FrameHostError::Revert => InstructionResult::Revert,
        FrameHostError::OutOfGas => InstructionResult::OutOfGas,
        FrameHostError::Fatal => InstructionResult::FatalExternalError,
    }
}

/// EIP-8141 `APPROVE` (0xaa).
pub fn approve<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, BOGOTA);
    popn!([offset, len, scope], context.interpreter);
    tracing::info!(
        target: "revm::eip8141::instruction",
        ?offset,
        ?len,
        ?scope,
        "Executing APPROVE"
    );
    let len = as_usize_or_fail!(context.interpreter, len);
    let output = if len == 0 {
        Bytes::new()
    } else {
        let offset = as_usize_or_fail!(context.interpreter, offset);
        crate::interpreter::resize_memory(
            &mut context.interpreter.gas,
            &mut context.interpreter.memory,
            context.host.gas_params(),
            offset,
            len,
        )?;
        Bytes::copy_from_slice(context.interpreter.memory.slice_len(offset, len).as_ref())
    };
    let state_gas = context
        .host
        .approve_frame_with_state_gas(
            context.interpreter.input.target_address(),
            scope,
            context.interpreter.gas.reservoir(),
        )
        .map_err(host_error)?;
    state_gas!(context.interpreter, state_gas);
    context.interpreter.return_with_output(output);
    Err(InstructionResult::Return)
}

/// EIP-8141 `TXPARAM` (0xb0).
pub fn txparam<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, BOGOTA);
    popn_top!([], param, context.interpreter);
    tracing::info!(target: "revm::eip8141::instruction", ?param, "Executing TXPARAM");
    *param = context
        .host
        .frame_tx_param(*param, context.interpreter.gas.reservoir())
        .ok_or(InstructionResult::OpcodeNotFound)?;
    Ok(())
}

/// EIP-8141 `FRAMEDATALOAD` (0xb1).
pub fn framedataload<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, BOGOTA);
    popn!([offset, frame_index], context.interpreter);
    tracing::info!(
        target: "revm::eip8141::instruction",
        ?offset,
        ?frame_index,
        "Executing FRAMEDATALOAD"
    );
    let data = context
        .host
        .frame_data(frame_index)
        .ok_or(InstructionResult::OpcodeNotFound)?;
    let offset = as_usize_saturated!(offset);
    let mut word = B256::ZERO;
    if offset < data.len() {
        let len = 32.min(data.len() - offset);
        word[..len].copy_from_slice(&data[offset..offset + len]);
    }
    push!(context.interpreter, U256::from_be_bytes(word.0));
    Ok(())
}

fn copy_data<IT: ITy, H: Host + ?Sized>(
    context: &mut Ictx<'_, H, IT>,
    memory_offset: U256,
    data_offset: U256,
    len: U256,
    data: &[u8],
) -> Result {
    let len = as_usize_or_fail!(context.interpreter, len);
    let Some(memory_offset) = copy_cost_and_memory_resize(
        context.interpreter,
        context.host.gas_params(),
        memory_offset,
        len,
    )?
    else {
        return Ok(());
    };
    context
        .interpreter
        .memory
        .set_data(memory_offset, as_usize_saturated!(data_offset), len, data);
    Ok(())
}

/// EIP-8141 `FRAMEDATACOPY` (0xb2).
pub fn framedatacopy<IT: ITy, H: Host + ?Sized>(mut context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, BOGOTA);
    popn!(
        [memory_offset, data_offset, len, frame_index],
        context.interpreter
    );
    tracing::info!(
        target: "revm::eip8141::instruction",
        ?memory_offset,
        ?data_offset,
        ?len,
        ?frame_index,
        "Executing FRAMEDATACOPY"
    );
    let data = context
        .host
        .frame_data(frame_index)
        .ok_or(InstructionResult::OpcodeNotFound)?;
    copy_data(&mut context, memory_offset, data_offset, len, &data)
}

/// EIP-8141 `FRAMEPARAM` (0xb3).
pub fn frameparam<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, BOGOTA);
    popn!([frame_index, param], context.interpreter);
    tracing::info!(
        target: "revm::eip8141::instruction",
        ?frame_index,
        ?param,
        "Executing FRAMEPARAM"
    );
    let value = context
        .host
        .frame_param(frame_index, param)
        .ok_or(InstructionResult::OpcodeNotFound)?;
    push!(context.interpreter, value);
    Ok(())
}

/// EIP-8141 `SIGPARAM` (0xb4).
pub fn sigparam<IT: ITy, H: Host + ?Sized>(context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, BOGOTA);
    popn!([signature_index, param], context.interpreter);
    tracing::info!(
        target: "revm::eip8141::instruction",
        ?signature_index,
        ?param,
        "Executing SIGPARAM"
    );
    let value = context
        .host
        .frame_signature_param(signature_index, param)
        .ok_or(InstructionResult::OpcodeNotFound)?;
    push!(context.interpreter, value);
    Ok(())
}

/// EIP-8141 `SIGDATACOPY` (0xb5).
pub fn sigdatacopy<IT: ITy, H: Host + ?Sized>(mut context: Ictx<'_, H, IT>) -> Result {
    check!(context.interpreter, BOGOTA);
    popn!(
        [memory_offset, data_offset, len, signature_index],
        context.interpreter
    );
    tracing::info!(
        target: "revm::eip8141::instruction",
        ?signature_index,
        ?memory_offset,
        ?data_offset,
        ?len,
        "Executing SIGDATACOPY"
    );
    let data = context
        .host
        .frame_signature_bytes(signature_index)
        .ok_or(InstructionResult::OpcodeNotFound)?;
    copy_data(&mut context, memory_offset, data_offset, len, &data)
}
