//! Local context trait [`LocalContextTr`] and related types.
use alloy_eip8141::FrameStatus;
use core::{
    cell::{Ref, RefCell},
    ops::Range,
};
use primitives::{Address, HashMap, StorageKey};
use std::{rc::Rc, string::String, vec::Vec};

/// EIP-8141 approvals accumulated by successful top-level frames.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct FrameApprovalState {
    /// Account that approved payment.
    pub payer: Option<Address>,
    /// Whether execution as the transaction sender has been approved.
    pub sender_approved: bool,
}

/// Per-transaction EIP-8141 interpreter runtime state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FrameTransactionRuntime {
    /// Index of the currently executing top-level frame.
    pub current_frame_index: usize,
    /// Resolved target of the current top-level frame.
    pub resolved_target: Address,
    /// Statuses of completed top-level frames.
    pub statuses: Vec<FrameStatus>,
    /// Execution-gas usage reported by completed top-level frames.
    pub execution_gas_used: Vec<u64>,
    /// State-gas usage reported by completed top-level frames.
    pub state_gas_used: Vec<u64>,
    /// Committed approval state.
    pub approval: FrameApprovalState,
    /// Approval scopes corresponding to active interpreter call frames.
    pub approval_stack: Vec<FrameApprovalState>,
    /// Approval produced by the completed top-level interpreter frame.
    pub root_approval: Option<FrameApprovalState>,
    /// Revertible state-gas attribution across top-level frames.
    state_gas: FrameStateGas,
}

/// State-gas ownership and rollback bookkeeping, separate from approvals.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct FrameStateGas {
    /// Top-level frame owning each outstanding storage charge.
    owners: HashMap<(Address, StorageKey), usize>,
    /// Attribution changes retained across top-level frames.
    journal: Vec<FrameStateGasJournalEntry>,
    /// Checkpoints for active interpreter call frames.
    checkpoints: Vec<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum FrameStateGasJournalEntry {
    Owner {
        slot: (Address, StorageKey),
        previous: Option<usize>,
    },
    GasUsed {
        frame_index: usize,
        previous: u64,
    },
}

impl FrameTransactionRuntime {
    /// Creates runtime state for a frame transaction.
    pub fn new(resolved_target: Address) -> Self {
        Self {
            resolved_target,
            ..Self::default()
        }
    }

    /// Creates runtime state with capacity for all top-level frame results.
    pub fn with_capacity(resolved_target: Address, frame_count: usize) -> Self {
        Self {
            statuses: Vec::with_capacity(frame_count),
            execution_gas_used: Vec::with_capacity(frame_count),
            state_gas_used: Vec::with_capacity(frame_count),
            ..Self::new(resolved_target)
        }
    }

    /// Enters an interpreter call frame approval scope.
    pub fn enter_scope(&mut self) {
        let state = self.approval_stack.last().copied().unwrap_or(self.approval);
        self.approval_stack.push(state);
        self.state_gas
            .checkpoints
            .push(self.state_gas.journal.len());
    }

    /// Exits an interpreter call frame, committing approvals only on success.
    pub fn exit_scope(&mut self, success: bool) {
        let state = self.approval_stack.pop();
        let state_gas_checkpoint = self.state_gas.checkpoints.pop();
        if !success {
            if let Some(checkpoint) = state_gas_checkpoint {
                self.revert_state_gas(checkpoint);
            }
        }
        let Some(state) = state else {
            return;
        };
        if !success {
            return;
        }
        if let Some(parent) = self.approval_stack.last_mut() {
            *parent = state;
        } else {
            self.root_approval = Some(state);
        }
    }

    /// Commits approvals emitted by a successful top-level frame.
    pub const fn commit_root_approval(&mut self) {
        if let Some(state) = self.root_approval.take() {
            self.approval = state;
        }
    }

    /// Returns a checkpoint for state-gas ownership and receipt attribution.
    pub const fn state_gas_checkpoint(&self) -> usize {
        self.state_gas.journal.len()
    }

    /// Reverts state-gas ownership and receipt attribution to `checkpoint`.
    pub fn revert_state_gas(&mut self, checkpoint: usize) {
        while self.state_gas.journal.len() > checkpoint {
            match self.state_gas.journal.pop().expect("length checked") {
                FrameStateGasJournalEntry::Owner { slot, previous } => {
                    if let Some(owner) = previous {
                        self.state_gas.owners.insert(slot, owner);
                    } else {
                        self.state_gas.owners.remove(&slot);
                    }
                }
                FrameStateGasJournalEntry::GasUsed {
                    frame_index,
                    previous,
                } => {
                    if let Some(gas_used) = self.state_gas_used.get_mut(frame_index) {
                        *gas_used = previous;
                    }
                }
            }
        }
    }

    /// Attributes a successful storage-creation state-gas charge to the current frame.
    pub fn record_sstore_state_gas(&mut self, address: Address, key: StorageKey, amount: u64) {
        if amount == 0 {
            return;
        }
        let slot = (address, key);
        let previous_owner = self.state_gas.owners.insert(slot, self.current_frame_index);
        self.state_gas
            .journal
            .push(FrameStateGasJournalEntry::Owner {
                slot,
                previous: previous_owner,
            });
        let gas_used = self
            .state_gas_used
            .get_mut(self.current_frame_index)
            .expect("current frame receipt initialized");
        let previous = *gas_used;
        self.state_gas
            .journal
            .push(FrameStateGasJournalEntry::GasUsed {
                frame_index: self.current_frame_index,
                previous,
            });
        *gas_used = gas_used
            .checked_add(amount)
            .expect("frame state gas is bounded by its u64 limit");
    }

    /// Applies a storage-restoration refill and returns the amount spendable by this frame.
    pub fn refill_sstore_state_gas(
        &mut self,
        address: Address,
        key: StorageKey,
        amount: u64,
    ) -> u64 {
        if amount == 0 {
            return 0;
        }
        let slot = (address, key);
        let Some(owner) = self.state_gas.owners.remove(&slot) else {
            return 0;
        };
        self.state_gas
            .journal
            .push(FrameStateGasJournalEntry::Owner {
                slot,
                previous: Some(owner),
            });
        let gas_used = self
            .state_gas_used
            .get_mut(owner)
            .expect("outstanding charge owner has a receipt");
        let previous = *gas_used;
        self.state_gas
            .journal
            .push(FrameStateGasJournalEntry::GasUsed {
                frame_index: owner,
                previous,
            });
        *gas_used = gas_used
            .checked_sub(amount)
            .expect("refill cannot exceed its outstanding state-gas charge");
        if owner == self.current_frame_index {
            amount
        } else {
            0
        }
    }
}

/// Non-empty, item-pooling Vec.
#[derive(Debug, Clone)]
pub struct FrameStack<T> {
    stack: Vec<T>,
    index: Option<usize>,
}

impl<T> Default for FrameStack<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> FrameStack<T> {
    /// Creates a new, empty stack. It must be initialized with init before use.
    pub fn new() -> Self {
        // p99.9 of call frame depth is 8,
        // per: https://ethresear.ch/t/evm-stack-and-memory-usage-statistics-report/24209
        Self {
            stack: Vec::with_capacity(8),
            index: None,
        }
    }

    /// Creates a new stack with preallocated items by calling `T::default()` `len` times.
    /// Index will still be `None` until `end_init` is called.
    pub fn new_prealloc(len: usize) -> Self
    where
        T: Default,
    {
        let mut stack = Vec::with_capacity(len);
        stack.resize_with(len, T::default);
        Self { stack, index: None }
    }

    /// Initializes the stack with a single item.
    #[inline]
    pub fn start_init(&mut self) -> OutFrame<'_, T> {
        self.index = None;
        if self.stack.is_empty() {
            self.stack.reserve(8);
        }
        self.out_frame_at(0)
    }

    /// Finishes initialization.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it assumes that the `token` is initialized from this FrameStack object.
    #[inline]
    pub unsafe fn end_init(&mut self, token: FrameToken) {
        token.assert();
        if self.stack.is_empty() {
            unsafe { self.stack.set_len(1) };
        }
        self.index = Some(0);
    }

    /// Returns the current index of the stack.
    #[inline]
    pub const fn index(&self) -> Option<usize> {
        self.index
    }

    /// Increments the index.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it assumes that the `token` is obtained from `get_next` and
    /// that `end_init` is called to initialize the FrameStack.
    #[inline]
    pub unsafe fn push(&mut self, token: FrameToken) {
        token.assert();
        let index = self.index.as_mut().unwrap();
        *index += 1;
        // capacity of stack is incremented in `get_next`
        debug_assert!(
            *index < self.stack.capacity(),
            "Stack capacity is not enough for index"
        );
        // If the index is the last one, we need to increase the length.
        if *index == self.stack.len() {
            unsafe { self.stack.set_len(self.stack.len() + 1) };
        }
    }

    /// Clears the stack by setting the index to 0.
    /// It does not destroy the stack.
    #[inline]
    pub const fn clear(&mut self) {
        self.index = None;
    }

    /// Decrements the index.
    #[inline]
    pub fn pop(&mut self) {
        self.index = self.index.unwrap_or(0).checked_sub(1);
    }

    /// Returns the current item.
    #[inline]
    pub fn get(&mut self) -> &mut T {
        debug_assert!(
            self.stack.capacity() > self.index.unwrap(),
            "Stack capacity is not enough for index"
        );
        unsafe { &mut *self.stack.as_mut_ptr().add(self.index.unwrap()) }
    }

    /// Get next uninitialized item.
    #[inline]
    pub fn get_next(&mut self) -> OutFrame<'_, T> {
        if self.index.unwrap() + 1 == self.stack.capacity() {
            // allocate 8 more items
            self.stack.reserve(8);
        }
        self.out_frame_at(self.index.unwrap() + 1)
    }

    fn out_frame_at(&mut self, idx: usize) -> OutFrame<'_, T> {
        unsafe {
            OutFrame::new_maybe_uninit(self.stack.as_mut_ptr().add(idx), idx < self.stack.len())
        }
    }
}

/// A potentially initialized frame. Used when initializing a new frame in the main loop.
#[expect(missing_debug_implementations)]
pub struct OutFrame<'a, T> {
    ptr: *mut T,
    init: bool,
    lt: core::marker::PhantomData<&'a mut T>,
}

impl<'a, T> OutFrame<'a, T> {
    /// Creates a new initialized `OutFrame` from a mutable reference to a type `T`.
    pub fn new_init(slot: &'a mut T) -> Self {
        unsafe { Self::new_maybe_uninit(slot, true) }
    }

    /// Creates a new uninitialized `OutFrame` from a mutable reference to a `MaybeUninit<T>`.
    pub fn new_uninit(slot: &'a mut core::mem::MaybeUninit<T>) -> Self {
        unsafe { Self::new_maybe_uninit(slot.as_mut_ptr(), false) }
    }

    /// Creates a new `OutFrame` from a raw pointer to a type `T`.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it assumes that the pointer is valid and points to a location
    /// where a type `T` can be stored. It also assumes that the `init` flag correctly reflects whether
    /// the type `T` has been initialized or not.
    pub unsafe fn new_maybe_uninit(ptr: *mut T, init: bool) -> Self {
        Self {
            ptr,
            init,
            lt: Default::default(),
        }
    }

    /// Returns a mutable reference to the type `T`, initializing it if it hasn't been initialized yet.
    pub fn get(&mut self, f: impl FnOnce() -> T) -> &mut T {
        if !self.init {
            self.do_init(f);
        }
        unsafe { &mut *self.ptr }
    }

    #[inline(never)]
    #[cold]
    fn do_init(&mut self, f: impl FnOnce() -> T) {
        unsafe {
            self.init = true;
            self.ptr.write(f());
        }
    }

    /// Returns a mutable reference to the type `T`, without checking if it has been initialized.
    ///
    /// # Safety
    ///
    /// This method is unsafe because it assumes that the `OutFrame` has been initialized before use.
    pub unsafe fn get_unchecked(&mut self) -> &mut T {
        debug_assert!(self.init, "OutFrame must be initialized before use");
        unsafe { &mut *self.ptr }
    }

    /// Consumes the `OutFrame`, returning a `FrameToken` that indicates the frame has been initialized.
    pub const fn consume(self) -> FrameToken {
        FrameToken(self.init)
    }
}

/// Used to guarantee that a frame is initialized before use.
#[expect(missing_debug_implementations)]
pub struct FrameToken(bool);

impl FrameToken {
    /// Asserts that the frame token is initialized.
    #[cfg_attr(debug_assertions, track_caller)]
    pub fn assert(self) {
        assert!(self.0, "FrameToken must be initialized before use");
    }
}

/// Local context used for caching initcode from Initcode transactions.
pub trait LocalContextTr {
    /// Interpreter shared memory buffer. A reused memory buffer for calls.
    fn shared_memory_buffer(&self) -> &Rc<RefCell<Vec<u8>>>;

    /// Slice of the shared memory buffer returns None if range is not valid or buffer can't be borrowed.
    fn shared_memory_buffer_slice(&self, range: Range<usize>) -> Option<Ref<'_, [u8]>> {
        Ref::filter_map(self.shared_memory_buffer().borrow(), |b| b.get(range)).ok()
    }

    /// Clear the local context.
    fn clear(&mut self);

    /// Set the error message for a precompile error, if any.
    ///
    /// This is used to bubble up precompile error messages when the
    /// transaction directly targets a precompile (depth == 1).
    fn set_precompile_error_context(&mut self, _output: String);

    /// Take and clear the precompile error context, if present.
    ///
    /// Returns `Some(String)` if a precompile error message was recorded.
    fn take_precompile_error_context(&mut self) -> Option<String>;

    /// Returns the active EIP-8141 runtime state.
    fn frame_transaction(&self) -> Option<&FrameTransactionRuntime> {
        None
    }

    /// Returns whether this local context can store EIP-8141 runtime state.
    fn supports_eip8141(&self) -> bool {
        false
    }

    /// Returns the active EIP-8141 runtime state mutably.
    fn frame_transaction_mut(&mut self) -> Option<&mut FrameTransactionRuntime> {
        None
    }

    /// Replaces the active EIP-8141 runtime state.
    fn set_frame_transaction(&mut self, _runtime: Option<FrameTransactionRuntime>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_stack() {
        let mut stack = FrameStack::new_prealloc(1);
        let mut frame = stack.start_init();
        // it is already initialized to zero.
        *frame.get(|| 2) += 1;

        let token = frame.consume();
        unsafe { stack.end_init(token) };

        assert_eq!(stack.index(), Some(0));
        assert_eq!(stack.stack.len(), 1);

        let a = stack.get();
        assert_eq!(a, &mut 1);
        let mut b = stack.get_next();
        assert!(!b.init);
        assert_eq!(b.get(|| 2), &mut 2);
        let token = b.consume(); // TODO: remove
        unsafe { stack.push(token) };

        assert_eq!(stack.index(), Some(1));
        assert_eq!(stack.stack.len(), 2);
        let a = stack.get();
        assert_eq!(a, &mut 2);
        let b = stack.get_next();
        assert!(!b.init);

        stack.pop();

        assert_eq!(stack.index(), Some(0));
        assert_eq!(stack.stack.len(), 2);
        let a = stack.get();
        assert_eq!(a, &mut 1);
        let mut b = stack.get_next();
        assert!(b.init);
        assert_eq!(unsafe { b.get_unchecked() }, &mut 2);
    }
}
