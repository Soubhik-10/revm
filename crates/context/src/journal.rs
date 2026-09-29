//! This module contains [`Journal`] struct and implements [`JournalTr`] trait for it.
//!
//! Entry submodule contains [`JournalEntry`] and [`JournalEntryTr`] traits.
//! and inner submodule contains [`JournalInner`] struct that contains state.
pub mod inner;
pub mod warm_addresses;

pub use context_interface::journaled_state::entry::{JournalEntry, JournalEntryTr};
pub use inner::{JournalCfg, JournalInner};

use bytecode::Bytecode;
use context_interface::{
    context::{SStoreResult, SelfDestructResult, StateLoad},
    journaled_state::{
        account::JournaledAccount, AccountInfoLoad, AccountLoad, JournalCheckpoint,
        JournalLoadError, JournalTr, TransferError, WarmAccessSnapshot,
    },
};
use core::ops::{Deref, DerefMut};
use database_interface::Database;
use primitives::eip7906::{
    TxDiffParam, TxTraceParam, ACCOUNT_BALANCE_CHANGED, ACCOUNT_CODE_HASH_CHANGED,
    ACCOUNT_NONCE_CHANGED, ACCOUNT_STORAGE_CHANGED,
};
use primitives::{
    hardfork::SpecId, Address, AddressMap, AddressSet, Bytes, HashSet, Log, StorageKey,
    StorageValue, B256, KECCAK_EMPTY, U256,
};
use state::{Account, EvmState};
use std::vec::Vec;

/// A journal of state changes internal to the EVM
///
/// On each additional call, the depth of the journaled state is increased (`depth`) and a new journal is added.
///
/// The journal contains every state change that happens within that call, making it possible to revert changes made in a specific call.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Journal<DB, ENTRY = JournalEntry>
where
    ENTRY: JournalEntryTr,
{
    /// Database
    pub database: DB,
    /// Inner journal state.
    pub inner: JournalInner<ENTRY>,
}

impl<DB, ENTRY> Deref for Journal<DB, ENTRY>
where
    ENTRY: JournalEntryTr,
{
    type Target = JournalInner<ENTRY>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<DB, ENTRY> DerefMut for Journal<DB, ENTRY>
where
    ENTRY: JournalEntryTr,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<DB, ENTRY: JournalEntryTr> Journal<DB, ENTRY> {
    /// Creates a new JournaledState by copying state data from a JournalInit and provided database.
    /// This allows reusing the state, logs, and other data from a previous execution context while
    /// connecting it to a different database backend.
    pub const fn new_with_inner(database: DB, inner: JournalInner<ENTRY>) -> Self {
        Self { database, inner }
    }

    /// Consumes the [`Journal`] and returns [`JournalInner`].
    ///
    /// If you need to preserve the original journal, use [`Self::to_inner`] instead which clones the state.
    pub fn into_init(self) -> JournalInner<ENTRY> {
        self.inner
    }
}

impl<DB, ENTRY: JournalEntryTr + Clone> Journal<DB, ENTRY> {
    /// Creates a new [`JournalInner`] by cloning all internal state data (state, storage, logs, etc)
    /// This allows creating a new journaled state with the same state data but without
    /// carrying over the original database.
    ///
    /// This is useful when you want to reuse the current state for a new transaction or
    /// execution context, but want to start with a fresh database.
    pub fn to_inner(&self) -> JournalInner<ENTRY> {
        self.inner.clone()
    }
}

impl<DB: Database, ENTRY: JournalEntryTr> Journal<DB, ENTRY> {
    fn eip7906_storage_value(
        &mut self,
        selector: TxDiffParam,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<Option<StateLoad<U256>>, JournalLoadError<DB::Error>> {
        let load = self
            .inner
            .sload(&mut self.database, address, key, skip_cold_load)?;
        let value = if selector == TxDiffParam::SlotValueBefore {
            let Some(slot) = self
                .inner
                .state
                .get(&address)
                .and_then(|account| account.storage.get(&key))
            else {
                return Ok(None);
            };
            slot.original_value()
        } else {
            load.data
        };
        Ok(Some(StateLoad::new(value, load.is_cold)))
    }

    fn eip7906_account_value(
        &mut self,
        selector: TxDiffParam,
        address: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<U256>, JournalLoadError<DB::Error>> {
        let load =
            self.inner
                .load_account_optional(&mut self.database, address, false, skip_cold_load)?;
        let value = match selector {
            TxDiffParam::BalanceBefore => load.data.original_info().balance,
            TxDiffParam::BalanceAfter => load.data.info.balance,
            TxDiffParam::CodeHashBefore => {
                U256::from_be_bytes(load.data.original_info().code_hash.0)
            }
            TxDiffParam::CodeHashAfter => U256::from_be_bytes(load.data.info.code_hash.0),
            _ => unreachable!("only account lookup selectors are dispatched here"),
        };
        Ok(StateLoad::new(value, load.is_cold))
    }
}

impl<DB: Database, ENTRY: JournalEntryTr> JournalTr for Journal<DB, ENTRY> {
    type Database = DB;
    type State = EvmState;
    type JournaledAccount<'a>
        = JournaledAccount<'a, DB, ENTRY>
    where
        ENTRY: 'a,
        DB: 'a;

    fn new(database: DB) -> Journal<DB, ENTRY> {
        Self {
            inner: JournalInner::new(),
            database,
        }
    }

    fn db_and_state(&self) -> (&Self::Database, &Self::State) {
        (&self.database, &self.inner.state)
    }

    #[inline]
    fn db_and_state_mut(&mut self) -> (&mut Self::Database, &mut Self::State) {
        (&mut self.database, &mut self.inner.state)
    }

    fn sload(
        &mut self,
        address: Address,
        key: StorageKey,
    ) -> Result<StateLoad<StorageValue>, <Self::Database as Database>::Error> {
        self.inner
            .sload_assume_account_present(&mut self.database, address, key, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    fn sstore(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
    ) -> Result<StateLoad<SStoreResult>, <Self::Database as Database>::Error> {
        self.inner
            .sstore_assume_account_present(&mut self.database, address, key, value, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    fn tload(&mut self, address: Address, key: StorageKey) -> StorageValue {
        self.inner.tload(address, key)
    }

    fn tstore(&mut self, address: Address, key: StorageKey, value: StorageValue) {
        self.inner.tstore(address, key, value)
    }

    fn log(&mut self, log: Log) {
        self.inner.log(log)
    }

    #[inline]
    fn logs(&self) -> &[Log] {
        &self.inner.logs
    }

    fn eip7906_txtrace(&self, param: U256, index: U256) -> Option<U256> {
        let selector = TxTraceParam::try_from(u8::try_from(param).ok()?).ok()?;
        let index = usize::try_from(index).ok()?;
        if selector.requires_zero_index() && index != 0 {
            return None;
        }

        eip7906_trace_value(&self.inner.state, &self.inner.logs, selector, index)
    }

    fn eip7906_txdiff(
        &mut self,
        param: U256,
        in2: U256,
        in3: U256,
        skip_cold_load: bool,
    ) -> Result<Option<StateLoad<U256>>, JournalLoadError<DB::Error>> {
        let selector = match u8::try_from(param)
            .ok()
            .and_then(|value| TxDiffParam::try_from(value).ok())
        {
            Some(selector) => selector,
            None => return Ok(None),
        };
        if selector.requires_zero_third_operand() && !in3.is_zero() {
            return Ok(None);
        }

        let address = eip7906_address(in2);
        if selector.is_storage_lookup() {
            return self.eip7906_storage_value(selector, address, in3, skip_cold_load);
        }

        if selector.is_account_lookup() {
            return self
                .eip7906_account_value(selector, address, skip_cold_load)
                .map(Some);
        }

        Ok(eip7906_transaction_local_value(
            &self.inner.state,
            &self.inner.logs,
            selector,
            address,
            in2,
            in3,
        )
        .map(|value| StateLoad::new(value, false)))
    }

    fn eip7906_event_data(&self, event_index: U256) -> Option<Bytes> {
        let index = usize::try_from(event_index).ok()?;
        Some(self.inner.logs.get(index)?.data.data.clone())
    }

    #[inline]
    fn take_logs(&mut self) -> Vec<Log> {
        self.inner.take_logs()
    }

    fn selfdestruct(
        &mut self,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner
            .selfdestruct(&mut self.database, address, target, skip_cold_load)
    }

    #[inline]
    fn warm_access_list(&mut self, access_list: AddressMap<HashSet<StorageKey>>) {
        self.inner.warm_addresses.set_access_list(access_list);
    }

    #[inline]
    fn warm_coinbase_account(&mut self, address: Address) {
        self.inner.warm_addresses.set_coinbase(address);
    }

    #[inline]
    fn warm_precompiles(&mut self, precompiles: &AddressSet) {
        self.inner
            .warm_addresses
            .set_precompile_addresses(precompiles);
    }

    #[inline]
    fn precompile_addresses(&self) -> &AddressSet {
        self.inner.warm_addresses.precompiles()
    }

    #[inline]
    fn is_account_cold(&self, address: Address) -> bool {
        self.inner.is_account_cold(address)
    }

    /// Returns call depth.
    #[inline]
    fn depth(&self) -> usize {
        self.inner.depth
    }

    #[inline]
    fn set_spec_id(&mut self, spec_id: SpecId) {
        self.inner.cfg.spec = spec_id;
    }

    #[inline]
    fn set_eip7708_config(&mut self, disabled: bool, eip8246_delayed_clear_disabled: bool) {
        self.inner
            .set_eip7708_config(disabled, eip8246_delayed_clear_disabled);
    }

    #[inline]
    fn transfer(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Result<Option<TransferError>, DB::Error> {
        self.inner.transfer(&mut self.database, from, to, balance)
    }

    #[inline]
    fn transfer_loaded(
        &mut self,
        from: Address,
        to: Address,
        balance: U256,
    ) -> Option<TransferError> {
        self.inner.transfer_loaded(from, to, balance)
    }

    #[inline]
    fn touch_account(&mut self, address: Address) {
        self.inner.touch(address);
    }

    #[inline]
    #[expect(deprecated)]
    fn caller_accounting_journal_entry(
        &mut self,
        address: Address,
        old_balance: U256,
        bump_nonce: bool,
    ) {
        self.inner
            .caller_accounting_journal_entry(address, old_balance, bump_nonce);
    }

    /// Increments the balance of the account.
    #[inline]
    fn balance_incr(
        &mut self,
        address: Address,
        balance: U256,
    ) -> Result<(), <Self::Database as Database>::Error> {
        self.inner
            .balance_incr(&mut self.database, address, balance)
    }

    /// Increments the nonce of the account.
    #[inline]
    #[expect(deprecated)]
    fn nonce_bump_journal_entry(&mut self, address: Address) {
        self.inner.nonce_bump_journal_entry(address)
    }

    #[inline]
    fn load_account(&mut self, address: Address) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_account(&mut self.database, address)
    }

    #[inline]
    fn load_account_mut_skip_cold_load(
        &mut self,
        address: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, JournalLoadError<DB::Error>> {
        self.inner
            .load_account_mut_optional(&mut self.database, address, skip_cold_load)
    }

    #[inline]
    fn load_account_mut_optional_code(
        &mut self,
        address: Address,
        load_code: bool,
    ) -> Result<StateLoad<Self::JournaledAccount<'_>>, DB::Error> {
        self.inner
            .load_account_mut_optional_code(&mut self.database, address, load_code, false)
            .map_err(JournalLoadError::unwrap_db_error)
    }

    #[inline]
    fn load_account_with_code(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<&Account>, DB::Error> {
        self.inner.load_code(&mut self.database, address)
    }

    #[inline]
    fn load_account_delegated(
        &mut self,
        address: Address,
    ) -> Result<StateLoad<AccountLoad>, DB::Error> {
        self.inner
            .load_account_delegated(&mut self.database, address)
    }

    #[inline]
    fn checkpoint(&mut self) -> JournalCheckpoint {
        self.inner.checkpoint()
    }

    #[inline]
    fn checkpoint_commit(&mut self) {
        self.inner.checkpoint_commit()
    }

    #[inline]
    fn checkpoint_revert(&mut self, checkpoint: JournalCheckpoint) {
        self.inner.checkpoint_revert(checkpoint)
    }

    fn warm_access_snapshot(&self) -> WarmAccessSnapshot {
        let transaction_id = self.inner.transaction_id;
        let accesses = self
            .inner
            .state
            .iter()
            .filter_map(|(address, account)| {
                if account.is_cold_transaction_id(transaction_id) {
                    return None;
                }
                let slots = account
                    .storage
                    .iter()
                    .filter_map(|(key, slot)| {
                        (!slot.is_cold_transaction_id(transaction_id)).then_some(*key)
                    })
                    .collect();
                Some((*address, slots))
            })
            .collect();
        WarmAccessSnapshot { accesses }
    }

    fn supports_eip8141(&self) -> bool {
        // Implementation capability; transaction validation checks fork activation.
        true
    }

    fn restore_warm_access_snapshot(&mut self, snapshot: &WarmAccessSnapshot) {
        let transaction_id = self.inner.transaction_id;
        for (address, slots) in &snapshot.accesses {
            if let Some(account) = self.inner.state.get_mut(address) {
                account.mark_warm_with_transaction_id(transaction_id);
                for key in slots {
                    if let Some(slot) = account.storage.get_mut(key) {
                        slot.mark_warm_with_transaction_id(transaction_id);
                    }
                }
            }
        }
    }

    fn clear_transient_storage(&mut self) {
        self.inner.transient_storage.clear();
    }

    #[inline]
    fn set_code_with_hash(&mut self, address: Address, code: Bytecode, hash: B256) {
        self.inner.set_code_with_hash(address, code, hash);
    }

    #[inline]
    fn create_account_checkpoint(
        &mut self,
        caller: Address,
        address: Address,
        balance: U256,
        spec_id: SpecId,
    ) -> Result<JournalCheckpoint, TransferError> {
        // Ignore error.
        self.inner
            .create_account_checkpoint(caller, address, balance, spec_id)
    }

    #[inline]
    fn commit_tx(&mut self) {
        self.inner.commit_tx()
    }

    #[inline]
    fn discard_tx(&mut self) {
        self.inner.discard_tx();
    }

    /// Clear current journal resetting it to initial state and return changes state.
    #[inline]
    fn finalize(&mut self) -> Self::State {
        self.inner.finalize()
    }

    #[inline]
    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner
            .sload_assume_account_present(&mut self.database, address, key, skip_cold_load)
    }

    #[inline]
    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, JournalLoadError<<Self::Database as Database>::Error>>
    {
        self.inner.sstore_assume_account_present(
            &mut self.database,
            address,
            key,
            value,
            skip_cold_load,
        )
    }

    #[inline]
    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, JournalLoadError<<Self::Database as Database>::Error>> {
        let spec = self.inner.cfg.spec;
        self.inner
            .load_account_optional(&mut self.database, address, load_code, skip_cold_load)
            .map(|a| {
                AccountInfoLoad::new(&a.data.info, a.is_cold, a.state_clear_aware_is_empty(spec))
            })
    }
}

fn eip7906_balance_changes(state: &EvmState) -> Vec<(Address, U256, U256)> {
    let mut changes = state
        .iter()
        .filter_map(|(address, account)| {
            let before = account.original_info().balance;
            let after = account.info.balance;
            (before != after).then_some((*address, before, after))
        })
        .collect::<Vec<_>>();
    changes.sort_unstable_by_key(|(address, ..)| *address);
    changes
}

fn eip7906_storage_changes(state: &EvmState) -> Vec<(Address, StorageKey, U256, U256)> {
    let mut changes = state
        .iter()
        .flat_map(|(address, account)| {
            account.changed_storage_slots().map(move |(key, slot)| {
                (*address, *key, slot.original_value(), slot.present_value())
            })
        })
        .collect::<Vec<_>>();
    changes.sort_unstable_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    changes
}

fn eip7906_deployments(state: &EvmState) -> Vec<(Address, B256)> {
    let mut deployments = state
        .iter()
        .filter_map(|(address, account)| {
            let before = account.original_info().code_hash;
            let after = account.info.code_hash;
            let is_delegation = account
                .info
                .code
                .as_ref()
                .is_some_and(|code| code.is_eip7702());
            (before == KECCAK_EMPTY && after != KECCAK_EMPTY && !is_delegation)
                .then_some((*address, after))
        })
        .collect::<Vec<_>>();
    deployments.sort_unstable_by_key(|(address, _)| *address);
    deployments
}

fn eip7906_trace_value(
    state: &EvmState,
    logs: &[Log],
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    match selector {
        TxTraceParam::BalancesChanged => Some(U256::from(eip7906_balance_changes(state).len())),
        TxTraceParam::SlotsChanged => Some(U256::from(eip7906_storage_changes(state).len())),
        TxTraceParam::ContractsDeployed => Some(U256::from(eip7906_deployments(state).len())),
        TxTraceParam::BalanceChangeAddress
        | TxTraceParam::BalanceBefore
        | TxTraceParam::BalanceAfter => eip7906_balance_trace_value(state, selector, index),
        TxTraceParam::SlotChangeAddress
        | TxTraceParam::SlotKey
        | TxTraceParam::SlotValueBefore
        | TxTraceParam::SlotValueAfter => eip7906_storage_trace_value(state, selector, index),
        TxTraceParam::DeployedAddress | TxTraceParam::DeployedCodeHash => {
            eip7906_deployment_trace_value(state, selector, index)
        }
        TxTraceParam::EventsCount => Some(U256::from(logs.len())),
        TxTraceParam::EventAddress
        | TxTraceParam::EventTopicCount
        | TxTraceParam::EventTopic0
        | TxTraceParam::EventTopic1
        | TxTraceParam::EventTopic2
        | TxTraceParam::EventTopic3
        | TxTraceParam::EventDataLength => eip7906_event_trace_value(logs, selector, index),
        TxTraceParam::GasPreCharge | TxTraceParam::GasPayerAddress => None,
    }
}

fn eip7906_balance_trace_value(
    state: &EvmState,
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    let (address, before, after) = *eip7906_balance_changes(state).get(index)?;
    Some(match selector {
        TxTraceParam::BalanceChangeAddress => U256::from_be_slice(address.as_slice()),
        TxTraceParam::BalanceBefore => before,
        TxTraceParam::BalanceAfter => after,
        _ => unreachable!("only balance selectors are dispatched here"),
    })
}

fn eip7906_storage_trace_value(
    state: &EvmState,
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    let (address, key, before, after) = *eip7906_storage_changes(state).get(index)?;
    Some(match selector {
        TxTraceParam::SlotChangeAddress => U256::from_be_slice(address.as_slice()),
        TxTraceParam::SlotKey => key,
        TxTraceParam::SlotValueBefore => before,
        TxTraceParam::SlotValueAfter => after,
        _ => unreachable!("only storage selectors are dispatched here"),
    })
}

fn eip7906_deployment_trace_value(
    state: &EvmState,
    selector: TxTraceParam,
    index: usize,
) -> Option<U256> {
    let (address, code_hash) = *eip7906_deployments(state).get(index)?;
    Some(match selector {
        TxTraceParam::DeployedAddress => U256::from_be_slice(address.as_slice()),
        TxTraceParam::DeployedCodeHash => U256::from_be_bytes(code_hash.0),
        _ => unreachable!("only deployment selectors are dispatched here"),
    })
}

fn eip7906_event_trace_value(logs: &[Log], selector: TxTraceParam, index: usize) -> Option<U256> {
    let event = logs.get(index)?;
    let topics = event.data.topics();
    Some(match selector {
        TxTraceParam::EventAddress => U256::from_be_slice(event.address.as_slice()),
        TxTraceParam::EventTopicCount => U256::from(topics.len()),
        TxTraceParam::EventTopic0 => U256::from_be_bytes(topics.first()?.0),
        TxTraceParam::EventTopic1 => U256::from_be_bytes(topics.get(1)?.0),
        TxTraceParam::EventTopic2 => U256::from_be_bytes(topics.get(2)?.0),
        TxTraceParam::EventTopic3 => U256::from_be_bytes(topics.get(3)?.0),
        TxTraceParam::EventDataLength => U256::from(event.data.data.len()),
        _ => unreachable!("only event selectors are dispatched here"),
    })
}

fn eip7906_transaction_local_value(
    state: &EvmState,
    logs: &[Log],
    selector: TxDiffParam,
    address: Address,
    operand: U256,
    local_index: U256,
) -> Option<U256> {
    match selector {
        TxDiffParam::AddressSlotsCount => {
            Some(U256::from(state.get(&address).map_or(0, |account| {
                account.changed_storage_slots().count()
            })))
        }
        TxDiffParam::AddressSlotIndex => eip7906_address_slot_index(state, address, local_index),
        TxDiffParam::AddressEventsCount => Some(U256::from(
            logs.iter().filter(|event| event.address == address).count(),
        )),
        TxDiffParam::AddressEventIndex => {
            eip7906_event_index(logs, local_index, |event| event.address == address)
        }
        TxDiffParam::AccountChangeFlags => {
            Some(U256::from(eip7906_account_change_flags(state, address)))
        }
        TxDiffParam::TopicEventsCount => {
            let topic = B256::from(operand.to_be_bytes());
            Some(U256::from(
                logs.iter()
                    .filter(|event| eip7906_event_has_indexed_topic(event, topic))
                    .count(),
            ))
        }
        TxDiffParam::TopicEventIndex => {
            let topic = B256::from(operand.to_be_bytes());
            eip7906_event_index(logs, local_index, |event| {
                eip7906_event_has_indexed_topic(event, topic)
            })
        }
        _ => unreachable!("only transaction-local selectors are dispatched here"),
    }
}

fn eip7906_address_slot_index(
    state: &EvmState,
    address: Address,
    local_index: U256,
) -> Option<U256> {
    let local_index = usize::try_from(local_index).ok()?;
    eip7906_storage_changes(state)
        .iter()
        .enumerate()
        .filter(|(_, (entry_address, ..))| *entry_address == address)
        .nth(local_index)
        .map(|(index, _)| U256::from(index))
}

fn eip7906_event_index(
    logs: &[Log],
    local_index: U256,
    matches: impl Fn(&Log) -> bool,
) -> Option<U256> {
    let local_index = usize::try_from(local_index).ok()?;
    logs.iter()
        .enumerate()
        .filter(|(_, event)| matches(event))
        .nth(local_index)
        .map(|(index, _)| U256::from(index))
}

#[inline]
fn eip7906_address(value: U256) -> Address {
    Address::from_word(B256::from(value.to_be_bytes()))
}

fn eip7906_account_change_flags(state: &EvmState, address: Address) -> u8 {
    let Some(account) = state.get(&address) else {
        return 0;
    };
    let original = account.original_info();
    let mut flags = 0;
    if original.nonce != account.info.nonce {
        flags |= ACCOUNT_NONCE_CHANGED;
    }
    if original.balance != account.info.balance {
        flags |= ACCOUNT_BALANCE_CHANGED;
    }
    if account.changed_storage_slots().next().is_some() {
        flags |= ACCOUNT_STORAGE_CHANGED;
    }
    if original.code_hash != account.info.code_hash {
        flags |= ACCOUNT_CODE_HASH_CHANGED;
    }
    flags
}

#[inline]
fn eip7906_event_has_indexed_topic(event: &Log, topic: B256) -> bool {
    event
        .data
        .topics()
        .iter()
        .skip(1)
        .any(|candidate| *candidate == topic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use context_interface::journaled_state::account::JournaledAccountTr;
    use database::{CacheDB, EmptyDB};
    use primitives::eip7906::{TxDiffParam, TxTraceParam};
    use primitives::{address, b256, LogData};

    const ACCOUNT: Address = address!("1000000000000000000000000000000000000001");
    const OTHER: Address = address!("2000000000000000000000000000000000000002");
    const UNTOUCHED: Address = address!("3000000000000000000000000000000000000003");
    const SLOT: U256 = U256::from_limbs([7, 0, 0, 0]);
    const OTHER_SLOT: U256 = U256::from_limbs([3, 0, 0, 0]);
    const TOPIC: B256 = b256!("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    fn selector(param: TxDiffParam) -> U256 {
        U256::from(u8::from(param))
    }

    fn address_word(address: Address) -> U256 {
        U256::from_be_slice(address.as_slice())
    }

    fn value(
        journal: &mut Journal<CacheDB<EmptyDB>>,
        param: TxDiffParam,
        in2: U256,
        in3: U256,
    ) -> Option<StateLoad<U256>> {
        journal
            .eip7906_txdiff(selector(param), in2, in3, false)
            .unwrap()
    }

    fn trace(journal: &Journal<CacheDB<EmptyDB>>, param: TxTraceParam, index: usize) -> U256 {
        journal
            .eip7906_txtrace(U256::from(u8::from(param)), U256::from(index))
            .unwrap()
    }

    #[test]
    fn txdiff_exposes_direct_values_views_topics_and_change_flags() {
        let before_hash = b256!("1111111111111111111111111111111111111111111111111111111111111111");
        let after_hash = b256!("2222222222222222222222222222222222222222222222222222222222222222");
        let deployed_hash =
            b256!("3333333333333333333333333333333333333333333333333333333333333333");
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(
            ACCOUNT,
            state::AccountInfo {
                balance: U256::from(10),
                nonce: 1,
                code_hash: before_hash,
                ..Default::default()
            },
        );
        db.insert_account_storage(ACCOUNT, SLOT, U256::from(9))
            .unwrap();
        db.insert_account_info(OTHER, state::AccountInfo::default());
        db.insert_account_info(
            UNTOUCHED,
            state::AccountInfo {
                balance: U256::from(44),
                ..Default::default()
            },
        );
        db.insert_account_storage(UNTOUCHED, SLOT, U256::from(55))
            .unwrap();

        let mut journal = Journal::new(db);
        {
            let mut account = journal.load_account_mut(ACCOUNT).unwrap().data;
            account.set_balance(U256::from(12));
            account.set_nonce(2);
            account.set_code(
                after_hash,
                Bytecode::new_legacy(Bytes::from_static(&[0x00])),
            );
        }
        journal.sstore(ACCOUNT, SLOT, U256::from(11)).unwrap();
        journal.load_account_mut(OTHER).unwrap().data.set_code(
            deployed_hash,
            Bytecode::new_legacy(Bytes::from_static(&[0x01])),
        );
        journal.sstore(OTHER, OTHER_SLOT, U256::from(1)).unwrap();
        journal.log(Log {
            address: ACCOUNT,
            data: LogData::new(vec![B256::ZERO, TOPIC], Bytes::from_static(&[0xaa])).unwrap(),
        });
        journal.log(Log {
            address: OTHER,
            data: LogData::new(vec![B256::ZERO, TOPIC, TOPIC], Bytes::new()).unwrap(),
        });

        let expected_trace = [
            (TxTraceParam::BalancesChanged, 0, U256::from(1)),
            (TxTraceParam::SlotsChanged, 0, U256::from(2)),
            (TxTraceParam::ContractsDeployed, 0, U256::from(1)),
            (TxTraceParam::BalanceChangeAddress, 0, address_word(ACCOUNT)),
            (TxTraceParam::BalanceBefore, 0, U256::from(10)),
            (TxTraceParam::BalanceAfter, 0, U256::from(12)),
            (TxTraceParam::SlotChangeAddress, 0, address_word(ACCOUNT)),
            (TxTraceParam::SlotKey, 0, SLOT),
            (TxTraceParam::SlotValueBefore, 0, U256::from(9)),
            (TxTraceParam::SlotValueAfter, 0, U256::from(11)),
            (TxTraceParam::SlotChangeAddress, 1, address_word(OTHER)),
            (TxTraceParam::SlotKey, 1, OTHER_SLOT),
            (TxTraceParam::DeployedAddress, 0, address_word(OTHER)),
            (
                TxTraceParam::DeployedCodeHash,
                0,
                U256::from_be_bytes(deployed_hash.0),
            ),
            (TxTraceParam::EventsCount, 0, U256::from(2)),
            (TxTraceParam::EventAddress, 0, address_word(ACCOUNT)),
            (TxTraceParam::EventTopicCount, 0, U256::from(2)),
            (TxTraceParam::EventTopic0, 0, U256::ZERO),
            (TxTraceParam::EventTopic1, 0, U256::from_be_bytes(TOPIC.0)),
            (TxTraceParam::EventDataLength, 0, U256::from(1)),
        ];
        for (param, index, expected) in expected_trace {
            assert_eq!(
                trace(&journal, param, index),
                expected,
                "{param:?}[{index}]"
            );
        }

        let account = address_word(ACCOUNT);
        assert_eq!(
            value(&mut journal, TxDiffParam::SlotValueBefore, account, SLOT)
                .unwrap()
                .data,
            U256::from(9)
        );
        assert_eq!(
            value(&mut journal, TxDiffParam::SlotValueAfter, account, SLOT)
                .unwrap()
                .data,
            U256::from(11)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::BalanceBefore,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from(10)
        );
        assert_eq!(
            value(&mut journal, TxDiffParam::BalanceAfter, account, U256::ZERO)
                .unwrap()
                .data,
            U256::from(12)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::CodeHashBefore,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from_be_bytes(before_hash.0)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::CodeHashAfter,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from_be_bytes(after_hash.0)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::AddressSlotsCount,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from(1)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::AddressSlotIndex,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::ZERO
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::AddressEventsCount,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from(1)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::AddressEventIndex,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::ZERO
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::AccountChangeFlags,
                account,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from(0x0f)
        );

        let topic = U256::from_be_bytes(TOPIC.0);
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::TopicEventsCount,
                topic,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from(2)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::TopicEventIndex,
                topic,
                U256::from(1)
            )
            .unwrap()
            .data,
            U256::from(1)
        );

        let untouched = address_word(UNTOUCHED);
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::AccountChangeFlags,
                untouched,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::ZERO
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::BalanceBefore,
                untouched,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from(44)
        );
        assert_eq!(
            value(
                &mut journal,
                TxDiffParam::BalanceAfter,
                untouched,
                U256::ZERO
            )
            .unwrap()
            .data,
            U256::from(44)
        );
    }

    #[test]
    fn txdiff_validates_operands_and_preserves_cold_load_semantics() {
        let mut db = CacheDB::<EmptyDB>::default();
        db.insert_account_info(UNTOUCHED, state::AccountInfo::default());
        db.insert_account_storage(UNTOUCHED, SLOT, U256::from(55))
            .unwrap();
        let mut journal = Journal::new(db);
        let address = address_word(UNTOUCHED);

        assert!(journal
            .eip7906_txdiff(
                selector(TxDiffParam::BalanceBefore),
                address,
                U256::from(1),
                false,
            )
            .unwrap()
            .is_none());
        assert!(journal
            .eip7906_txdiff(
                selector(TxDiffParam::AddressSlotIndex),
                address,
                U256::from(1),
                false,
            )
            .unwrap()
            .is_none());
        assert!(journal
            .eip7906_txdiff(U256::from(0xff), address, U256::ZERO, false)
            .unwrap()
            .is_none());

        let error = journal
            .eip7906_txdiff(selector(TxDiffParam::SlotValueBefore), address, SLOT, true)
            .unwrap_err();
        assert!(error.is_cold_load_skipped());

        let cold = value(&mut journal, TxDiffParam::SlotValueBefore, address, SLOT).unwrap();
        assert!(cold.is_cold);
        assert_eq!(cold.data, U256::from(55));
        let warm = value(&mut journal, TxDiffParam::SlotValueAfter, address, SLOT).unwrap();
        assert!(!warm.is_cold);
        assert_eq!(warm.data, U256::from(55));
    }
}
