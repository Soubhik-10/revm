//! This module contains [`Context`] struct and implements [`ContextTr`] trait for it.
use crate::{block::BlockEnv, cfg::CfgEnv, journal::Journal, tx::TxEnv, LocalContext};
use context_interface::{
    cfg::GasParams,
    context::{ContextError, ContextSetters, SStoreResult, SelfDestructResult, StateLoad},
    host::{FrameHostError, LoadError},
    journaled_state::{account::JournaledAccountTr, AccountInfoLoad},
    Block, Cfg, ContextTr, Host, JournalTr, LocalContextTr, Transaction, TransactionType,
};
use database_interface::{Database, DatabaseRef, EmptyDB, WrapDatabaseRef};
use derive_where::derive_where;
use primitives::{
    hardfork::SpecId, hints_util::cold_path, Address, Bytes, Log, StorageKey, StorageValue, B256,
    U256,
};

/// EVM context contains data that EVM needs for execution.
#[derive_where(Clone, Debug; BLOCK, CFG, CHAIN, TX, DB, JOURNAL, <DB as Database>::Error, LOCAL)]
pub struct Context<
    BLOCK = BlockEnv,
    TX = TxEnv,
    CFG = CfgEnv,
    DB: Database = EmptyDB,
    JOURNAL: JournalTr<Database = DB> = Journal<DB>,
    CHAIN = (),
    LOCAL: LocalContextTr = LocalContext,
> {
    /// Block information.
    pub block: BLOCK,
    /// Transaction information.
    pub tx: TX,
    /// Configurations.
    pub cfg: CFG,
    /// EVM State with journaling support and database.
    pub journaled_state: JOURNAL,
    /// Inner context.
    pub chain: CHAIN,
    /// Local context that is filled by execution.
    pub local: LOCAL,
    /// Error that happened during execution.
    pub error: Result<(), ContextError<DB::Error>>,
}

#[inline]
fn sync_cfg_to_journal<CFG: Cfg, JOURNAL: JournalTr>(cfg: &CFG, journal: &mut JOURNAL) {
    journal.set_spec_id(cfg.spec().into());
    journal.set_eip7708_config(
        cfg.is_eip7708_disabled(),
        cfg.is_eip8246_delayed_clear_disabled(),
    );
}

impl<
        BLOCK: Block,
        TX: Transaction,
        DB: Database,
        CFG: Cfg,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN,
        LOCAL: LocalContextTr,
    > ContextTr for Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
{
    type Block = BLOCK;
    type Tx = TX;
    type Cfg = CFG;
    type Db = DB;
    type Journal = JOURNAL;
    type Chain = CHAIN;
    type Local = LOCAL;

    #[inline]
    fn all(
        &self,
    ) -> (
        &Self::Block,
        &Self::Tx,
        &Self::Cfg,
        &Self::Db,
        &Self::Journal,
        &Self::Chain,
        &Self::Local,
    ) {
        let block = &self.block;
        let tx = &self.tx;
        let cfg = &self.cfg;
        let db = self.journaled_state.db();
        let journal = &self.journaled_state;
        let chain = &self.chain;
        let local = &self.local;

        (block, tx, cfg, db, journal, chain, local)
    }

    #[inline]
    fn all_mut(
        &mut self,
    ) -> (
        &Self::Block,
        &Self::Tx,
        &Self::Cfg,
        &mut Self::Journal,
        &mut Self::Chain,
        &mut Self::Local,
    ) {
        let block = &self.block;
        let tx = &self.tx;
        let cfg = &self.cfg;
        let journal = &mut self.journaled_state;
        let chain = &mut self.chain;
        let local = &mut self.local;

        (block, tx, cfg, journal, chain, local)
    }

    #[inline]
    fn error(&mut self) -> &mut Result<(), ContextError<<Self::Db as Database>::Error>> {
        &mut self.error
    }
}

impl<
        BLOCK: Block,
        TX: Transaction,
        DB: Database,
        CFG: Cfg,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN,
        LOCAL: LocalContextTr,
    > ContextSetters for Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
{
    fn set_tx(&mut self, tx: Self::Tx) {
        self.tx = tx;
    }

    fn set_block(&mut self, block: Self::Block) {
        self.block = block;
    }
}

impl<
        BLOCK: Block + Default,
        TX: Transaction + Default,
        DB: Database,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN: Default,
        LOCAL: LocalContextTr + Default,
        SPEC: Default + Into<SpecId> + Clone,
    > Context<BLOCK, TX, CfgEnv<SPEC>, DB, JOURNAL, CHAIN, LOCAL>
{
    /// Creates a new context with a new database type.
    ///
    /// This will create a new [`Journal`] object.
    pub fn new(db: DB, spec: SPEC) -> Self {
        let cfg = CfgEnv::new_with_spec(spec);
        let mut journaled_state = JOURNAL::new(db);
        sync_cfg_to_journal(&cfg, &mut journaled_state);
        Self {
            tx: TX::default(),
            block: BLOCK::default(),
            cfg,
            local: LOCAL::default(),
            journaled_state,
            chain: Default::default(),
            error: Ok(()),
        }
    }
}

impl<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL> Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
where
    BLOCK: Block,
    TX: Transaction,
    CFG: Cfg,
    DB: Database,
    JOURNAL: JournalTr<Database = DB>,
    LOCAL: LocalContextTr,
{
    /// Creates a new context with a new journal type. New journal needs to have the same database type.
    pub fn with_new_journal<OJOURNAL: JournalTr<Database = DB>>(
        self,
        mut journal: OJOURNAL,
    ) -> Context<BLOCK, TX, CFG, DB, OJOURNAL, CHAIN, LOCAL> {
        sync_cfg_to_journal(&self.cfg, &mut journal);
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: journal,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new database type.
    ///
    /// This will create a new [`Journal`] object.
    pub fn with_db<ODB: Database>(
        self,
        db: ODB,
    ) -> Context<BLOCK, TX, CFG, ODB, Journal<ODB>, CHAIN, LOCAL> {
        let mut journaled_state = Journal::new(db);
        sync_cfg_to_journal(&self.cfg, &mut journaled_state);
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new `DatabaseRef` type.
    pub fn with_ref_db<ODB: DatabaseRef>(
        self,
        db: ODB,
    ) -> Context<BLOCK, TX, CFG, WrapDatabaseRef<ODB>, Journal<WrapDatabaseRef<ODB>>, CHAIN, LOCAL>
    {
        let mut journaled_state = Journal::new(WrapDatabaseRef(db));
        sync_cfg_to_journal(&self.cfg, &mut journaled_state);
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new block type.
    pub fn with_block<OB: Block>(
        self,
        block: OB,
    ) -> Context<OB, TX, CFG, DB, JOURNAL, CHAIN, LOCAL> {
        Context {
            tx: self.tx,
            block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }
    /// Creates a new context with a new transaction type.
    pub fn with_tx<OTX: Transaction>(
        self,
        tx: OTX,
    ) -> Context<BLOCK, OTX, CFG, DB, JOURNAL, CHAIN, LOCAL> {
        Context {
            tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new chain type.
    pub fn with_chain<OC>(self, chain: OC) -> Context<BLOCK, TX, CFG, DB, JOURNAL, OC, LOCAL> {
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new chain type.
    pub fn with_cfg<OCFG: Cfg>(
        mut self,
        cfg: OCFG,
    ) -> Context<BLOCK, TX, OCFG, DB, JOURNAL, CHAIN, LOCAL> {
        sync_cfg_to_journal(&cfg, &mut self.journaled_state);
        Context {
            tx: self.tx,
            block: self.block,
            cfg,
            journaled_state: self.journaled_state,
            local: self.local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Creates a new context with a new local context type.
    pub fn with_local<OL: LocalContextTr>(
        self,
        local: OL,
    ) -> Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, OL> {
        Context {
            tx: self.tx,
            block: self.block,
            cfg: self.cfg,
            journaled_state: self.journaled_state,
            local,
            chain: self.chain,
            error: Ok(()),
        }
    }

    /// Modifies the context configuration.
    #[must_use]
    pub fn modify_cfg_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut CFG),
    {
        f(&mut self.cfg);
        sync_cfg_to_journal(&self.cfg, &mut self.journaled_state);
        self
    }

    /// Modifies the context block.
    #[must_use]
    pub fn modify_block_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut BLOCK),
    {
        self.modify_block(f);
        self
    }

    /// Modifies the context transaction.
    #[must_use]
    pub fn modify_tx_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut TX),
    {
        self.modify_tx(f);
        self
    }

    /// Modifies the context chain.
    #[must_use]
    pub fn modify_chain_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut CHAIN),
    {
        self.modify_chain(f);
        self
    }

    /// Modifies the context database.
    #[must_use]
    pub fn modify_db_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut DB),
    {
        self.modify_db(f);
        self
    }

    /// Modifies the context journal.
    #[must_use]
    pub fn modify_journal_chained<F>(mut self, f: F) -> Self
    where
        F: FnOnce(&mut JOURNAL),
    {
        self.modify_journal(f);
        self
    }

    /// Modifies the context block.
    pub fn modify_block<F>(&mut self, f: F)
    where
        F: FnOnce(&mut BLOCK),
    {
        f(&mut self.block);
    }

    /// Modifies the context transaction.
    pub fn modify_tx<F>(&mut self, f: F)
    where
        F: FnOnce(&mut TX),
    {
        f(&mut self.tx);
    }

    /// Modifies the context configuration.
    pub fn modify_cfg<F>(&mut self, f: F)
    where
        F: FnOnce(&mut CFG),
    {
        f(&mut self.cfg);
        sync_cfg_to_journal(&self.cfg, &mut self.journaled_state);
    }

    /// Modifies the context chain.
    pub fn modify_chain<F>(&mut self, f: F)
    where
        F: FnOnce(&mut CHAIN),
    {
        f(&mut self.chain);
    }

    /// Modifies the context database.
    pub fn modify_db<F>(&mut self, f: F)
    where
        F: FnOnce(&mut DB),
    {
        f(self.journaled_state.db_mut());
    }

    /// Modifies the context journal.
    pub fn modify_journal<F>(&mut self, f: F)
    where
        F: FnOnce(&mut JOURNAL),
    {
        f(&mut self.journaled_state);
    }

    /// Modifies the local context.
    pub fn modify_local<F>(&mut self, f: F)
    where
        F: FnOnce(&mut LOCAL),
    {
        f(&mut self.local);
    }
}

impl<
        BLOCK: Block,
        TX: Transaction,
        CFG: Cfg,
        DB: Database,
        JOURNAL: JournalTr<Database = DB>,
        CHAIN,
        LOCAL: LocalContextTr,
    > Host for Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN, LOCAL>
{
    /* Block */

    fn basefee(&self) -> U256 {
        U256::from(self.block().basefee())
    }

    fn blob_gasprice(&self) -> U256 {
        U256::from(self.block().blob_gasprice().unwrap_or(0))
    }

    fn gas_limit(&self) -> U256 {
        U256::from(self.block().gas_limit())
    }

    fn difficulty(&self) -> U256 {
        self.block().difficulty()
    }

    fn prevrandao(&self) -> Option<U256> {
        self.block().prevrandao().map(|r| r.into())
    }

    #[inline]
    fn gas_params(&self) -> &GasParams {
        self.cfg().gas_params()
    }

    fn is_amsterdam_eip8037_enabled(&self) -> bool {
        self.cfg().is_amsterdam_eip8037_enabled()
    }

    fn block_number(&self) -> U256 {
        self.block().number()
    }

    fn timestamp(&self) -> U256 {
        U256::from(self.block().timestamp())
    }

    fn beneficiary(&self) -> Address {
        self.block().beneficiary()
    }

    fn slot_num(&self) -> U256 {
        U256::from(self.block().slot_num())
    }

    fn chain_id(&self) -> U256 {
        U256::from(self.cfg().chain_id())
    }

    /* Transaction */

    fn effective_gas_price(&self) -> U256 {
        let basefee = self.block().basefee();
        U256::from(self.tx().effective_gas_price(basefee as u128))
    }

    fn caller(&self) -> Address {
        if let (Some(frame_tx), Some(runtime)) = (
            self.tx().frame_transaction(),
            self.local().frame_transaction(),
        ) {
            return match frame_tx
                .frames
                .get(runtime.current_frame_index)
                .map(|frame| frame.mode)
            {
                Some(alloy_eip8141::FrameMode::Sender) => self.tx().caller(),
                Some(_) => alloy_eip8141::ENTRY_POINT,
                None => self.tx().caller(),
            };
        }
        self.tx().caller()
    }

    fn blob_hash(&self, number: usize) -> Option<U256> {
        let tx = &self.tx();
        if tx.tx_type() != TransactionType::Eip4844 && tx.tx_type() != TransactionType::Eip8141 {
            return None;
        }
        tx.blob_versioned_hashes()
            .get(number)
            .map(|t| U256::from_be_bytes(t.0))
    }

    fn frame_tx_param(&self, param: U256) -> Option<U256> {
        let tx = self.tx();
        let frame_tx = tx.frame_transaction()?;
        let runtime = self.local().frame_transaction()?;
        Some(match param {
            p if p == U256::from(0) => U256::from(0x06),
            p if p == U256::from(1) => U256::from(tx.nonce()),
            p if p == U256::from(2) => U256::from_be_slice(tx.caller().as_slice()),
            p if p == U256::from(3) => U256::from(tx.max_priority_fee_per_gas()?),
            p if p == U256::from(4) => U256::from(tx.max_fee_per_gas()),
            p if p == U256::from(5) => U256::from(tx.max_fee_per_blob_gas()),
            p if p == U256::from(6) => frame_tx.max_cost(
                tx.max_fee_per_gas(),
                tx.total_blob_gas(),
                self.block().blob_gasprice().unwrap_or_default(),
            ),
            p if p == U256::from(7) => U256::from(tx.blob_versioned_hashes().len()),
            p if p == U256::from(8) => U256::from_be_bytes(frame_tx.signature_hash.0),
            p if p == U256::from(9) => U256::from(frame_tx.frames.len()),
            p if p == U256::from(10) => U256::from(runtime.current_frame_index),
            p if p == U256::from(11) => U256::from(frame_tx.signatures.len()),
            _ => return None,
        })
    }

    fn frame_data(&self, frame_index: U256) -> Option<Bytes> {
        let index = usize::try_from(frame_index).ok()?;
        self.tx()
            .frame_transaction()?
            .frames
            .get(index)
            .map(|frame| frame.data.clone())
    }

    fn frame_param(&self, frame_index: U256, param: U256) -> Option<U256> {
        let index = usize::try_from(frame_index).ok()?;
        let tx = self.tx();
        let frame_tx = tx.frame_transaction()?;
        let runtime = self.local().frame_transaction()?;
        let frame = frame_tx.frames.get(index)?;
        let target = frame
            .target_address()
            .or_else(|| frame.target.is_empty().then_some(tx.caller()))?;
        Some(match param {
            p if p == U256::from(0) => U256::from_be_slice(target.as_slice()),
            p if p == U256::from(1) => U256::from(frame.gas_limit),
            p if p == U256::from(2) => U256::from(u8::from(frame.mode)),
            p if p == U256::from(3) => U256::from(frame.flags),
            p if p == U256::from(4) => U256::from(frame.data.len()),
            p if p == U256::from(5) => {
                if index >= runtime.current_frame_index {
                    return None;
                }
                U256::from(u8::from(*runtime.statuses.get(index)?))
            }
            p if p == U256::from(6) => U256::from(frame.allowed_scope()),
            p if p == U256::from(7) => U256::from(frame.is_atomic_batch() as u8),
            p if p == U256::from(8) => frame.value,
            _ => return None,
        })
    }

    fn frame_signature_param(&self, signature_index: U256, param: U256) -> Option<U256> {
        let index = usize::try_from(signature_index).ok()?;
        let tx = self.tx();
        let signature = tx.frame_transaction()?.signatures.get(index)?;
        Some(match param {
            p if p == U256::from(0) => {
                if signature.scheme == alloy_eip8141::SignatureScheme::Arbitrary {
                    return None;
                }
                let signer = if signature.signer.is_empty() {
                    tx.caller()
                } else {
                    signature.signer_address()?
                };
                U256::from_be_slice(signer.as_slice())
            }
            p if p == U256::from(1) => U256::from(u8::from(signature.scheme)),
            p if p == U256::from(2) => {
                if signature.msg.is_empty() {
                    U256::ZERO
                } else {
                    U256::from_be_slice(&signature.msg)
                }
            }
            p if p == U256::from(3) => U256::from(signature.signature.len()),
            _ => return None,
        })
    }

    fn frame_signature_bytes(&self, signature_index: U256) -> Option<Bytes> {
        let index = usize::try_from(signature_index).ok()?;
        let signature = self.tx().frame_transaction()?.signatures.get(index)?;
        (signature.scheme == alloy_eip8141::SignatureScheme::Arbitrary)
            .then(|| signature.signature.clone())
    }

    fn approve_frame(
        &mut self,
        current_target: Address,
        scope: U256,
    ) -> Result<(), FrameHostError> {
        let (resolved_target, current_frame_index, current) = {
            let runtime = self
                .local()
                .frame_transaction()
                .ok_or(FrameHostError::Invalid)?;
            (
                runtime.resolved_target,
                runtime.current_frame_index,
                runtime
                    .approval_stack
                    .last()
                    .copied()
                    .ok_or(FrameHostError::Invalid)?,
            )
        };
        if current_target != resolved_target || scope > U256::from(u8::MAX) {
            return Err(FrameHostError::Revert);
        }

        let (sender, allowed_scope, max_cost) = {
            let tx = self.tx();
            let frame_tx = tx.frame_transaction().ok_or(FrameHostError::Invalid)?;
            let frame = frame_tx
                .frames
                .get(current_frame_index)
                .ok_or(FrameHostError::Invalid)?;
            (
                tx.caller(),
                frame.allowed_scope(),
                frame_tx.max_cost(
                    tx.max_fee_per_gas(),
                    tx.total_blob_gas(),
                    self.block().blob_gasprice().unwrap_or_default(),
                ),
            )
        };
        let scope = u8::try_from(scope).map_err(|_| FrameHostError::Revert)?;
        if scope == 0 || scope & !allowed_scope != 0 {
            return Err(FrameHostError::Revert);
        }
        let approves_payment = scope & 0x01 != 0;
        let approves_execution = scope & 0x02 != 0;
        if approves_execution && (current.sender_approved || resolved_target != sender) {
            return Err(FrameHostError::Revert);
        }
        if approves_payment
            && (current.payer.is_some() || (!current.sender_approved && !approves_execution))
        {
            return Err(FrameHostError::Revert);
        }

        if approves_payment {
            let balance_check_disabled = self.cfg().is_balance_check_disabled();
            let fee_charge_disabled = self.cfg().is_fee_charge_disabled();
            let payer_balance_result = self
                .journal_mut()
                .load_account_mut(resolved_target)
                .map(|account| *account.balance());
            let payer_balance = match payer_balance_result {
                Ok(balance) => balance,
                Err(error) => {
                    *self.error() = Err(error.into());
                    return Err(FrameHostError::Fatal);
                }
            };
            if !balance_check_disabled && payer_balance < max_cost {
                return Err(FrameHostError::Revert);
            }
            if balance_check_disabled && payer_balance < max_cost {
                let result = self
                    .journal_mut()
                    .load_account_mut(resolved_target)
                    .map(|mut account| account.incr_balance(max_cost - payer_balance));
                if let Err(error) = result {
                    *self.error() = Err(error.into());
                    return Err(FrameHostError::Fatal);
                }
            }
            let bump_result = self
                .journal_mut()
                .load_account_mut(sender)
                .map(|mut account| account.bump_nonce());
            let bumped = match bump_result {
                Ok(bumped) => bumped,
                Err(error) => {
                    *self.error() = Err(error.into());
                    return Err(FrameHostError::Fatal);
                }
            };
            if !bumped {
                return Err(FrameHostError::Revert);
            }
            if !fee_charge_disabled {
                let result = self
                    .journal_mut()
                    .load_account_mut(resolved_target)
                    .map(|mut account| account.decr_balance(max_cost));
                if let Err(error) = result {
                    *self.error() = Err(error.into());
                    return Err(FrameHostError::Fatal);
                }
            }
        }

        let runtime = self
            .local_mut()
            .frame_transaction_mut()
            .ok_or(FrameHostError::Invalid)?;
        let approval = runtime
            .approval_stack
            .last_mut()
            .ok_or(FrameHostError::Invalid)?;
        tracing::info!(
            target: "revm::eip8141",
            frame_index = current_frame_index,
            target = ?resolved_target,
            scope,
            approves_payment,
            approves_execution,
            max_cost = ?max_cost,
            "Applying EIP-8141 frame approval"
        );
        *approval = context_interface::local::FrameApprovalState {
            payer: if approves_payment {
                Some(resolved_target)
            } else {
                current.payer
            },
            sender_approved: current.sender_approved || approves_execution,
        };
        Ok(())
    }

    /* Config */

    fn max_initcode_size(&self) -> usize {
        self.cfg().max_initcode_size()
    }

    /* Database */

    fn block_hash(&mut self, requested_number: u64) -> Option<B256> {
        self.db_mut()
            .block_hash(requested_number)
            .map_err(|e| {
                cold_path();
                *self.error() = Err(e.into());
            })
            .ok()
    }

    /* Journal */

    /// Gets the transient storage value of `address` at `index`.
    fn tload(&mut self, address: Address, index: StorageKey) -> StorageValue {
        self.journal_mut().tload(address, index)
    }

    /// Sets the transient storage value of `address` at `index`.
    fn tstore(&mut self, address: Address, index: StorageKey, value: StorageValue) {
        self.journal_mut().tstore(address, index, value)
    }

    /// Emits a log owned by `address` with given `LogData`.
    fn log(&mut self, log: Log) {
        self.journal_mut().log(log);
    }

    /// Marks `address` to be deleted, with funds transferred to `target`.
    #[inline]
    fn selfdestruct(
        &mut self,
        address: Address,
        target: Address,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SelfDestructResult>, LoadError> {
        self.journal_mut()
            .selfdestruct(address, target, skip_cold_load)
            .map_err(|e| {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    *self.error() = Err(err.into());
                }
                ret
            })
    }

    #[inline]
    fn sstore_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        value: StorageValue,
        skip_cold_load: bool,
    ) -> Result<StateLoad<SStoreResult>, LoadError> {
        self.journal_mut()
            .sstore_skip_cold_load(address, key, value, skip_cold_load)
            .map_err(|e| {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    *self.error() = Err(err.into());
                }
                ret
            })
    }

    #[inline]
    fn sload_skip_cold_load(
        &mut self,
        address: Address,
        key: StorageKey,
        skip_cold_load: bool,
    ) -> Result<StateLoad<StorageValue>, LoadError> {
        self.journal_mut()
            .sload_skip_cold_load(address, key, skip_cold_load)
            .map_err(|e| {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    *self.error() = Err(err.into());
                }
                ret
            })
    }

    #[inline]
    fn load_account_info_skip_cold_load(
        &mut self,
        address: Address,
        load_code: bool,
        skip_cold_load: bool,
    ) -> Result<AccountInfoLoad<'_>, LoadError> {
        match self.journaled_state.load_account_info_skip_cold_load(
            address,
            load_code,
            skip_cold_load,
        ) {
            Ok(a) => Ok(a),
            Err(e) => {
                cold_path();
                let (ret, err) = e.into_parts();
                if let Some(err) = err {
                    self.error = Err(err.into());
                }
                Err(ret)
            }
        }
    }
}
