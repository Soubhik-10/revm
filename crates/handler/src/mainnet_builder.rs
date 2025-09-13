use crate::{frame::EthFrame, instructions::EthInstructions, EthPrecompiles};
use context::{BlockEnv, Cfg, CfgEnv, Context, Evm, FrameStack, Journal, TxEnv};
use context_interface::{Block, Database, JournalTr, Transaction};
use database_interface::EmptyDB;
use interpreter::interpreter::EthInterpreter;
use primitives::hardfork::SpecId;

/// Type alias for a mainnet EVM instance with standard Ethereum components.
pub type MainnetEvm<CTX, INSP = ()> =
    Evm<CTX, INSP, EthInstructions<EthInterpreter, CTX>, EthPrecompiles, EthFrame<EthInterpreter>>;

/// Type alias for a mainnet context with standard Ethereum environment types.
pub type MainnetContext<DB> = Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, ()>;

/// Trait for building mainnet EVM instances from contexts.
pub trait MainBuilder: Sized {
    /// The context type that will be used in the EVM.
    type Context;

    /// Builds a mainnet EVM instance without an inspector.
    fn build_mainnet(self) -> MainnetEvm<Self::Context>;

    /// Builds a mainnet EVM instance with the provided inspector.
    fn build_mainnet_with_inspector<INSP>(self, inspector: INSP)
        -> MainnetEvm<Self::Context, INSP>;
}

impl<BLOCK, TX, CFG, DB, JOURNAL, CHAIN> MainBuilder for Context<BLOCK, TX, CFG, DB, JOURNAL, CHAIN>
where
    BLOCK: Block,
    TX: Transaction,
    CFG: Cfg,
    DB: Database,
    JOURNAL: JournalTr<Database = DB>,
{
    type Context = Self;

    fn build_mainnet(self) -> MainnetEvm<Self::Context> {
        Evm {
            ctx: self,
            inspector: (),
            instruction: EthInstructions::default(),
            precompiles: EthPrecompiles::default(),
            frame_stack: FrameStack::new(),
        }
    }

    fn build_mainnet_with_inspector<INSP>(
        self,
        inspector: INSP,
    ) -> MainnetEvm<Self::Context, INSP> {
        Evm {
            ctx: self,
            inspector,
            instruction: EthInstructions::default(),
            precompiles: EthPrecompiles::default(),
            frame_stack: FrameStack::new(),
        }
    }
}

/// Trait used to initialize Context with default mainnet types.
pub trait MainContext {
    /// Creates a new mainnet context with default configuration.
    fn mainnet() -> Self;
}

impl MainContext for Context<BlockEnv, TxEnv, CfgEnv, EmptyDB, Journal<EmptyDB>, ()> {
    fn mainnet() -> Self {
        Context::new(EmptyDB::new(), SpecId::default())
    }
}

#[cfg(test)]
mod test {
    use crate::ExecuteEvm;
    use crate::{MainBuilder, MainContext};
    use alloy_signer::{Either, SignerSync};
    use alloy_signer_local::PrivateKeySigner;
    use bytecode::{
        opcode::{PUSH1, SSTORE},
        Bytecode,
    };
    use context::{Context, TxEnv};
    use context_interface::transaction::Authorization;
    use database::{BenchmarkDB, EEADDRESS, FFADDRESS};
    use primitives::{hardfork::SpecId, TxKind, U256};
    use primitives::{StorageKey, StorageValue};

    #[test]
    fn sanity_eip7702_tx() {
        let signer = PrivateKeySigner::random();
        let auth = Authorization {
            chain_id: U256::ZERO,
            nonce: 0,
            address: FFADDRESS,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let auth = auth.into_signed(signature);

        let bytecode = Bytecode::new_legacy([PUSH1, 0x01, PUSH1, 0x01, SSTORE].into());

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        let state = evm
            .transact(
                TxEnv::builder()
                    .gas_limit(100_000)
                    .authorization_list(vec![Either::Left(auth)])
                    .caller(EEADDRESS)
                    .kind(TxKind::Call(signer.address()))
                    .build()
                    .unwrap(),
            )
            .unwrap()
            .state;

        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(
            auth_acc
                .storage
                .get(&StorageKey::from(1))
                .unwrap()
                .present_value,
            StorageValue::from(1)
        );
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn storage_access_sstore_write_read_same_slot() {
        use bytecode::opcode::STOP;

        let signer = PrivateKeySigner::random();

        let auth = Authorization {
            chain_id: U256::ZERO,
            nonce: 0,
            address: FFADDRESS,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let auth = auth.into_signed(signature);

        //SSTORE 0x42 in 0x01 and SLOAD 0x01
        let bytecode = Bytecode::new_legacy(
            vec![
                PUSH1,
                0x42,
                PUSH1,
                0x01,
                SSTORE,
                PUSH1,
                0x01,
                bytecode::opcode::SLOAD,
                STOP,
            ]
            .into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        let result = evm
            .transact(
                TxEnv::builder()
                    .gas_limit(100_000)
                    .authorization_list(vec![Either::Left(auth)])
                    .caller(EEADDRESS)
                    .kind(TxKind::Call(signer.address()))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let state = result.state;
        // As per the EIP it should be stored in both writes and reads.
        let expected_storage_access = state::StorageAccess {
            reads: {
                let mut reads = std::collections::BTreeSet::new();
                reads.insert(U256::from(1));
                reads
            },
            writes: {
                let mut writes = std::collections::BTreeMap::new();
                writes.insert(U256::from(1), (U256::ZERO, U256::from(66)));
                writes
            },
        };
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access)
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn storage_access_sstore_write_same_value() {
        let signer = PrivateKeySigner::random();

        let auth = Authorization {
            chain_id: U256::ZERO,
            nonce: 0,
            address: FFADDRESS,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let auth = auth.into_signed(signature);

        //SSTORE 0x42 in 0x01 and change it again to 0x42
        let bytecode = Bytecode::new_legacy(
            vec![
                PUSH1,
                0x42,
                PUSH1,
                0x01,
                SSTORE,
                PUSH1,
                0x42,
                PUSH1,
                0x01,
                SSTORE,
                bytecode::opcode::STOP,
            ]
            .into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        let result = evm
            .transact(
                TxEnv::builder()
                    .gas_limit(100_000)
                    .authorization_list(vec![Either::Left(auth)])
                    .caller(EEADDRESS)
                    .kind(TxKind::Call(signer.address()))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let state = result.state;
        // As per the EIP it should be stored in reads and writes since sstore first changes 0->66(writes) then try to change 66->66(reads).
        let expected_storage_access = state::StorageAccess {
            reads: {
                let mut reads = std::collections::BTreeSet::new();
                reads.insert(U256::from(1));
                reads
            },
            writes: {
                let mut writes = std::collections::BTreeMap::new();
                writes.insert(U256::from(1), (U256::ZERO, U256::from(66)));
                writes
            },
        };
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access)
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn storage_access_sstore_with_zero() {
        let signer = PrivateKeySigner::random();

        let auth = Authorization {
            chain_id: U256::ZERO,
            nonce: 0,
            address: FFADDRESS,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let auth = auth.into_signed(signature);

        //SSTORE 0x42 in 0x01 and change it  to 0x00
        let bytecode = Bytecode::new_legacy(
            vec![
                PUSH1,
                0x42,
                PUSH1,
                0x01,
                SSTORE,
                PUSH1,
                0x00,
                PUSH1,
                0x01,
                SSTORE,
                bytecode::opcode::STOP,
            ]
            .into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        let result = evm
            .transact(
                TxEnv::builder()
                    .gas_limit(100_000)
                    .authorization_list(vec![Either::Left(auth)])
                    .caller(EEADDRESS)
                    .kind(TxKind::Call(signer.address()))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let state = result.state;
        // As per the EIP it should be stored in writes since sstore first changes 0->66(writes) then  change 66->0(writes).
        let expected_storage_access = state::StorageAccess {
            reads: {
                use std::collections::BTreeSet;
                BTreeSet::new()
            },
            writes: {
                let mut writes = std::collections::BTreeMap::new();
                writes.insert(U256::from(1), (U256::from(66), U256::ZERO));
                writes
            },
        };
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access)
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn storage_access_unchanged() {
        let signer = PrivateKeySigner::random();

        let auth = Authorization {
            chain_id: U256::ZERO,
            nonce: 0,
            address: FFADDRESS,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let auth = auth.into_signed(signature);

        // PUSH20 ADDRESS AND EXTCODEHASH,EXTCODESIZE,BALANCE
        let bytecode = Bytecode::new_legacy(
            vec![
                bytecode::opcode::PUSH20,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                0xFF,
                bytecode::opcode::DUP1,
                bytecode::opcode::EXTCODEHASH,
                bytecode::opcode::DUP2,
                bytecode::opcode::EXTCODESIZE,
                bytecode::opcode::DUP3,
                bytecode::opcode::BALANCE,
                bytecode::opcode::STOP,
            ]
            .into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        // As per the EIP it should not be stored.
        let expected_storage_access = state::StorageAccess {
            reads: { std::collections::BTreeSet::new() },
            writes: { std::collections::BTreeMap::new() },
        };
        let result = evm
            .transact(
                TxEnv::builder()
                    .gas_limit(100_000)
                    .authorization_list(vec![Either::Left(auth)])
                    .caller(EEADDRESS)
                    .kind(TxKind::Call(signer.address()))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let state = result.state;
        let auth_acc = state.get(&signer.address()).unwrap();
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access)
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn storage_access_with_staticcall() {
        let signer = PrivateKeySigner::random();

        let auth = Authorization {
            chain_id: U256::ZERO,
            nonce: 0,
            address: FFADDRESS,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let auth = auth.into_signed(signature);

        //Passes STATICCALL
        let bytecode = Bytecode::new_legacy(
            vec![
                PUSH1,
                0x20,
                PUSH1,
                0x00,
                PUSH1,
                0x20,
                PUSH1,
                0x00,
                bytecode::opcode::PUSH20,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x00,
                0x12,
                0x34,
                bytecode::opcode::PUSH2,
                0xFF,
                0xFF,
                bytecode::opcode::STATICCALL,
                bytecode::opcode::STOP,
            ]
            .into(),
        );
        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        let result = evm
            .transact(
                TxEnv::builder()
                    .gas_limit(100_000)
                    .authorization_list(vec![Either::Left(auth)])
                    .caller(EEADDRESS)
                    .kind(TxKind::Call(signer.address()))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let state = result.state;
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        // As per the EIP it should not be stored.
        let expected_storage_access = state::StorageAccess {
            reads: { std::collections::BTreeSet::new() },
            writes: { std::collections::BTreeMap::new() },
        };
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access);
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn storage_access_with_revert() {
        let signer = PrivateKeySigner::random();

        let auth = Authorization {
            chain_id: U256::ZERO,
            nonce: 0,
            address: FFADDRESS,
        };
        let signature = signer.sign_hash_sync(&auth.signature_hash()).unwrap();
        let auth = auth.into_signed(signature);

        //Passes REVERT
        let bytecode = Bytecode::new_legacy(
            vec![
                PUSH1,
                0x42,
                PUSH1,
                0x01,
                SSTORE,
                bytecode::opcode::REVERT,
                bytecode::opcode::STOP,
            ]
            .into(),
        );
        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        let result = evm
            .transact(
                TxEnv::builder()
                    .gas_limit(100_000)
                    .authorization_list(vec![Either::Left(auth)])
                    .caller(EEADDRESS)
                    .kind(TxKind::Call(signer.address()))
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let state = result.state;
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        // As per the EIP it should not be stored.
        let expected_storage_access = state::StorageAccess {
            reads: { std::collections::BTreeSet::new() },
            writes: { std::collections::BTreeMap::new() },
        };
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access);
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn transfer_check() {
        use context::ContextTr;
        let recipient = database::BENCH_TARGET;
        let sender = database::BENCH_CALLER;

        let mut db = database::InMemoryDB::default();
        db.insert_account_info(
            database::BENCH_TARGET,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        db.insert_account_info(
            database::BENCH_CALLER,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(db.clone());

        let mut evm = ctx.build_mainnet();

        let sender_balance_before = context::Database::basic(&mut evm.db_mut(), sender)
            .unwrap()
            .unwrap()
            .balance;
        let recipient_balance_before = context::Database::basic(&mut evm.db_mut(), recipient)
            .unwrap()
            .unwrap_or_default()
            .balance;

        println!("Sender Balance (before):   {sender_balance_before}");
        println!("Recipient Balance (before): {recipient_balance_before}");

        let result = evm
            .transact(
                TxEnv::builder()
                    .caller(sender)
                    .kind(TxKind::Call(recipient))
                    .value(U256::from(2_000_000_000u32))
                    .gas_price(1)
                    .gas_priority_fee(None)
                    .nonce(0)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        database::DatabaseCommit::commit(&mut evm.db_mut(), result.clone().state);

        let sender_balance_after = context::Database::basic(&mut evm.db_mut(), sender)
            .unwrap()
            .unwrap()
            .balance;
        let recipient_balance_after = context::Database::basic(&mut evm.db_mut(), recipient)
            .unwrap()
            .unwrap_or_default()
            .balance;

        println!("Sender Balance (after):   {sender_balance_after}");
        println!("Recipient Balance (after): {recipient_balance_after}");

        let result_balance_change_sender = &result.state.get(&sender).unwrap().balance_change;
        println!("Balance Change of sender: {result_balance_change_sender:?}");
        let result_balance_change_recipient = &result.state.get(&recipient).unwrap().balance_change;
        println!("Balance Change of recipient: {result_balance_change_recipient:?}");
        let expected_sender_change = U256::from(999_979_000u64);

        let expected_recipient_change = U256::from(5_000_000_000u64);
        assert_eq!(
            *result_balance_change_sender,
            (expected_sender_change, false)
        );
        assert_eq!(
            *result_balance_change_recipient,
            (expected_recipient_change, false)
        );
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn transfer_check_zero() {
        use context::ContextTr;
        let recipient = database::BENCH_TARGET;
        let sender = database::BENCH_CALLER;

        let mut db = database::InMemoryDB::default();
        db.insert_account_info(
            database::BENCH_TARGET,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        db.insert_account_info(
            database::BENCH_CALLER,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(db.clone());

        let mut evm = ctx.build_mainnet();

        let sender_balance_before = context::Database::basic(&mut evm.db_mut(), sender)
            .unwrap()
            .unwrap()
            .balance;
        let recipient_balance_before = context::Database::basic(&mut evm.db_mut(), recipient)
            .unwrap()
            .unwrap_or_default()
            .balance;

        println!("Sender Balance (before):   {sender_balance_before}");
        println!("Recipient Balance (before): {recipient_balance_before}");

        let result = evm
            .transact(
                TxEnv::builder()
                    .caller(sender)
                    .kind(TxKind::Call(recipient))
                    .value(U256::from(0u32))
                    .gas_price(1)
                    .gas_priority_fee(None)
                    .nonce(0)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        database::DatabaseCommit::commit(&mut evm.db_mut(), result.clone().state);

        let sender_balance_after = context::Database::basic(&mut evm.db_mut(), sender)
            .unwrap()
            .unwrap()
            .balance;
        let recipient_balance_after = context::Database::basic(&mut evm.db_mut(), recipient)
            .unwrap()
            .unwrap_or_default()
            .balance;

        println!("Sender Balance (after):   {sender_balance_after}");
        println!("Recipient Balance (after): {recipient_balance_after}");

        let result_balance_change_sender = &result.state.get(&sender).unwrap().balance_change;
        println!("Balance Change of sender: {result_balance_change_sender:?}");
        let result_balance_change_recipient = &result.state.get(&recipient).unwrap().balance_change;
        println!("Balance Change of recipient: {result_balance_change_recipient:?}");
        let expected_sender_change = U256::from(2_999_979_000u64);

        let expected_recipient_change = U256::from(3_000_000_000u64);
        assert_eq!(
            *result_balance_change_sender,
            (expected_sender_change, false)
        );
        assert_eq!(
            *result_balance_change_recipient,
            (expected_recipient_change, true)
        );
    }

    #[test]
    #[cfg(feature = "glamsterdam")]
    fn nonce_check() {
        use context::ContextTr;
        let recipient = database::BENCH_TARGET;
        let sender = database::BENCH_CALLER;

        let mut db = database::InMemoryDB::default();
        db.insert_account_info(
            database::BENCH_TARGET,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        db.insert_account_info(
            database::BENCH_CALLER,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::AMSTERDAM)
            .with_db(db.clone());

        let mut evm = ctx.build_mainnet();

        let sender_nonce_before = context::Database::basic(&mut evm.db_mut(), sender)
            .unwrap()
            .unwrap()
            .nonce;
        let recipient_nonce_before = context::Database::basic(&mut evm.db_mut(), recipient)
            .unwrap()
            .unwrap_or_default()
            .nonce;

        println!("Sender nonce (before):   {sender_nonce_before}");
        println!("Recipient nonce (before): {recipient_nonce_before}");

        let result = evm
            .transact(
                TxEnv::builder()
                    .caller(sender)
                    .kind(TxKind::Call(recipient))
                    .value(U256::from(0u32))
                    .gas_price(1)
                    .gas_priority_fee(None)
                    .nonce(0)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        database::DatabaseCommit::commit(&mut evm.db_mut(), result.clone().state);

        let sender_nonce_after = context::Database::basic(&mut evm.db_mut(), sender)
            .unwrap()
            .unwrap()
            .nonce;
        let recipient_nonce_after = context::Database::basic(&mut evm.db_mut(), recipient)
            .unwrap()
            .unwrap_or_default()
            .nonce;

        println!("Sender nonce (after):   {sender_nonce_after}");
        println!("Recipient nonce (after): {recipient_nonce_after}");

        let result_nonce_change_sender = &result.state.get(&sender).unwrap().nonce_change;
        println!("Nonce Change of sender: {result_nonce_change_sender:?}");
        let result_nonce_change_recipient = &result.state.get(&recipient).unwrap().nonce_change;
        println!("Nonce Change of recipient: {result_nonce_change_recipient:?}");
    }

    #[test]
    #[cfg(feature = "glamsterdam")]
    fn nonce_check_create() {
        use context::ContextTr;

        let sender = database::BENCH_CALLER;

        let mut db = database::InMemoryDB::default();

        // Give sender some balance and default nonce = 0
        db.insert_account_info(
            sender,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| {
                cfg.spec = SpecId::AMSTERDAM;
                cfg.disable_nonce_check = true;
            })
            .with_db(db.clone());

        let mut evm = ctx.build_mainnet();

        let bytecode = primitives::Bytes::from(vec![0x60, 0x80, 0x60, 0x40]);
        let result1 = evm
            .transact_one(
                context::tx::TxEnvBuilder::new()
                    .kind(TxKind::Create)
                    .data(bytecode.clone())
                    .gas_limit(100000)
                    .caller(sender)
                    .gas_price(20)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        let created_address = result1.created_address().unwrap();

        let created_acc = evm
            .ctx
            .journal_mut()
            .state
            .get_mut(&created_address)
            .unwrap();

        created_acc.info.balance = U256::from(111111111111111111u64);

        let result = evm
            .transact(
                context::tx::TxEnvBuilder::new()
                    .kind(TxKind::Create)
                    .data(bytecode.clone())
                    .gas_limit(100000)
                    .caller(created_address)
                    .gas_price(20)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        database::DatabaseCommit::commit(&mut evm.db_mut(), result.clone().state);
        let result_nonce_change = &result.state.get(&created_address).unwrap().nonce_change;
        println!("result :{result_nonce_change:?}");
        assert_eq!(*result_nonce_change, (1, 2));
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn test_tx_env_builder_build_valid_eip7702() {
        let mut db = database::InMemoryDB::default();

        db.insert_account_info(
            primitives::Address::from([1u8; 20]),
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| {
                cfg.spec = SpecId::AMSTERDAM;
                cfg.disable_nonce_check = true;
            })
            .with_db(db.clone());

        let mut evm = ctx.build_mainnet();

        let auth = alloy_eip7702::RecoveredAuthorization::new_unchecked(
            Authorization {
                chain_id: U256::from(1),
                nonce: 0,
                address: primitives::Address::default(),
            },
            alloy_eip7702::RecoveredAuthority::Valid(primitives::Address::default()),
        );
        let auth_list = vec![Either::Right(auth)];

        let tx = evm
            .transact(
                context::tx::TxEnvBuilder::new()
                    .tx_type(Some(4))
                    .caller(primitives::Address::from([1u8; 20]))
                    .gas_limit(50000)
                    .gas_price(30)
                    .gas_priority_fee(Some(10))
                    .kind(TxKind::Call(primitives::Address::from([2u8; 20])))
                    .authorization_list(auth_list.clone())
                    .build()
                    .unwrap(),
            )
            .unwrap();
        println!("Tx:{tx:?}");
        let receiver = primitives::Address::from([2u8; 20]);
        let sender = primitives::Address::from([1u8; 20]);
        let result_nonce_change = &tx.state.get(&receiver).unwrap().nonce_change;
        let result_nonce_change_sender = &tx.state.get(&sender).unwrap().nonce_change;
        assert_eq!(*result_nonce_change, (0, 0));

        assert_eq!(*result_nonce_change_sender, (0, 1));
    }

    #[cfg(feature = "glamsterdam")]
    #[test]
    fn code_check_create() {
        use context::ContextTr;

        let sender = database::BENCH_CALLER;

        let mut db = database::InMemoryDB::default();

        db.insert_account_info(
            sender,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| {
                cfg.spec = SpecId::AMSTERDAM;
                cfg.disable_nonce_check = true;
            })
            .with_db(db.clone());

        let mut evm = ctx.build_mainnet();

        const DEPLOYMENT_BYTECODE: &[u8] = &[
            0x60, 0x0A, 0x60, 0x0C, 0x60, 0x00, 0x39, 0x60, 0x0A, 0x60, 0x00, 0xf3, 0x60, 0x2a,
            0x60, 0x00, 0x52, 0x60, 0x20, 0x60, 0x00, 0xf3,
        ];
        let result1 = evm
            .transact(
                context::tx::TxEnvBuilder::new()
                    .kind(TxKind::Create)
                    .data(DEPLOYMENT_BYTECODE.into())
                    .gas_limit(100000)
                    .caller(sender)
                    .gas_price(20)
                    .build()
                    .unwrap(),
            )
            .unwrap();

        database::DatabaseCommit::commit(&mut evm.db_mut(), result1.clone().state);

        let created_address = result1.result.created_address().unwrap();

        let code_change = &result1.state.get(&created_address).unwrap().code_change;
        let tracked_code = &code_change;
        let expected =
            primitives::Bytes::copy_from_slice(&primitives::hex!("602a60005260206000f300"));

        println!("tracked {:?}", tracked_code);
        assert_eq!(**tracked_code, expected);
    }
}
