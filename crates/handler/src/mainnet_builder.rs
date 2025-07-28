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

    use std::collections::{BTreeMap, BTreeSet};

    use crate::ExecuteEvm;
    use crate::{MainBuilder, MainContext};
    use alloy_signer::{Either, SignerSync};
    use alloy_signer_local::PrivateKeySigner;
    use bytecode::opcode::{
        BALANCE, DUP1, DUP2, DUP3, EXTCODEHASH, EXTCODESIZE, PUSH2, PUSH20, REVERT, SLOAD,
        STATICCALL, STOP,
    };
    use bytecode::{
        opcode::{PUSH1, SSTORE},
        Bytecode,
    };
    use context::{Context, ContextTr, Database, TxEnv};
    use context_interface::transaction::Authorization;
    use database::{BenchmarkDB, DatabaseCommit, BENCH_CALLER, BENCH_TARGET, EEADDRESS, FFADDRESS};
    use primitives::{hardfork::SpecId, TxKind, U256};
    use primitives::{StorageKey, StorageValue};
    use state::StorageAccess;

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

    #[test]
    #[cfg(feature = "glamsterdam")]
    fn storage_access_sstore_write_read_same_slot() {
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
            vec![PUSH1, 0x42, PUSH1, 0x01, SSTORE, PUSH1, 0x01, SLOAD, STOP].into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
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
        let expected_storage_access = StorageAccess {
            reads: {
                let mut reads = BTreeMap::new();
                reads.insert(0u64, BTreeSet::from([U256::from(1)]));
                reads
            },
            writes: {
                let mut writes = BTreeMap::new();
                writes.insert(
                    0u64,
                    BTreeMap::from([(U256::from(1), (U256::ZERO, U256::from(66)))]),
                );
                writes
            },
        };
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access)
    }

    #[test]
    #[cfg(feature = "glamsterdam")]
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
                PUSH1, 0x42, PUSH1, 0x01, SSTORE, PUSH1, 0x42, PUSH1, 0x01, SSTORE, STOP,
            ]
            .into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
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
        let expected_storage_access = StorageAccess {
            reads: {
                let mut reads = BTreeMap::new();
                reads.insert(0u64, BTreeSet::from([U256::from(1)]));
                reads
            },
            writes: {
                let mut writes = BTreeMap::new();
                writes.insert(
                    0u64,
                    BTreeMap::from([(U256::from(1), (U256::ZERO, U256::from(66)))]),
                );
                writes
            },
        };
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access)
    }

    #[test]
    #[cfg(feature = "glamsterdam")]
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
                PUSH1, 0x42, PUSH1, 0x01, SSTORE, PUSH1, 0x00, PUSH1, 0x01, SSTORE, STOP,
            ]
            .into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
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
        let expected_storage_access = StorageAccess {
            reads: { BTreeMap::new() },
            writes: {
                let mut writes = BTreeMap::new();
                writes.insert(
                    0u64,
                    BTreeMap::from([(U256::from(1), (U256::from(66), U256::ZERO))]),
                );
                writes
            },
        };
        let storage_access = &state.get(&signer.address()).unwrap().storage_access;
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access)
    }

    #[test]
    #[cfg(feature = "glamsterdam")]
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
                PUSH20,
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
                DUP1,
                EXTCODEHASH,
                DUP2,
                EXTCODESIZE,
                DUP3,
                BALANCE,
                STOP,
            ]
            .into(),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
            .with_db(BenchmarkDB::new_bytecode(bytecode));

        let mut evm = ctx.build_mainnet();

        // As per the EIP it should not be stored.
        let expected_storage_access = StorageAccess {
            reads: { BTreeMap::new() },
            writes: { BTreeMap::new() },
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

    #[test]
    #[cfg(feature = "glamsterdam")]
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
                PUSH1, 0x20, PUSH1, 0x00, PUSH1, 0x20, PUSH1, 0x00, PUSH20, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x12, 0x34, PUSH2, 0xFF, 0xFF, STATICCALL, STOP,
            ]
            .into(),
        );
        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
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
        let expected_storage_access = StorageAccess {
            reads: { BTreeMap::new() },
            writes: { BTreeMap::new() },
        };
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access);
    }

    #[test]
    #[cfg(feature = "glamsterdam")]
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
        let bytecode =
            Bytecode::new_legacy(vec![PUSH1, 0x42, PUSH1, 0x01, SSTORE, REVERT, STOP].into());
        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
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
        let expected_storage_access = StorageAccess {
            reads: { BTreeMap::new() },
            writes: { BTreeMap::new() },
        };
        let auth_acc = state.get(&signer.address()).unwrap();
        assert_eq!(auth_acc.info.code, Some(Bytecode::new_eip7702(FFADDRESS)));
        assert_eq!(auth_acc.info.nonce, 1);
        assert_eq!(*storage_access, expected_storage_access);
    }

    #[test]
    fn transfer_check() {
        //         === OUTPUT ===
        //         running 1 test
        // test mainnet_builder::test::transfer_check ... ok

        // successes:

        // ---- mainnet_builder::test::transfer_check stdout ----
        // Sender Balance (before):   3000000000
        // Recipient Balance (before): 3000000000
        // Sender Balance (after):   2999978000
        // Recipient Balance (after): 3000001000
        // Balance Change: BalanceChange { change: {0: {(2983222784, 2983221784)}} }
        // Balance Change: BalanceChange { change: {0: {(3000000000, 3000001000)}} }

        // successes:
        //     mainnet_builder::test::transfer_check
        let recipient = BENCH_TARGET;
        let sender = BENCH_CALLER;

        let mut db = database::InMemoryDB::default();
        db.insert_account_info(
            BENCH_TARGET,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        db.insert_account_info(
            BENCH_CALLER,
            state::AccountInfo::from_balance(U256::from(3_000_000_000u32)),
        );

        let ctx = Context::mainnet()
            .modify_cfg_chained(|cfg| cfg.spec = SpecId::PRAGUE)
            .with_db(db.clone());

        let mut evm = ctx.build_mainnet();

        let sender_balance_before = evm.db_mut().basic(sender).unwrap().unwrap().balance;
        let recipient_balance_before = evm
            .db_mut()
            .basic(recipient)
            .unwrap()
            .unwrap_or_default()
            .balance;

        println!("Sender Balance (before):   {}", sender_balance_before);
        println!("Recipient Balance (before): {}", recipient_balance_before);

        let result = evm
            .transact(
                TxEnv::builder()
                    .caller(sender)
                    .kind(TxKind::Call(recipient))
                    .value(U256::from(1000))
                    .gas_price(1)
                    .gas_priority_fee(None)
                    .nonce(0)
                    .build()
                    .unwrap(),
            )
            .unwrap();
        evm.db_mut().commit(result.clone().state);

        let sender_balance_after = evm.db_mut().basic(sender).unwrap().unwrap().balance;
        let recipient_balance_after = evm
            .db_mut()
            .basic(recipient)
            .unwrap()
            .unwrap_or_default()
            .balance;

        println!("Sender Balance (after):   {}", sender_balance_after);
        println!("Recipient Balance (after): {}", recipient_balance_after);

        let result_balance_change = &result.state.get(&sender).unwrap().balance_change;
        println!("Balance Change of sender: {:?}", result_balance_change);
        let result_balance_change = &result.state.get(&recipient).unwrap().balance_change;
        println!("Balance Change of recipient: {:?}", result_balance_change);
    }
}
