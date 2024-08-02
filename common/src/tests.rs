#[cfg(test)]
mod tests {
    use crate::common::*;
    use k256::ecdsa::SigningKey;
    use std::collections::HashMap;
    use rand::rngs::OsRng;

    const PAY_AMOUNT: u128 = 10u128;

    struct Genesis {
        faucet: TxSigner,
        rollup: TxSigner,
        alices: Vec<TxSigner>,
        l1: EngineData,
        l2: EngineData,
    }

    impl Genesis {
        fn new(num_alices: usize) -> Genesis {
            let mut csprng = OsRng;
            let faucet = TxSigner::new(SigningKey::random(&mut csprng));
            let rollup = TxSigner::new(SigningKey::random(&mut csprng));
            let mut alices = Vec::new();
            for _ in 0..num_alices {
                alices.push(TxSigner::new(SigningKey::random(&mut csprng)));
            }
            let l1 = EngineData::new(faucet.pk, GENESIS_AMOUNT);
            let l2 = EngineData::new(faucet.pk, 0);
            Genesis { faucet, rollup, alices, l1, l2 }
        }
    }

    // run the test with the following command, note the manifest-path is relative
    // RUST_BACKTRACE=1 cargo test --lib tests::process_works --manifest-path ./common/Cargo.toml
    #[test]
    fn payment_and_account_book_works() {
        let num_alices = 33usize;
        let mut genesis = Genesis::new(num_alices as usize);
        let book = &mut genesis.l1.account_book;
        let faucet_pk = &genesis.faucet.pk;
        // no txns, only genesis
        assert!(book.account_hash_verify(faucet_pk, |a| a.sqn_expect == 0u32 && a.amount == GENESIS_AMOUNT && a.owner == *faucet_pk));
        /////////////////////////////////////////////////////
        // create txns
        let mut to_update = HashMap::new();
        let alices = &genesis.alices;
        for i in 0..num_alices {
            let tx = Tx::new(faucet_pk.clone(), i as u32, Payment { to: alices[i].pk, amount: PAY_AMOUNT }, &mut genesis.faucet.sk);
            let r = book.process_payment(&tx).unwrap();
            for (k, v) in r {
                to_update.insert(k, v);
            }
        }
        let to_update: Vec<(AccountID, Hash)> = to_update.into_iter().collect();
        book.update_tree(to_update);

        assert_eq!(alices.len(), num_alices as usize);
        // n accounts are created
        for alice in alices {
            assert!(book.account_hash_verify(&alice.pk, |a| a.sqn_expect == 0 && a.amount == PAY_AMOUNT && a.owner == alice.pk));
        }
        // genesis account
        assert!(book.account_hash_verify(&faucet_pk, |a| a.sqn_expect == num_alices as u32 && a.amount == GENESIS_AMOUNT - PAY_AMOUNT * num_alices as u128 && a.owner == *faucet_pk));

        /////////////////////////////////////////////////////
        // more txns
        let mut to_update = HashMap::new();
        let alices = &mut genesis.alices;
        for alice in alices {
            let tx = Tx::new(alice.pk.clone(), 0u32, Payment { to: faucet_pk.clone(), amount: PAY_AMOUNT }, &mut alice.sk);
            let r = book.process_payment(&tx).unwrap();
            for (k, v) in r {
                to_update.insert(k, v);
            }
        }
        let to_update: Vec<(AccountID, Hash)> = to_update.into_iter().collect();
        book.update_tree(to_update);
        let alices = &genesis.alices;
        // n accounts
        for alice in alices {
            assert!(book.account_hash_verify(&alice.pk, |a| a.sqn_expect == 1 && a.amount == 0 && a.owner == alice.pk));
        }
        // genesis account
        assert!(book.account_hash_verify(&faucet_pk, |a| a.sqn_expect == num_alices as u32 && a.amount == GENESIS_AMOUNT && a.owner == *faucet_pk));

        // recompute root
        assert!(book.verify_partial_root());
    }

    #[test]
    fn deposit_withdrawal_works() {
        let num_alices = 0usize;
        let mut genesis = Genesis::new(num_alices);
        let faucet_pk = &genesis.faucet.pk;

        // L1 deposit
        let tx = Tx::new(faucet_pk.clone(), 0, CreateRollupAccount { rollup_pk: genesis.rollup.pk.clone() }, &mut genesis.faucet.sk);
        genesis.l1.txns.push(Transaction::RollupCreate(tx));
        let tx = Tx::new(faucet_pk.clone(), 1, L1ToL2Deposit { rollup_pk: genesis.rollup.pk.clone(), amount: PAY_AMOUNT }, &mut genesis.faucet.sk);
        let deposit_tx_id = tx.id();
        genesis.l1.txns.push(Transaction::Deposit(tx.clone()));
        let bh1 = crate::l1_engine::process(&mut genesis.l1, |_| Ok(BlockHeaderL2::default()));
        assert!(bh1.is_ok());
        assert!(genesis.l1.txns.is_empty());

        assert!(genesis.l1.account_book.account_hash_verify(&faucet_pk, |a| a.sqn_expect == 2u32 && a.amount == GENESIS_AMOUNT - PAY_AMOUNT && a.owner == *faucet_pk));
        assert!(genesis.l1.account_book.account_hash_verify(&genesis.rollup.pk, |a| a.sqn_expect == 0u32 && a.amount == PAY_AMOUNT && a.owner == genesis.rollup.pk &&
            a.rollup.as_ref().is_some_and(|ru| ru.header_hash == Hash::default() && !ru.inbox.is_empty() && ru.inbox[0] == deposit_tx_id && ru.sqn == 0)));

        // L2 deposit
        genesis.l2.txns.push(Transaction::DepositL2(tx));
        let bh2 = crate::l2_engine::process(&mut genesis.l2);
        assert!(bh2.is_ok());
        assert!(genesis.l2.txns.is_empty());
        assert!(genesis.l2.account_book.account_hash_verify(&faucet_pk, |a| a.sqn_expect == 0u32 && a.amount == PAY_AMOUNT && a.owner == *faucet_pk));

        // update L2 state to L1 (no zk proof)
        let bh2 = bh2.unwrap();
        let data = bincode::serialize(&bh2).unwrap();
        let tx = Tx::new(genesis.rollup.pk.clone(), 0, RollupStateUpdate { proof_receipt: data }, &mut genesis.rollup.sk);
        genesis.l1.txns.push(Transaction::RollupUpdate(tx));
        let bh1 = crate::l1_engine::process(&mut genesis.l1, |data| {
            let header: BlockHeaderL2 = bincode::deserialize(data).unwrap();
            Ok(header)
        });
        assert!(bh1.is_ok());
        assert!(genesis.l1.account_book.account_hash_verify(&genesis.rollup.pk, |a| a.sqn_expect == 1u32 && a.amount == PAY_AMOUNT && a.owner == genesis.rollup.pk &&
            a.rollup.as_ref().is_some_and(|ru| ru.header_hash == bh2.hash() && ru.inbox.is_empty() && ru.sqn == 1)));

        // withdrawal
        let tx = Tx::new(faucet_pk.clone(), 0, L2ToL1Withdrawal { amount: PAY_AMOUNT }, &mut genesis.faucet.sk);
        genesis.l2.txns.push(Transaction::Withdrawal(tx));
        let bh2 = crate::l2_engine::process(&mut genesis.l2);
        assert!(bh2.is_ok());
        assert!(genesis.l2.account_book.account_hash_verify(&faucet_pk, |a| a.sqn_expect == 1u32 && a.amount == 0 && a.owner == *faucet_pk));

        // update L2 state to L1 (no zk proof), to see withdrawal effect
        let bh2 = bh2.unwrap();
        assert!(!bh2.withdrawals.is_empty() && bh2.withdrawals[0].to == *faucet_pk && bh2.withdrawals[0].amount == PAY_AMOUNT && bh2.sqn == 1 && bh2.inbox_msg_count == 0);
        let data = bincode::serialize(&bh2).unwrap();
        let tx = Tx::new(genesis.rollup.pk.clone(), 1, RollupStateUpdate { proof_receipt: data }, &mut genesis.rollup.sk);
        genesis.l1.txns.push(Transaction::RollupUpdate(tx));
        let bh1 = crate::l1_engine::process(&mut genesis.l1, |data| {
            let header: BlockHeaderL2 = bincode::deserialize(data).unwrap();
            Ok(header)
        });
        assert!(bh1.is_ok());
        assert!(genesis.l1.account_book.account_hash_verify(&genesis.rollup.pk, |a| a.sqn_expect == 2u32 && a.amount == 0 && a.owner == genesis.rollup.pk &&
            a.rollup.as_ref().is_some_and(|ru| ru.header_hash == bh2.hash() && ru.inbox.is_empty() && ru.sqn == 2)));
    }
}
