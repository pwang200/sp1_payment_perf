use crate::common::*;
use sha2::Digest;

pub fn process(input: &mut EngineData) -> ResultT<BlockHeaderL2> {
    let txns_hash = tx_set_hash(&input.txns);
    let mut to_update = std::collections::HashMap::new();
    let mut w_records = Vec::new();
    let mut l1_l2_msgs = Vec::new();
    for t in &input.txns {
        let mut updates = match t {
            Transaction::Pay(tx) => {
                input.account_book.process_payment(tx)?
            }
            Transaction::DepositL2(tx) => {
                l1_l2_msgs.push(tx.id());
                input.account_book.process_deposit_l2(tx)?
            }
            Transaction::Withdrawal(tx) => {
                input.account_book.process_withdrawal(tx, &mut w_records)?
            }
            _ => {
                return Err("tx type");
            }
        };
        for (k, v) in updates.drain(..) {
            to_update.insert(k, v);
        }
    }
    let to_update: Vec<(AccountID, Hash)> = to_update.into_iter().collect();
    input.account_book.update_tree(to_update);

    let mut hasher = DefaultHasher::new();
    let num_msgs = l1_l2_msgs.len();
    for tid in l1_l2_msgs {
        hasher.update(tid);
    }
    let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");

    let header = BlockHeaderL2 {
        parent: input.parent,
        state_root: *input.account_book.root(),
        sqn: input.sqn,
        txns_hash,
        inbox_msg_hash: x,
        inbox_msg_count: num_msgs as u32,
        withdrawals: w_records,
    };

    input.update(header.hash());

    Ok(header)
}
