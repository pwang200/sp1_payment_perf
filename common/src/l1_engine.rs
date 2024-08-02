use crate::common::*;

pub fn process(input: &mut EngineData,
               valid_receipt: impl Fn(&Vec<u8>) -> ResultT<BlockHeaderL2>) -> ResultT<BlockHeaderL1> {
    let txns_hash = tx_set_hash(&input.txns);
    let mut to_update = std::collections::HashMap::new();
    let mut deposits = Vec::new();
    for t in &input.txns {
        let mut updates = match t {
            Transaction::Pay(tx) => {
                input.account_book.process_payment(tx)?
            }
            Transaction::Deposit(tx) => {
                let r = input.account_book.process_deposit_l1(tx)?;
                deposits.push((*tx).clone());
                r
            }
            Transaction::RollupCreate(tx) => {
                input.account_book.process_create_rollup_account(tx)?
            }
            Transaction::RollupUpdate(tx) => {
                input.account_book.process_rollup_state_update(tx, &valid_receipt)?
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

    let header = BlockHeaderL1 {
        parent: input.parent,
        state_root: *input.account_book.root(),
        sqn: input.sqn,
        txns_hash,
        events: deposits,
    };

    input.update(header.hash());

    Ok(header)
}

