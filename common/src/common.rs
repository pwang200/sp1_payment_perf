use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::fmt::Debug;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};

use k256::{
    ecdsa::{signature::{Signer, Verifier}, Signature},
    // EncodedPoint,
};

pub type SigningKey = k256::ecdsa::SigningKey;
pub type VerifyingKey = k256::ecdsa::VerifyingKey;


use partial_binary_merkle::PartialMerkleTrie;

pub const ONE_BILLION: u128 = 1_000_000_000;
pub const GENESIS_AMOUNT: u128 = ONE_BILLION;

pub const ONE_SECOND: u64 = 1_000;

pub fn clock() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Failed to measure time")
        .as_millis()
}

pub const HASH_LEN: usize = 32;

pub type Hash = [u8; HASH_LEN];
pub type AccountID = Hash;
pub type DefaultHasher = Sha256;
pub type ResultT<T> = Result<T, &'static str>;
pub type TxResult = ResultT<Vec<(AccountID, Hash)>>;


pub fn pk_to_hash(pk: &VerifyingKey) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(pk.to_sec1_bytes());//.as_bytes());
    let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
    x
}

pub trait TxPayload {
    fn hash(&self, hasher: &mut DefaultHasher);
    fn sender_qualify(&self, account: &Account) -> bool;
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Clone)]
pub struct Tx<T>
    where T: TxPayload
{
    pub sender: VerifyingKey,
    pub sqn: u32,
    pub payload: T,
    sig: Signature,
}

impl<T: Debug + TxPayload> fmt::Debug for Tx<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tx")
            .field("sender", &self.sender)
            .field("sqn", &self.sqn)
            .field("payload", &self.payload)
            .finish()
    }
}

impl<T> Tx<T>
    where T: TxPayload
{
    pub fn new(sender: VerifyingKey,
               sqn: u32,
               payload: T,
               signing_key: &mut SigningKey,
    ) -> Tx<T> {
        let mut hasher = DefaultHasher::new();
        hasher.update(sender.to_encoded_point(false));
        hasher.update(sqn.to_be_bytes());
        payload.hash(&mut hasher);
        let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
        let sig: Signature = signing_key.sign(&x);
        Tx { sender: sender, sqn: sqn, payload: payload, sig: sig }
    }

    pub fn id(&self) -> Hash {
        let mut hasher = DefaultHasher::new();
        hasher.update(self.sender.to_encoded_point(false));
        hasher.update(self.sqn.to_be_bytes());
        self.payload.hash(&mut hasher);
        hasher.update(self.sig.to_bytes());
        let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
        x
    }

    pub fn sig_verify(&self) -> bool {
        let mut hasher = DefaultHasher::new();
        hasher.update(self.sender.to_encoded_point(false));
        hasher.update(self.sqn.to_be_bytes());
        self.payload.hash(&mut hasher);
        let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
        self.sender.verify(&x, &self.sig).is_ok()
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Payment {
    pub to: VerifyingKey,
    pub amount: u128,
}

impl TxPayload for Payment {
    fn hash(&self, hasher: &mut DefaultHasher) {
        hasher.update(self.to.to_encoded_point(false));
        hasher.update(self.amount.to_be_bytes());
    }

    fn sender_qualify(&self, account: &Account) -> bool {
        account.amount >= self.amount
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateRollupAccount {
    // must be a new account
    pub rollup_pk: VerifyingKey,
    //pub genesis_state_hash: Hash,
}

impl TxPayload for CreateRollupAccount {
    fn hash(&self, hasher: &mut DefaultHasher) {
        hasher.update(self.rollup_pk.to_encoded_point(false));
        //hasher.update(self.genesis_state_hash);
    }

    fn sender_qualify(&self, _account: &Account) -> bool {
        true
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L1ToL2Deposit {
    pub rollup_pk: VerifyingKey,
    pub amount: u128,
}

impl TxPayload for L1ToL2Deposit {
    fn hash(&self, hasher: &mut DefaultHasher) {
        hasher.update(self.rollup_pk.to_encoded_point(false));
        hasher.update(self.amount.to_be_bytes());
    }

    fn sender_qualify(&self, account: &Account) -> bool {
        account.amount >= self.amount
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct L2ToL1Withdrawal {
    pub amount: u128,
}

impl TxPayload for L2ToL1Withdrawal {
    fn hash(&self, hasher: &mut DefaultHasher) {
        hasher.update(self.amount.to_be_bytes());
    }
    fn sender_qualify(&self, account: &Account) -> bool {
        account.amount >= self.amount
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone)]
// cross chain message, not signed since there is no dedicated relyer
pub struct RollupStateUpdate {
    pub proof_receipt: Vec<u8>,
}

impl TxPayload for RollupStateUpdate {
    fn hash(&self, hasher: &mut DefaultHasher) {
        //let data: Vec<u8> = bincode::serialize(&self.proof_receipt).unwrap();
        hasher.update(&self.proof_receipt);
    }
    fn sender_qualify(&self, _account: &Account) -> bool {
        true
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RollupState {
    pub inbox: VecDeque<Hash>,
    pub header_hash: Hash,
    pub sqn: u32,
}

impl RollupState {
    fn hash(&self, hasher: &mut DefaultHasher) {
        for msg in &self.inbox {
            hasher.update(msg);
        }
        hasher.update(self.header_hash);
        hasher.update(self.sqn.to_be_bytes());
    }
}


#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Account {
    pub owner: VerifyingKey,
    pub amount: u128,
    pub sqn_expect: u32,
    pub rollup: Option<RollupState>,
}

impl Account {
    pub fn new(owner: VerifyingKey,
               amount: u128,
               rollup: Option<RollupState>,
    ) -> Account
    {
        Account { owner, amount, sqn_expect: 0, rollup: rollup }
    }

    pub fn hash(&self) -> Hash {
        let mut hasher = DefaultHasher::new();
        hasher.update(self.owner.to_encoded_point(false));
        hasher.update(self.amount.to_be_bytes());
        hasher.update(self.sqn_expect.to_be_bytes());
        match &self.rollup {
            None => {}
            Some(ru) => ru.hash(&mut hasher),
        }
        let x: Hash = hasher.finalize().as_slice().try_into().expect("Hash");
        x
    }

    pub fn id(&self) -> Hash {
        pk_to_hash(&self.owner)
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug)]
pub struct AccountBook {
    proof_tree: PartialMerkleTrie,
    accounts: BTreeMap<AccountID, Account>,
}

impl AccountBook {
    pub fn new(faucet_key: VerifyingKey, faucet_amout: u128) -> AccountBook {
        let mut tree = PartialMerkleTrie::new();
        let mut b = BTreeMap::new();
        let a = Account::new(faucet_key, faucet_amout, None);
        let id = a.id();
        let a_hash = a.hash();
        b.insert(id, a);
        tree.insert_or_replace(id, a_hash);
        AccountBook { proof_tree: tree, accounts: b }
    }

    pub fn new_batch(keys: Vec<VerifyingKey>, amout: u128) -> AccountBook {
        let mut tree = PartialMerkleTrie::new();
        let mut b = BTreeMap::new();
        keys.into_iter().for_each(|k| {
            let a = Account::new(k, amout, None);
            let id = a.id();
            let a_hash = a.hash();
            b.insert(id, a);
            tree.insert_or_replace(id, a_hash);
        });
        AccountBook { proof_tree: tree, accounts: b }
    }

    pub fn root(&self) -> &Hash {
        &self.proof_tree.root
    }

    pub fn get_account(&mut self, aid: &AccountID) -> Option<&mut Account> {
        self.accounts.get_mut(aid)
    }

    pub fn get_account_or_new(&mut self, pk: VerifyingKey) -> &mut Account {
        let aid = pk_to_hash(&pk);

        if !self.accounts.contains_key(&aid) {
            self.accounts.insert(aid.clone(), Account::new(pk, 0, None));
        }
        self.accounts.get_mut(&aid).unwrap()
    }

    pub fn get_num_accounts(&self) -> usize {
        self.accounts.len()
    }

    pub fn sender_check<T>(&self, tx: &Tx<T>) -> Result<AccountID, &'static str>
        where T: TxPayload
    {
        if !tx.sig_verify() {
            return Err("sig");
        }
        let id_sender = pk_to_hash(&tx.sender);
        if let Some(a_sender) = self.accounts.get(&id_sender) {
            if a_sender.sqn_expect != tx.sqn {
                return Err("sqn");
            }
            if !tx.payload.sender_qualify(a_sender) {
                return Err("sender");
            }
            return Ok(id_sender);
        } else {
            return Err("account");
        }
    }

    pub fn process_payment(&mut self, tx: &Tx<Payment>) -> TxResult
    {
        let mut hashes = Vec::new();
        let id_sender = self.sender_check(tx)?;
        let a_sender = self.accounts.get_mut(&id_sender).unwrap();
        // if a_sender.amount < tx.payload.amount {
        //     return Err("balance");
        // }
        a_sender.amount -= tx.payload.amount;
        a_sender.sqn_expect += 1;
        let a_sender_h = a_sender.hash();
        hashes.push((id_sender, a_sender_h));

        let id_to = pk_to_hash(&tx.payload.to);
        hashes.push(match self.accounts.get_mut(&id_to) {
            None => {
                let a_to = Account::new(tx.payload.to, tx.payload.amount, None);//TODO lifetime
                let a_to_h = a_to.hash();
                self.accounts.insert(id_to, a_to);
                (id_to, a_to_h)
            }
            Some(a_to) => {
                a_to.amount += tx.payload.amount;
                let a_to_h = a_to.hash();
                (id_to, a_to_h)
            }
        });
        Ok(hashes)
    }

    pub fn process_create_rollup_account(&mut self, tx: &Tx<CreateRollupAccount>) -> TxResult
    {
        let mut hashes = Vec::new();
        let id_sender = self.sender_check(tx)?;
        let id_to = pk_to_hash(&tx.payload.rollup_pk);
        match self.accounts.get(&id_to) {
            None => {
                let a_sender = self.accounts.get_mut(&id_sender).unwrap();
                a_sender.sqn_expect += 1;
                let a_sender_h = a_sender.hash();
                hashes.push((id_sender, a_sender_h));

                let rus = RollupState { inbox: VecDeque::new(), header_hash: Hash::default(), sqn: 0 };
                //tx.payload.genesis_state_hash
                let a_to = Account::new(tx.payload.rollup_pk, 0, Some(rus));
                let a_to_h = a_to.hash();
                self.accounts.insert(id_to, a_to);
                hashes.push((id_to, a_to_h));
                return Ok(hashes);
            }
            Some(_) => { return Err("exist"); }
        };
    }

    pub fn process_deposit_l1(&mut self, tx: &Tx<L1ToL2Deposit>) -> TxResult
    {
        let mut hashes = Vec::new();
        let id_sender = self.sender_check(tx)?;
        let id_to = pk_to_hash(&tx.payload.rollup_pk);
        // let (a_sender, a_to) = self.get_account_pair(&id_sender, &id_to)?;
        //
        // if a_sender.amount < tx.payload.amount {
        //     return Err("balance");
        // }
        let a_to = self.accounts.get_mut(&id_to);
        if a_to.is_none() {
            return Err("missing");
        }
        let a_to = a_to.unwrap();
        if a_to.rollup.is_none() { return Err("not rollup account"); }
        let rollup_state = a_to.rollup.as_mut().unwrap();

        a_to.amount += tx.payload.amount;
        rollup_state.inbox.push_back(tx.id());
        let a_to_h = a_to.hash();
        hashes.push((id_to, a_to_h));

        let a_sender = self.accounts.get_mut(&id_sender).unwrap();
        a_sender.amount -= tx.payload.amount;
        a_sender.sqn_expect += 1;
        let a_sender_h = a_sender.hash();
        hashes.push((id_sender, a_sender_h));

        Ok(hashes)
    }

    pub fn process_deposit_l2(&mut self, tx: &Tx<L1ToL2Deposit>) -> TxResult
    {
        let mut hashes = Vec::new();
        let id_to = pk_to_hash(&tx.sender);
        hashes.push(match self.accounts.get_mut(&id_to) {
            None => {
                let a_to = Account::new(tx.sender, tx.payload.amount, None);
                let a_to_h = a_to.hash();
                self.accounts.insert(id_to, a_to);
                (id_to, a_to_h)
            }
            Some(a_to) => {
                a_to.amount += tx.payload.amount;
                let a_to_h = a_to.hash();
                (id_to, a_to_h)
            }
        });
        Ok(hashes)
    }

    pub fn process_withdrawal(&mut self, tx: &Tx<L2ToL1Withdrawal>,
                              w_records: &mut Vec<WithdrawalRecord>) -> TxResult
    {
        let mut hashes = Vec::new();
        let id_sender = self.sender_check(tx)?;
        let a_sender = self.accounts.get_mut(&id_sender).unwrap();
        // if a_sender.amount < tx.payload.amount {
        //     return Err("balance");
        // }
        a_sender.amount -= tx.payload.amount;
        a_sender.sqn_expect += 1;
        let a_sender_h = a_sender.hash();
        hashes.push((id_sender, a_sender_h));

        w_records.push(WithdrawalRecord { to: tx.sender, amount: tx.payload.amount });
        Ok(hashes)
    }

    pub fn process_rollup_state_update(&mut self, tx: &Tx<RollupStateUpdate>,
                                       valid_receipt: impl Fn(&Vec<u8>) -> ResultT<BlockHeaderL2>) -> TxResult
    {
        // verify sig and account sqn
        // verify receipt against STF image id.
        // get block header from receipt
        // check parent, sqn match
        // check inbox consumed
        // update state hash, sqn
        // process withdrawal. We don't separate this step since no gas concern

        // verification steps:
        let id_sender = self.sender_check(tx)?;

        let receipt = &tx.payload.proof_receipt;
        let header: BlockHeaderL2 = valid_receipt(receipt)?;

        let a_sender = self.get_account(&id_sender).unwrap();
        if a_sender.rollup.is_none() {
            return Err("account_rollup");
        }

        let rollup = a_sender.rollup.as_mut().unwrap();
        if header.parent != rollup.header_hash {
            return Err("parent");
        }

        if header.sqn != rollup.sqn {
            return Err("sqn");
        }

        let mut hasher = DefaultHasher::new();
        for i in 0..header.inbox_msg_count as usize {
            hasher.update(rollup.inbox[i]);
        }
        let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
        if x != header.inbox_msg_hash {
            return Err("inbox");
        }

        let mut ws = 0;
        for w in &header.withdrawals {
            ws += w.amount;
        }
        if ws > a_sender.amount {
            return Err("withdraw");
        }

        // update
        for _ in 0..header.inbox_msg_count {
            rollup.inbox.pop_front();
        }
        rollup.sqn += 1;
        rollup.header_hash = header.hash();
        a_sender.amount -= ws;
        a_sender.sqn_expect += 1;
        let a_sender_h = a_sender.hash();
        let mut hashes = Vec::new();
        hashes.push((id_sender, a_sender_h));

        // process withdrawal.
        for w in header.withdrawals {
            let acc = self.get_account_or_new(w.to);
            acc.amount += w.amount;
        }

        Ok(hashes)
    }


    //for supporting a more richer set of txns, the account store must support versioning or
    //other ways to pre-run and get affected accounts before modifying the accounts
    fn get_affected_account_ids(&self, txns: &Vec<Transaction>) -> Vec<AccountID> {
        let mut ids = HashSet::new();
        for tx in txns {
            match tx {
                // only layer 2 txns
                Transaction::Pay(tx) => {
                    ids.insert(pk_to_hash(&tx.sender));
                    ids.insert(pk_to_hash(&tx.payload.to));
                }
                Transaction::Deposit(_tx) => { panic!("only l2 txns") }
                Transaction::RollupCreate(_tx) => { panic!("only l2 txns") }
                Transaction::RollupUpdate(_tx) => { panic!("only l2 txns") }
                Transaction::DepositL2(tx) => {
                    ids.insert(pk_to_hash(&tx.sender));
                }
                Transaction::Withdrawal(tx) => {
                    ids.insert(pk_to_hash(&tx.sender));
                }
            }
        }
        ids.into_iter().collect()
    }

    pub fn update_tree(&mut self, changes: Vec<(AccountID, Hash)>) {
        self.proof_tree.insert_or_replace_batch(changes);
    }

    pub fn get_partial(&self, txns: &Vec<Transaction>) -> AccountBook {
        let ids = self.get_affected_account_ids(txns);
        let mut accounts = BTreeMap::new();
        ids.iter().for_each(|id| {
            let a = self.accounts.get(id).unwrap();
            accounts.insert(id.clone(), a.clone());
        });

        let id_refs = ids.iter().map(|x| x).collect();
        let proof_tree = self.proof_tree.get_partial(&id_refs);
        AccountBook { proof_tree, accounts }
    }

    pub fn verify_partial_root(&self) -> bool {
        for (id, a) in &self.accounts {
            let a_h = self.proof_tree.get(id);
            if a_h.is_none() || a_h.unwrap() != a.hash() {
                return false;
            }
        }
        self.proof_tree.verify_partial()
    }

    #[cfg(test)]
    pub(crate) fn account_hash_verify(&mut self, pk: &VerifyingKey, is_valid: impl Fn(&Account) -> bool) -> bool {
        // has account
        // account info correct
        // computed account hash is the same as Merkle tree leaf
        // can get proof
        // proof verifies
        let id = pk_to_hash(pk);
        let account = self.accounts.get(&id);
        if account.is_none() {
            return false;
        }
        let account = account.unwrap();
        if !is_valid(account) {
            return false;
        }
        let account_hash = account.hash();

        let leaf = self.proof_tree.get(&id);
        if leaf.is_none() {
            return false;
        }
        if account_hash != leaf.unwrap() {
            return false;
        }

        let proof = self.proof_tree.get_proof(&id).unwrap();
        proof.verify(self.root())
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WithdrawalRecord {
    pub to: VerifyingKey,
    pub amount: u128,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Transaction {
    Pay(Tx<Payment>),
    Deposit(Tx<L1ToL2Deposit>),
    RollupCreate(Tx<CreateRollupAccount>),
    RollupUpdate(Tx<RollupStateUpdate>),
    DepositL2(Tx<L1ToL2Deposit>),
    Withdrawal(Tx<L2ToL1Withdrawal>),
}

pub fn tx_set_hash(txns: &Vec<Transaction>) -> Hash {
    let mut hasher = DefaultHasher::new();
    for tx in txns {
        match tx {
            Transaction::Pay(t) => hasher.update(&t.id()),
            Transaction::Deposit(t) => hasher.update(&t.id()),
            Transaction::RollupCreate(t) => hasher.update(&t.id()),
            Transaction::RollupUpdate(t) => hasher.update(&t.id()),
            Transaction::DepositL2(t) => hasher.update(&t.id()),
            Transaction::Withdrawal(t) => hasher.update(&t.id()),
        }
    }
    let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
    x
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug)]
pub struct EngineData {
    pub parent: Hash,
    pub account_book: AccountBook,
    pub txns: Vec<Transaction>,
    pub sqn: u32,
}

impl EngineData {
    pub fn new(faucet_key: VerifyingKey, faucet_amout: u128) -> EngineData {
        EngineData {
            parent: Hash::default(),
            account_book: AccountBook::new(faucet_key, faucet_amout),
            txns: vec![],
            sqn: 0,
        }
    }

    pub fn new_batch(keys: Vec<VerifyingKey>, amout: u128) -> EngineData {
        EngineData {
            parent: Hash::default(),
            account_book: AccountBook::new_batch(keys, amout),
            txns: vec![],
            sqn: 0,
        }
    }

    pub fn update(&mut self, parent: Hash) {
        self.txns.clear();
        self.sqn += 1;
        self.parent = parent;
    }

    pub fn get_partial(&self) -> EngineData {
        EngineData {
            parent: self.parent,
            account_book: self.account_book.get_partial(&self.txns),
            txns: self.txns.clone(),
            sqn: self.sqn,
        }
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BlockHeaderL1 {
    pub parent: Hash,
    pub state_root: Hash,
    pub sqn: u32,
    pub txns_hash: Hash,
    pub events: Vec<Tx<L1ToL2Deposit>>,
}

impl BlockHeaderL1 {
    pub fn hash(&self) -> Hash {
        let mut hasher = DefaultHasher::new();
        hasher.update(self.parent);
        hasher.update(self.state_root);
        hasher.update(self.sqn.to_be_bytes());
        hasher.update(self.txns_hash);
        let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
        x
    }
}

#[repr(align(4))]
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct BlockHeaderL2 {
    pub parent: Hash,
    pub state_root: Hash,
    pub sqn: u32,
    pub txns_hash: Hash,//TODO consider changing to l2 txns only to match design doc
    pub inbox_msg_hash: Hash,
    pub inbox_msg_count: u32,
    pub withdrawals: Vec<WithdrawalRecord>,
}

impl BlockHeaderL2 {
    pub fn hash(&self) -> Hash {
        let mut hasher = DefaultHasher::new();
        hasher.update(self.parent);
        hasher.update(self.state_root);
        hasher.update(self.sqn.to_be_bytes());
        hasher.update(self.txns_hash);
        hasher.update(self.inbox_msg_hash);
        hasher.update(self.inbox_msg_count.to_be_bytes());
        for w in &self.withdrawals {
            hasher.update(w.to.to_encoded_point(false));
            hasher.update(w.amount.to_be_bytes());
        }
        let x: Hash = hasher.finalize().as_slice().try_into().expect("hash");
        x
    }
}

#[derive(Clone)]
pub struct TxSigner {
    pub sk: SigningKey,
    pub pk: VerifyingKey,
    pub sqn: u32,
}

impl TxSigner {
    pub fn new(sk: SigningKey) -> TxSigner {
        let pk = sk.verifying_key().clone();
        TxSigner { sk, pk, sqn: 0 }
    }
}
