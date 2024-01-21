extern crate core;

// mod bitcoin_node;

#[cfg(test)]
pub mod test;

use bitcoin::{bech32::ToBase32, blockdata::opcodes, blockdata::script::Builder, consensus::Encodable, hashes::Hash, psbt::serialize::Serialize, schnorr::TweakedPublicKey, secp256k1::{self, All, Secp256k1, SecretKey, Message}, util::sighash::SighashCache, util::taproot::TaprootBuilder, Address, EcdsaSighashType, KeyPair, Network, OutPoint, PackedLockTime, PublicKey, SchnorrSighashType, Script, Sequence, Transaction, TxIn, TxOut, Witness, XOnlyPublicKey};

use bitcoin::schnorr::UntweakedPublicKey;
use bitcoin::util::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootSpendInfo, TapTweakHash};
use serde::{Serialize as SerdeSerialize};

// use p256k1::{
//     scalar::Scalar,
//     schnorr::Signature,
// };

pub trait ToPublicKey {
    /// Converts an object to a public key
    fn to_public_key(&self) -> bitcoin::PublicKey;

    /// Convert an object to x-only pubkey
    fn to_x_only_pubkey(&self) -> bitcoin::secp256k1::XOnlyPublicKey {
        let pk = self.to_public_key();
        bitcoin::secp256k1::XOnlyPublicKey::from(pk.inner)
    }
}

impl ToPublicKey for bitcoin::PublicKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        *self
    }
}

impl ToPublicKey for bitcoin::secp256k1::PublicKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        bitcoin::PublicKey::new(*self)
    }
}

impl ToPublicKey for bitcoin::secp256k1::XOnlyPublicKey {
    fn to_public_key(&self) -> bitcoin::PublicKey {
        // This code should never be used.
        // But is implemented for completeness
        let mut data: Vec<u8> = vec![0x02];
        data.extend(self.serialize().iter());
        bitcoin::PublicKey::from_slice(&data)
            .expect("Failed to construct 33 Publickey from 0x02 appended x-only key")
    }

    fn to_x_only_pubkey(&self) -> bitcoin::secp256k1::XOnlyPublicKey {
        *self
    }
}

pub fn create_script(recipient_public_key: &PublicKey, secp: &Secp256k1<All>) -> (Script, TaprootSpendInfo) {
    // TODO: this is a placeholder, replace with actual peg-in script
    let recipient_public_key_xonly = recipient_public_key.to_x_only_pubkey();
    let hash160 = bitcoin::hashes::hash160::Hash::hash(&recipient_public_key_xonly.serialize());

    let script_path = Builder::new()
        .push_opcode(opcodes::all::OP_DUP)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&hash160[..])
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script_path.clone()).unwrap()
        .finalize(&secp, recipient_public_key_xonly)
        .expect("Should be finalizable");

    (script_path, taproot_spend_info)
}

pub fn create_steno_script(recovery_key: &PublicKey, sealing_key: &PublicKey, cid: String, secp: &Secp256k1<All>) -> (Script, TaprootSpendInfo) {
    let recovery_key_xonly = recovery_key.to_x_only_pubkey();
    let solution = sealing_key.serialize().append(&mut cid.clone().as_bytes().to_vec());
    let hash160 = bitcoin::hashes::hash160::Hash::hash(&recovery_key_xonly.serialize());

    let script_path = Builder::new()
        .push_opcode(opcodes::all::OP_CAT)
        .push_opcode(opcodes::all::OP_HASH160)
        .push_slice(&hash160[..])
        .push_opcode(opcodes::all::OP_EQUALVERIFY)
        .into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, script_path.clone()).unwrap()
        .finalize(&secp, recovery_key_xonly)
        .expect("SpendInfo not finalizable");

    (script_path, taproot_spend_info)
}

pub fn create_p2tr_output(satoshis: u64, recipient_public_key: PublicKey, taproot_spend_info: Option<TaprootSpendInfo>, secp: &Secp256k1<All>) -> TxOut {
    let script_pubkey = match taproot_spend_info {
        Some(taproot_spend_info) => {
            let merkle_root = taproot_spend_info.merkle_root();
            let address = Address::p2tr(&secp, recipient_public_key.to_x_only_pubkey(), merkle_root, Network::Regtest);
            address.script_pubkey()
        },
        None => {
            let recipient_public_key_tweaked = TweakedPublicKey::dangerous_assume_tweaked(recipient_public_key.to_x_only_pubkey());
            Script::new_v1_p2tr_tweaked(recipient_public_key_tweaked)
        }
    };

    TxOut {
        value: satoshis,
        script_pubkey
    }
}

pub fn sign_p2tr_tx_input_schnorr(
    tx: &mut Transaction,
    input_index: usize,
    prev_output: &TxOut,
    secret_key: &SecretKey,
    script: Option<Script>,
    spend_info: Option<TaprootSpendInfo>,
    secp: &Secp256k1<All>
) {
    match (script, spend_info) {
        // script path spend
        (Some(script), Some(spend_info)) => {
            let mut sighash_cache = SighashCache::new(&*tx);
            let taproot_sighash = sighash_cache
                .taproot_script_spend_signature_hash(
                    input_index,
                    &bitcoin::util::sighash::Prevouts::All(&[prev_output]),
                    TapLeafHash::from_script(&script, LeafVersion::TapScript),
                    SchnorrSighashType::Default,
                )
                .unwrap();

            let signing_payload = taproot_sighash.as_hash();
            println!("signing_payload: {signing_payload}");
            // let sig = Signature::new(&signing_payload, &Scalar::from(secret_key.secret_bytes())).unwrap();
            let msg = Message::from_slice(signing_payload.as_ref()).unwrap();
            let sig = secp.sign_schnorr_no_aux_rand(&msg, &KeyPair::from_secret_key(&secp, &secret_key));
            println!("sig: {:#?}", sig.as_ptr());
            let control_block = spend_info.control_block(&(script.clone(), LeafVersion::TapScript)).unwrap();
            println!("control_block: {:#?}", control_block);
            let x_only_pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret_key).to_x_only_pubkey();

            tx.input[input_index]
                .witness
                .push(sig.as_ref());

            println!("x_only_pubkey: {}", x_only_pubkey);

            tx.input[input_index]
                .witness
                .push(x_only_pubkey.serialize());

            tx.input[input_index]
                .witness
                .push(script.to_bytes());

            tx.input[input_index]
                .witness
                .push(control_block.serialize());
        },

        // key path spend, applying tweak from spend_info
        (None, Some(spend_info)) => {
            // let sec_key = Scalar::from(secret_key.add_tweak(&spend_info.tap_tweak().to_scalar()).unwrap().secret_bytes());
            let sec_key = secret_key.add_tweak(&spend_info.tap_tweak().to_scalar()).unwrap();

            let mut sighash_cache = SighashCache::new(&*tx);
            let taproot_sighash = sighash_cache
                .taproot_key_spend_signature_hash(
                    input_index,
                    &bitcoin::util::sighash::Prevouts::All(&[prev_output]),
                    SchnorrSighashType::Default,
                )
                .unwrap();

            let signing_payload = taproot_sighash.as_hash().to_vec();
            let msg = Message::from_slice(signing_payload.as_ref()).unwrap();
            let schnorr_sig = secp.sign_schnorr_no_aux_rand(&msg, &KeyPair::from_secret_key(&secp, &sec_key));
            let schnorr_sig_bytes = schnorr_sig.as_ref();

            tx.input[input_index].witness.push(&schnorr_sig_bytes);
        },

        (None, None) => {
            let mut sighash_cache = SighashCache::new(&*tx);
            let taproot_sighash = sighash_cache
                .taproot_key_spend_signature_hash(
                    input_index,
                    &bitcoin::util::sighash::Prevouts::All(&[prev_output]),
                    SchnorrSighashType::Default,
                )
                .unwrap();

            let signing_payload = taproot_sighash.as_hash().to_vec();
            let msg = Message::from_slice(signing_payload.as_ref()).unwrap();
            let schnorr_sig = secp.sign_schnorr_no_aux_rand(&msg, &KeyPair::from_secret_key(&secp, &secret_key));
            let schnorr_sig_bytes = schnorr_sig.as_ref();

            tx.input[input_index].witness.push(&schnorr_sig_bytes);
        },

        // (Some(script), None) => {}
        _ => panic!("sign_p2tr_input: Script provided without TaprootSpendInfo")
    }
}

pub fn sign_tx_input_ecdsa(tx: &mut Transaction, input_index: usize, secret_key: &SecretKey, prev_output: &TxOut, secp: &Secp256k1<All>) {
    let public_key  = bitcoin::PublicKey::from_slice(&secret_key.public_key(&secp).serialize()).expect("unable to convert pk to pk");
    let addr = Address::p2wpkh(&public_key, Network::Regtest).unwrap();

    let tx_script = addr.script_pubkey().p2wpkh_script_code().unwrap();
    let mut sighash_cache = SighashCache::new(&*tx);

    let tx_sighash = sighash_cache
        .segwit_signature_hash(
            input_index,
            &tx_script,
            prev_output.value,
            EcdsaSighashType::All,
        )
        .unwrap();

    let msg = Message::from_slice(&tx_sighash).unwrap();
    let sig = secp.sign_ecdsa_low_r(&msg, secret_key);

    tx.input[input_index]
        .witness
        .push_bitcoin_signature(&sig.serialize_der(), EcdsaSighashType::All);

    tx.input[input_index]
        .witness
        .push(public_key.to_bytes());
}

fn consensus_encode(tx: &Transaction) -> String {
    let mut tx_bytes: Vec<u8> = vec![];
    let _tx_bytes_len = tx.consensus_encode(&mut tx_bytes).unwrap();
    let tx_bytes_hex = hex::encode(&tx_bytes);

    tx_bytes_hex
}

pub fn test() -> String {
    let miner: [u8; 32] = [102,247,172,172,5,11,222,107,211,141,159,227,135,94,129,111,157,207,61,238,50,61,248,22,233,148,195,235,130,171,159,234];
    let bob: [u8; 32] = [35,243,156,249,133,143,223,252,148,130,157,135,112,247,155,183,12,255,196,164,60,239,89,56,70,205,241,43,43,147,53,44];
    let alice: [u8; 32] = [28,222,178,97,59,209,72,177,169,9,152,206,68,88,0,172,160,29,192,237,60,242,9,214,151,140,197,171,242,12,208,27];
    let secp = Secp256k1::new();

    let alice_keypair = KeyPair::from_secret_key(&secp,&SecretKey::from_slice(&alice).unwrap());
    return format!("{:?}", alice_keypair.public_key());
}

#[derive(Debug)]
pub enum SignatureType {
    Ecdsa { secret_key: SecretKey, prev_output: TxOut },
    Schnorr { secret_key: SecretKey, prev_output: TxOut, script: Option<Script>, spend_info: Option<TaprootSpendInfo> }
}

impl SignatureType {
    pub fn new_ecdsa(secret_key: &SecretKey, prev_output: &TxOut) -> Self {
        SignatureType::Ecdsa { secret_key: secret_key.clone(), prev_output: prev_output.clone() }
    }

    pub fn new_schnorr(secret_key: &SecretKey, prev_output: &TxOut, script: Option<Script>, spend_info: Option<TaprootSpendInfo>) -> Self {
        SignatureType::Schnorr { secret_key: secret_key.clone(), prev_output: prev_output.clone(), script: script.clone(), spend_info: spend_info.clone() }
    }
}

pub struct TransactionBuilder {
    version: i32,
    lock_time: u32,
    input: Vec<TxIn>,
    signing_options: Vec<Option<SignatureType>>,
    output: Vec<TxOut>,
}

impl TransactionBuilder {
    fn new() -> Self {
        Self {
            version: 1,
            lock_time: 0,
            input: vec![],
            signing_options: vec![],
            output: vec![],
        }
    }

    fn bip_341(mut self) -> Self {
        self.version = 2;
        self
    }

    fn lock_time(mut self, lock_time: u32) -> Self {
        self.lock_time = lock_time;
        self
    }

    fn add_input(mut self, prev_output: OutPoint) -> Self {
        self.input.push(self._create_tx_input(prev_output));
        self.signing_options.push(None);

        self
    }

    fn add_input_with_signing_options(mut self, prev_output: OutPoint, signing_options: SignatureType) -> Self {
        self.input.push(self._create_tx_input(prev_output));
        self.signing_options.push(Some(signing_options));

        self
    }

    fn add_output(mut self, output: TxOut) -> Self {
        self.output.push(output);
        self
    }

    fn finalize(self) -> Transaction {
        let secp = Secp256k1::new();

        let mut tx = Transaction {
            version: self.version,
            lock_time: PackedLockTime(self.lock_time),
            input: self.input,
            output: self.output,
        };

        for (index, signing_ops) in self.signing_options.iter().enumerate() {
            match signing_ops {
                Some(op) => {
                    match op {
                        SignatureType::Ecdsa {secret_key, prev_output} => {
                            sign_tx_input_ecdsa(&mut tx, index, secret_key, prev_output, &secp);
                        },
                        SignatureType::Schnorr {secret_key, prev_output, script, spend_info} => {
                            sign_p2tr_tx_input_schnorr(&mut tx, index, prev_output, secret_key, script.clone(), spend_info.clone(), &secp)
                        }
                    }
                },
                None => {}
            }
        }

        tx
    }

    fn _create_tx_input(&self, prev_output: OutPoint) -> TxIn {
        TxIn {
            previous_output: prev_output,
            script_sig: Default::default(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    // use p256k1::keys::XOnlyPublicKey as p256k1_XOnlyPublicKey;
    use super::test::helpers::{Harness};

    use super::*;

    #[test]
    fn should_spend_valid_p2tr_transaction_with_script_path_via_script_path() {
        let harness = Harness::new();

        // create user source transaction keys
        let (miner_secret_key, _, miner_public_key, _, miner_address, miner_secp) = harness.wallet("miner");
        let (bob_secret_key, _, bob_public_key, _, bob_address, bob_secp) = harness.wallet("bob");
        let (alice_secret_key, _, alice_public_key, _, alice_address, alice_secp) = harness.wallet("alice");

        let coinbase_txn = harness.coinbase();

        // source_uxto belongs to miner
        let source_utxo = &coinbase_txn.output[0];
        let outpoint = OutPoint::new(coinbase_txn.txid(), 0);
        let fee = harness.get_fee();

        let (script, spend_info) = create_script(&alice_public_key, &miner_secp);

        let tx = TransactionBuilder::new()
            .bip_341()
            .add_input_with_signing_options(outpoint, SignatureType::new_ecdsa(&miner_secret_key, &source_utxo))
            .add_output(create_p2tr_output(source_utxo.value - fee, alice_public_key, Some(spend_info.clone()), &miner_secp))
            .finalize();

        assert!(harness.test_mempool_acceptance(&consensus_encode(&tx)));
        let blockhash = harness.mine_transaction(&tx, &miner_address);
        assert!(harness.tx_in_block(tx.txid(), blockhash.clone()));

        let source_txn = harness.get_raw_transaction(&tx.txid(), Some(blockhash.clone()));

        let source_utxo = &source_txn.output[0];
        let outpoint = OutPoint::new(source_txn.txid(), 0);
        let fee = harness.get_fee();

        // tx to send from alice to bob
        //    - spends a p2tr input via key path
        //    - creates a p2tr output
        //    - signed with schnorr to enable spending of p2tr output via key path

        let tx = TransactionBuilder::new()
            .bip_341()
            .add_input_with_signing_options(outpoint, SignatureType::new_schnorr(&alice_secret_key, &source_utxo, Some(script), Some(spend_info)))
            .add_output(create_p2tr_output(source_utxo.value - fee, bob_public_key, None, &miner_secp))
            .finalize();

        assert!(harness.test_mempool_acceptance(&consensus_encode(&tx)));
        assert!(harness.tx_in_block(tx.txid(), harness.mine_transaction(&tx, &miner_address)));
    }

    #[test]
    fn stenography() {
        let harness = Harness::new();
        let (miner_secret_key, _, miner_public_key, _, miner_address, miner_secp) = harness.wallet("miner");
        let (_, _, alice_public_key, _, _, _) = harness.wallet("alice");

        let source_txn = harness.coinbase();
        let source_utxo = &source_txn.output[0];

        let outpoint = OutPoint::new(source_txn.txid(), 0);
        let fee = harness.get_fee();
        let (script, spend_info) = create_steno_script(&miner_public_key, &alice_public_key, "test".to_string(), &miner_secp);

        let tx = TransactionBuilder::new()
            .bip_341()
            .add_input_with_signing_options(
                outpoint, 
                SignatureType::new_ecdsa(&miner_secret_key, &source_utxo)
              )
            .add_output(create_p2tr_output(
                &source_utxo.value - fee, 
                miner_public_key, 
                Some(spend_info.clone()), 
                &miner_secp)
            )
            .finalize();
        
        let tx_bytes = &consensus_encode(&tx);
        assert!(harness.test_mempool_acceptance(tx_bytes));
        // println!("btcdeb --txin={} --tx={}", &consensus_encode(&source_txn), tx_bytes);
        assert!(harness.tx_in_block(tx.txid(), harness.mine_transaction(&tx, &miner_address)));

        let tx2 = TransactionBuilder::new()
            .bip_341()
            .add_input_with_signing_options(
                OutPoint::new(tx.txid(), 0), 
                SignatureType::new_schnorr(
                    &miner_secret_key, 
                    &source_utxo, 
                    Some(script), 
                    Some(spend_info.clone())
                  )
              )
            .add_output(create_p2tr_output(
                &tx.output[0].value - fee, 
                alice_public_key, 
                Some(spend_info.clone()), 
                &miner_secp)
            )
            .finalize();
    }
  }
