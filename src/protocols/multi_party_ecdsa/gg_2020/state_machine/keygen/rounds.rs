use core::fmt;
use curv::arithmetic::Converter;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use sha2::Sha256;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use paillier::EncryptionKey;
use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;
use zk_paillier::zkproofs::DLogStatement;

use crate::protocols::multi_party_ecdsa::gg_2020::party_i::{
    KeyGenBroadcastMessage1, KeyGenDecommitMessage1, Keys,
};
use crate::protocols::multi_party_ecdsa::gg_2020::{self, ErrorType};

pub struct Round0 {
    pub party_i: u16,
    pub t: u16,
    pub n: u16,
}

impl Round0 { // 文档Step1
    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<gg_2020::party_i::KeyGenBroadcastMessage1>>,
    {
        log::info!("====Round 0 start=====");
        let party_keys = Keys::create(self.party_i as usize);
        log::info!("party_keys:\n{}", party_keys);

        let (bc1, decom1) =
            party_keys.phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2();
        log::info!("bc1:\n{}", bc1);
        log::info!("decom1:\n{}", decom1);

        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: bc1.clone(),
        });
        
        log::info!("====Round 0 over, output bc1=====");
        Ok(Round1 {
            keys: party_keys,
            bc1,
            decom1,
            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    keys: Keys,
    bc1: KeyGenBroadcastMessage1,
    decom1: KeyGenDecommitMessage1,
    party_i: u16,
    t: u16,
    n: u16,
}

impl Round1 { // 文档Step2
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenBroadcastMessage1>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<gg_2020::party_i::KeyGenDecommitMessage1>>,
    {
        log::info!("====Round 1 start=====");
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: self.decom1.clone(),
        });
        log::info!("input before insert bc1:\n{:#?}", input);
        log::info!("====Round 1 over, output decom1=====");
        Ok(Round2 {
            keys: self.keys,
            received_comm: input.into_vec_including_me(self.bc1),
            decom: self.decom1,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        false
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenBroadcastMessage1>> {
        let ret = containers::BroadcastMsgsStore::new(i, n);
        ret
    }
}

pub struct Round2 { // 文档Step3、4
    keys: gg_2020::party_i::Keys,
    received_comm: Vec<KeyGenBroadcastMessage1>,
    decom: KeyGenDecommitMessage1,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round2 {
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<KeyGenDecommitMessage1>,
        mut output: O,
    ) -> Result<Round3>
    where
        O: Push<Msg<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>)>>,
    {
        log::info!("====Round 2 start=====");
        log::info!("input:\n{:#?}", input);
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let received_decom = input.into_vec_including_me(self.decom);
        log::info!("received_decom:\n{:#?}", received_decom);

        let vss_result = self
            .keys
            .phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
                &params,
                &received_decom,
                &self.received_comm,
            )
            .map_err(ProceedError::Round2VerifyCommitments)?;
        
        log::info!("Loop for vss_result.secret_shares, output ones which is not mine.");
        for (i, share) in vss_result.1.iter().enumerate() {
            if i + 1 == usize::from(self.party_i) {
                continue;
            }
            log::info!("output vss_result.vss_scheme and vss_result.secret_shares index(from 1 count)={}, self index={}", i+1, self.party_i);
            output.push(Msg {
                sender: self.party_i,
                receiver: Some(i as u16 + 1),
                body: (vss_result.0.clone(), share.clone()),
            })
        }

        log::info!("====Round 2 over=====");

        Ok(Round3 {
            keys: self.keys,

            y_vec: received_decom.into_iter().map(|d| d.y_i).collect(),
            bc_vec: self.received_comm,

            own_vss: vss_result.0.clone(),
            own_share: vss_result.1[usize::from(self.party_i - 1)].clone(),

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<KeyGenDecommitMessage1>> {
        let ret = containers::BroadcastMsgsStore::new(i, n);
        ret
    }
}

pub struct Round3 { // 文档Step5\6\7\8?
    keys: gg_2020::party_i::Keys,

    y_vec: Vec<Point<Secp256k1>>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,

    own_vss: VerifiableSS<Secp256k1>,
    own_share: Scalar<Secp256k1>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round3 {
    pub fn proceed<O>(
        self,
        input: P2PMsgs<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>)>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<DLogProof<Secp256k1, Sha256>>>,
    {
        log::info!("====Round 3 start=====");
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };
        let (vss_schemes, party_shares): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((self.own_vss, self.own_share))
            .into_iter()
            .unzip();
        log::info!("input vss_schemes(len={}) and party_shares(len={})", vss_schemes.len(), party_shares.len());

        let (shared_keys, dlog_proof) = self
            .keys
            .phase2_verify_vss_construct_keypair_phase3_pok_dlog(
                &params,
                &self.y_vec,
                &party_shares,
                &vss_schemes,
                self.party_i.into(),
            )
            .map_err(ProceedError::Round3VerifyVssConstruct)?;

        log::info!("output dlog_proof");
        output.push(Msg {
            sender: self.party_i,
            receiver: None,
            body: dlog_proof.clone(),
        });
        log::info!("====Round 3 finished=====");

        Ok(Round4 {
            keys: self.keys.clone(),
            y_vec: self.y_vec.clone(),
            bc_vec: self.bc_vec,
            shared_keys,
            own_dlog_proof: dlog_proof,
            vss_vec: vss_schemes,

            party_i: self.party_i,
            t: self.t,
            n: self.n,
        })
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<P2PMsgs<(VerifiableSS<Secp256k1>, Scalar<Secp256k1>)>> {
        let ret = containers::P2PMsgsStore::new(i, n);
        ret
    }
}

pub struct Round4 { // 文档 Step9、10、11?
    keys: gg_2020::party_i::Keys,
    y_vec: Vec<Point<Secp256k1>>,
    bc_vec: Vec<gg_2020::party_i::KeyGenBroadcastMessage1>,
    shared_keys: gg_2020::party_i::SharedKeys,
    own_dlog_proof: DLogProof<Secp256k1, Sha256>,
    vss_vec: Vec<VerifiableSS<Secp256k1>>,

    party_i: u16,
    t: u16,
    n: u16,
}

impl Round4 {
    pub fn proceed(
        self,
        input: BroadcastMsgs<DLogProof<Secp256k1, Sha256>>,
    ) -> Result<LocalKey<Secp256k1>> {
        log::info!("====Round 4 start=====");
        let params = gg_2020::party_i::Parameters {
            threshold: self.t,
            share_count: self.n,
        };

        let dlog_proofs = input.into_vec_including_me(self.own_dlog_proof.clone());
        log::info!("dlog_proofs is:\n{:#?}", dlog_proofs);

        Keys::verify_dlog_proofs_check_against_vss(
            &params,
            &dlog_proofs,
            &self.y_vec,
            &self.vss_vec,
        )
        .map_err(ProceedError::Round4VerifyDLogProof)?;

        log::info!("Extract pk from dlog_proofs from 0 to {}", params.share_count);
        let pk_vec = (0..params.share_count as usize)
            .map(|i| dlog_proofs[i].pk.clone())
            .collect::<Vec<Point<Secp256k1>>>();
        log::info!("pk_vec is:\n{:#?}", pk_vec);

        log::info!("Extract paillier_key from bc_vec from 0 to {}", params.share_count);
        let paillier_key_vec = (0..params.share_count)
            .map(|i| self.bc_vec[i as usize].e.clone())
            .collect::<Vec<EncryptionKey>>();
        log::info!("paillier_key_vec is:\n{:#?}", paillier_key_vec);

        log::info!("Extract h1_h2_n_tilde from bc_vec from 0 to {}", self.bc_vec.len()-1);
        let h1_h2_n_tilde_vec = self
            .bc_vec
            .iter()
            .map(|bc1| bc1.dlog_statement.clone())
            .collect::<Vec<DLogStatement>>();
        log::info!("h1_h2_n_tilde_vec is:\n{:#?}", h1_h2_n_tilde_vec);

        log::info!("accumulate yi in y_vec, len = {}", self.y_vec.len());
        let (head, tail) = self.y_vec.split_at(1);
        let y_sum = tail.iter().fold(head[0].clone(), |acc, x| acc + x);
        log::info!("y_sum is:\n{:#?}", y_sum);

        let local_key = LocalKey {
            paillier_dk: self.keys.dk,
            pk_vec,

            keys_linear: self.shared_keys.clone(),
            paillier_key_vec,
            y_sum_s: y_sum,
            h1_h2_n_tilde_vec,

            vss_scheme: self.vss_vec[usize::from(self.party_i - 1)].clone(),

            i: self.party_i,
            t: self.t,
            n: self.n,
        };
        log::info!("local_key is(and return):\n{}", local_key);
        log::info!("====Round 4 finish=====");

        Ok(local_key)
    }
    pub fn is_expensive(&self) -> bool {
        true
    }
    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<DLogProof<Secp256k1, Sha256>>> {
        let ret = containers::BroadcastMsgsStore::new(i, n);
        ret
    }
}

/// Local secret obtained by party after [keygen](super::Keygen) protocol is completed
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LocalKey<E: Curve> {
    pub paillier_dk: paillier::DecryptionKey,
    pub pk_vec: Vec<Point<E>>,
    pub keys_linear: gg_2020::party_i::SharedKeys,
    pub paillier_key_vec: Vec<EncryptionKey>,
    pub y_sum_s: Point<E>,
    pub h1_h2_n_tilde_vec: Vec<DLogStatement>,
    pub vss_scheme: VerifiableSS<E>,
    pub i: u16,
    pub t: u16,
    pub n: u16,
}

impl fmt::Display for LocalKey<Secp256k1> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
r#"paillier_dk:
    p:
        {}
    q:
        {}
pk_vec:
    {:#?}
keys_linear:
    {}
paillier_key_vec:
    {:#?}
y_sum_s:
    x:
        {}
    y:
        {}
h1_h2_n_tilde_vec:
    {:#?}
vss_scheme:
    {:#?}
i:{}
t:{}
n:{}"#, self.paillier_dk.p.to_hex(),
            self.paillier_dk.q.to_hex(),
            self.pk_vec,
            self.keys_linear,
            self.paillier_key_vec,
            self.y_sum_s.x_coord().unwrap().to_hex(),
            self.y_sum_s.y_coord().unwrap().to_hex(),
            self.h1_h2_n_tilde_vec,
            self.vss_scheme,
            self.i,
            self.t,
            self.n)
    }
}

impl LocalKey<Secp256k1> {
    /// Public key of secret shared between parties
    pub fn public_key(&self) -> Point<Secp256k1> {
        self.y_sum_s.clone()
    }
}

// Errors

type Result<T> = std::result::Result<T, ProceedError>;

/// Proceeding protocol error
///
/// Subset of [keygen errors](enum@super::Error) that can occur at protocol proceeding (i.e. after
/// every message was received and pre-validated).
#[derive(Debug, Error)]
pub enum ProceedError {
    #[error("round 2: verify commitments: {0:?}")]
    Round2VerifyCommitments(ErrorType),
    #[error("round 3: verify vss construction: {0:?}")]
    Round3VerifyVssConstruct(ErrorType),
    #[error("round 4: verify dlog proof: {0:?}")]
    Round4VerifyDLogProof(ErrorType),
}
