#![allow(non_snake_case)]

/*
    Multi-party ECDSA

    Copyright 2018 by Kzen Networks

    This file is part of Multi-party ECDSA library
    (https://github.com/KZen-networks/multi-party-ecdsa)

    Multi-party ECDSA is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/multi-party-ecdsa/blob/master/LICENSE>
*/

use core::fmt;
use std::fmt::Debug;

use centipede::juggling::proof_system::{Helgamalsegmented, Witness};
use centipede::juggling::segmentation::Msegmentation;
use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives::commitments::traits::Commitment;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::*;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::cryptographic_primitives::secret_sharing::feldman_vss::VerifiableSS;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use crate::Error::{self, InvalidSig, Phase5BadSum, Phase6Error};
use paillier::{
    Decrypt, DecryptionKey, EncryptionKey, KeyGeneration, Paillier, RawCiphertext, RawPlaintext,
};

use serde::{Deserialize, Serialize};
use zk_paillier::zkproofs::NiCorrectKeyProof;
use zk_paillier::zkproofs::{CompositeDLogProof, DLogStatement};

use crate::protocols::multi_party_ecdsa::gg_2020::ErrorType;
use crate::utilities::zk_pdl_with_slack::{PDLwSlackProof, PDLwSlackStatement, PDLwSlackWitness};
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;

use std::convert::TryInto;

const SECURITY: usize = 256;
const PAILLIER_MIN_BIT_LENGTH: usize = 2047;
const PAILLIER_MAX_BIT_LENGTH: usize = 2048;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Parameters {
    pub threshold: u16,   //t
    pub share_count: u16, //n
}

impl fmt::Display for Parameters {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "threshold={}, share_count={}.", self.threshold, self.share_count)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Keys<E: Curve = Secp256k1> {
    pub u_i: Scalar<E>, // random scalar ui
    pub Y_i: Point<E>, // Point on curve Ui = ui*G
    pub dk: DecryptionKey, // Paillier DecryptionKey p & q
    pub ek: EncryptionKey, // Paillier EncryptionKey n=p*q & N=n*n
    pub party_index: usize,
    pub N_tilde: BigInt,
    pub h1: BigInt,
    pub h2: BigInt,
    pub xhi: BigInt,
    pub xhi_inv: BigInt,
}

impl fmt::Display for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
r#"u_i:{}
y_i:
    x:{}
    y:{}
dk:
    p:{}
    q:{}
ek:
    n:{}
    nn:{}
party_index:{},
N_tilde:{}
h1:{}
h2:{}
xhi:{}
xhi_inv:{}"#, 
        self.u_i.to_bigint().to_hex(), 
        self.Y_i.x_coord().unwrap().to_hex(), 
        self.Y_i.y_coord().unwrap().to_hex(),
        self.dk.p.to_hex(),
        self.dk.q.to_hex(),
        self.ek.n.to_hex(),
        self.ek.nn.to_hex(),
        self.party_index,
        self.N_tilde.to_hex(),
        self.h1.to_hex(),
        self.h2.to_hex(),
        self.xhi.to_hex(),
        self.xhi_inv.to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PartyPrivate {
    u_i: Scalar<Secp256k1>,
    x_i: Scalar<Secp256k1>,
    dk: DecryptionKey,
}

impl fmt::Display for PartyPrivate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "u_i:{}\nx_i:{}\ndk:\n\tp:{}\n\tq:{}", self.u_i.to_bigint().to_hex(), self.x_i.to_bigint().to_hex(), self.dk.p.to_hex(), self.dk.q.to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenBroadcastMessage1 {
    pub e: EncryptionKey,
    pub dlog_statement: DLogStatement,
    pub com: BigInt,
    pub correct_key_proof: NiCorrectKeyProof,
    pub composite_dlog_proof_base_h1: CompositeDLogProof,
    pub composite_dlog_proof_base_h2: CompositeDLogProof,
}

impl KeyGenBroadcastMessage1{
    pub fn Display_correct_key_proof(&self) -> String {
        let mut correct_key_proof = String::new();
        for x in self.correct_key_proof.sigma_vec.iter(){
            correct_key_proof.push_str(format!(r#"{},
    "#, x.to_hex()).as_str());
        }
        correct_key_proof
    }
}

pub fn Display_NiCorrectKeyProof(proof:&NiCorrectKeyProof) -> String{
    let mut ret = String::new();
    for x in proof.sigma_vec.iter(){
        ret.push_str(format!(r#"{},
    "#, x.to_hex()).as_str());
    }

    ret
}

impl fmt::Display for KeyGenBroadcastMessage1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut correct_key_proof = String::new();
        for x in self.correct_key_proof.sigma_vec.iter(){
            correct_key_proof.push_str(format!(r#"{},
    "#, x.to_hex()).as_str());
        }
        write!(f, 
r#"e(EncryptionKey):
    n:{}
    nn:{}
dlog_statement(DLogStatement):
    N:{}
    g:{}
    ni:{}
com:{}
correct_key_proof(NiCorrectKeyProof):
    {}
composite_dlog_proof_base_h1(CompositeDLogProof):
    x:{}
    y:{}
composite_dlog_proof_base_h2(CompositeDLogProof):
    x:{}
    y:{}"#, 
        self.e.n.to_hex(),
        self.e.nn.to_hex(),
        self.dlog_statement.N.to_hex(),
        self.dlog_statement.g.to_hex(),
        self.dlog_statement.ni.to_hex(),
        self.com.to_hex(),
        correct_key_proof,
        self.composite_dlog_proof_base_h1.x.to_hex(),
        self.composite_dlog_proof_base_h1.y.to_hex(),
        self.composite_dlog_proof_base_h2.x.to_hex(),
        self.composite_dlog_proof_base_h2.y.to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyGenDecommitMessage1 { 
    pub blind_factor: BigInt, // 随机因子
    /// Ui = u1*G
    pub Y_i: Point<Secp256k1>, 
}

impl fmt::Display for KeyGenDecommitMessage1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
r#"blind_factor:{}
Y_i(Point<Secp256k1>):
    x:{}
    y:{}"#,
        self.blind_factor.to_hex(),
        self.Y_i.x_coord().unwrap().to_hex(),
        self.Y_i.y_coord().unwrap().to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedKeys {
    pub Y: Point<Secp256k1>,
    pub x_i: Scalar<Secp256k1>,
}

impl fmt::Display for SharedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
r#"Y(Point<Secp256k1>):
    x:{}
    y:{}
x_i(Scalar<Secp256k1>):{}"#,
        self.Y.x_coord().unwrap().to_hex(),
        self.Y.y_coord().unwrap().to_hex(),
        self.x_i.to_bigint().to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignKeys {
    pub w_i: Scalar<Secp256k1>,
    pub g_w_i: Point<Secp256k1>,
    pub k_i: Scalar<Secp256k1>,
    pub gamma_i: Scalar<Secp256k1>,
    pub g_gamma_i: Point<Secp256k1>,
}

impl fmt::Display for SignKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, 
r#"w_i(Scalar<Secp256k1>):{}
g_w_i(Point<Secp256k1>):
    x:{}
    y:{}
k_i(Scalar<Secp256k1>):{}
gamma_i(Scalar<Secp256k1>):{}
g_gamma_i(Point<Secp256k1>):
    x:{}
    y:{}"#,
        self.w_i.to_bigint().to_hex(),
        self.g_w_i.x_coord().unwrap().to_hex(),
        self.g_w_i.y_coord().unwrap().to_hex(),
        self.k_i.to_bigint().to_hex(),
        self.gamma_i.to_bigint().to_hex(),
        self.g_gamma_i.x_coord().unwrap().to_hex(),
        self.g_gamma_i.y_coord().unwrap().to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignBroadcastPhase1 {
    pub com: BigInt,
}

impl fmt::Display for SignBroadcastPhase1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.com.to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignDecommitPhase1 {
    pub blind_factor: BigInt,
    pub g_gamma_i: Point<Secp256k1>,
}

impl fmt::Display for SignDecommitPhase1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blind_factor:{}\ng_gamma_i:\n\tx:{}\n\ty:{}", self.blind_factor.to_hex(), self.g_gamma_i.x_coord().unwrap().to_hex(), self.g_gamma_i.y_coord().unwrap().to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSignature {
    pub r: Scalar<Secp256k1>,
    pub R: Point<Secp256k1>,
    pub s_i: Scalar<Secp256k1>,
    pub m: BigInt,
    pub y: Point<Secp256k1>,
}

impl fmt::Display for LocalSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"r:{}
R:
    x:{}
    y:{}
s_i:{}
m:{}
y:
    x:{}
    y:{}"#, self.r.to_bigint().to_hex(), self.R.x_coord().unwrap().to_hex(), self.R.y_coord().unwrap().to_hex(),
            self.s_i.to_bigint().to_hex(), self.m.to_hex(), self.y.x_coord().unwrap().to_hex(), self.y.y_coord().unwrap().to_hex())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: Scalar<Secp256k1>,
    pub s: Scalar<Secp256k1>,
    pub recid: u8,
}

impl fmt::Display for SignatureRecid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "r:{}\ns:{}\nrecid:{}", self.r.to_bigint().to_hex(), self.s.to_bigint().to_hex(), self.recid)
    }
}

pub fn generate_h1_h2_N_tilde() -> (BigInt, BigInt, BigInt, BigInt, BigInt) {
    // note, should be safe primes:
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();;
    //log::info!("-vv- generate_h1_h2_N_tilde -vv-");

    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    //log::info!("create a new Paillier keypair ek_tilde(n, nn) and dk_tilde(p, q):");
    //log::info!("ek_tilde is:\nn:\n{}\nnn:\n{}", ek_tilde.n.to_hex(), ek_tilde.nn.to_hex());
    //log::info!("dk_tilde is:\np:\n{}\nq:\n{}", dk_tilde.p.to_hex(), dk_tilde.q.to_hex());

    let one = BigInt::one();
    //log::info!("one is:\n{}", one.to_hex());

    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    //log::info!("phi(=(dk_tilde.p-1)*(dk_tilde.q-1)) is:\n{}", phi.to_hex());

    let h1 = BigInt::sample_below(&ek_tilde.n);
    //log::info!("h1(sample below ek_tilde.n) is:\n{}", h1.to_hex());

    let (mut xhi, mut xhi_inv) = loop {
        let xhi_ = BigInt::sample_below(&phi);
        match BigInt::mod_inv(&xhi_, &phi) {
            Some(inv) => break (xhi_, inv),
            None => continue,
        }
    };
    //log::info!("random sample xhi_ below phi, ensure xhi_inv exists.");
    //log::info!("xhi(sample below phi) is:\n{}", xhi.to_hex());
    //log::info!("xhi_inv(where xhi_inv*xhi = 1 mod phi) is:\n{}", xhi_inv.to_hex());

    let h2 = BigInt::mod_pow(&h1, &xhi, &ek_tilde.n);
    //log::info!("h2(=h1^xhi mod ek_tilde.n) is:\n{}", h2.to_hex());

    xhi = BigInt::sub(&phi, &xhi);
    //log::info!("xhi'(=phi - xhi) is:\n{}", xhi.to_hex());

    xhi_inv = BigInt::sub(&phi, &xhi_inv);
    //log::info!("xhi_inv'(phi - xhi_inv) is:\n{}", xhi_inv.to_hex());

    //log::info!("-^^- generate_h1_h2_N_tilde -^^-");
    //log::info!("-^^- returns (ek_tilde.n, h1, h2, xhi, xhi_inv) -^^-");
    (ek_tilde.n, h1, h2, xhi, xhi_inv)
}

impl Keys {
    pub fn create(index: usize) -> Self {
        log::info!("-vv- Keys.create -vv-");

        let u = Scalar::<Secp256k1>::random(); // 文档u1
        log::info!("u(random scalar) is:\n{:#?}\n", u);

        let Y = Point::generator() * &u; // 文档U1
        log::info!("Y(=u*G, point on curve) is:\n\tx:{}\n\ty:{}", Y.x_coord().unwrap().to_hex(), Y.y_coord().unwrap().to_hex());

        let (ek, dk) = Paillier::keypair().keys();
        log::info!("Paillier keypair:random sample 1024 bits prime p & q, ek.n=p*q, ek.nn=ek.n*ek.n:");
        log::info!("ek(Paillier keypair EncryptionKey) is:");
        log::info!("\tek-n is:\n{:#?}\n", ek.n.to_hex()); //文档n
        log::info!("\tek-nn is:\n{:#?}\n", ek.nn.to_hex()); // 文档n^2
        
        log::info!("dk(Paillier keypair decryptionKey) is:");
        log::info!("\tdk-p is:\n{:#?}\n", dk.p.to_hex()); // 文档p1
        log::info!("\tdk-q is:\n{:#?}\n", dk.q.to_hex()); // 文档q1

        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        log::info!("N_tilde is:\n{:#?}\n", N_tilde.to_hex());
        log::info!("h1 is:\n{:#?}\n", h1.to_hex());
        log::info!("h2 is:\n{:#?}\n", h2.to_hex());
        log::info!("xhi is:\n{:#?}\n", xhi.to_hex());
        log::info!("xhi_inv is:\n{:#?}\n", xhi_inv.to_hex());
        
        log::info!("-^^- Keys.create -^^-");
        log::info!("-^^- returns (u_i=u, y_i=y, dk, ek, party_index, N_tilde, h1, h2, xhi, xhi_inv) -^^-");
        Self {
            u_i: u,
            Y_i: Y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn create_safe_prime(index: usize) -> Self {
        let u = Scalar::<Secp256k1>::random();
        let y = Point::generator() * &u;

        let (ek, dk) = Paillier::keypair_safe_primes().keys();
        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Self {
            u_i: u,
            Y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }
    pub fn create_from(u: Scalar<Secp256k1>, index: usize) -> Self {
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();
        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Self {
            u_i: u,
            Y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    pub fn phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2(
        &self,
    ) -> (KeyGenBroadcastMessage1, KeyGenDecommitMessage1) {
        log::info!("-vv-Keys::phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2-vv-");

        let blind_factor = BigInt::sample(SECURITY);
        log::info!("blind_factor(256bits sample) is:\n{}", blind_factor.to_hex());

        let correct_key_proof = NiCorrectKeyProof::proof(&self.dk, None);
        log::info!("correct_key_proof is:\n\t{}", Display_NiCorrectKeyProof(&correct_key_proof));
        //log::info!("This protocol is based on the NIZK protocol in https://eprint.iacr.org/2018/057.pdf, for parameters = e = N, m2 = 11, alpha = 6370 see https://eprint.iacr.org/2018/987.pdf 6.2.3 for full details.");

        let dlog_statement_base_h1 = DLogStatement {
            N: self.N_tilde.clone(),
            g: self.h1.clone(),
            ni: self.h2.clone(),
        };
        // log::info!("dlog_statement_base_h1.N(=N_tilde) is:\n{}", dlog_statement_base_h1.N.to_hex());
        // log::info!("dlog_statement_base_h1.g(=h1) is:\n{}", dlog_statement_base_h1.g.to_hex());
        // log::info!("dlog_statement_base_h1.ni(=h2) is:\n{}", dlog_statement_base_h1.ni.to_hex());

        let dlog_statement_base_h2 = DLogStatement {
            N: self.N_tilde.clone(),
            g: self.h2.clone(),
            ni: self.h1.clone(),
        };
        // log::info!("dlog_statement_base_h2.N(=N_tilde) is:\n{}", dlog_statement_base_h2.N.to_hex());
        // log::info!("dlog_statement_base_h2.g(=h2) is:\n{}", dlog_statement_base_h2.g.to_hex());
        // log::info!("dlog_statement_base_h2.ni(=h1) is:\n{}", dlog_statement_base_h2.ni.to_hex());

        let composite_dlog_proof_base_h1 =
            CompositeDLogProof::prove(&dlog_statement_base_h1, &self.xhi);
        log::info!("composite_dlog_proof_base_h1(CompositeDLogProof of dlog_statement_base_h1)");
        log::info!("composite_dlog_proof_base_h1.x is:\n{}", composite_dlog_proof_base_h1.x.to_hex());
        log::info!("composite_dlog_proof_base_h1.y is:\n{}", composite_dlog_proof_base_h1.y.to_hex());

        let composite_dlog_proof_base_h2 =
            CompositeDLogProof::prove(&dlog_statement_base_h2, &self.xhi_inv);
        log::info!("composite_dlog_proof_base_h2(CompositeDLogProof of dlog_statement_base_h2)");
        log::info!("composite_dlog_proof_base_h2.x is:\n{}", composite_dlog_proof_base_h2.x.to_hex());
        log::info!("composite_dlog_proof_base_h2.y is:\n{}", composite_dlog_proof_base_h2.y.to_hex());

        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(self.Y_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        log::info!("com(=hash of (y_i(compressed) | blind_factor)) is:\n{}", com.to_hex());

        let bcm1 = KeyGenBroadcastMessage1 {
            e: self.ek.clone(),
            dlog_statement: dlog_statement_base_h1,
            com,
            correct_key_proof,
            composite_dlog_proof_base_h1,
            composite_dlog_proof_base_h2,
        };
        log::info!("bcm1:\n{}", bcm1);
        // log::info!("bcm1.e(ek).n is:\n{}", bcm1.e.n.to_hex());
        // log::info!("bcm1.e(ek).nn is:\n{}", bcm1.e.nn.to_hex());
        // log::info!("bcm1.dlog_statement(dlog_statement_base_h1).N is:\n{}", bcm1.dlog_statement.N.to_hex());
        // log::info!("bcm1.dlog_statement(dlog_statement_base_h1).g is:\n{}", bcm1.dlog_statement.g.to_hex());
        // log::info!("bcm1.dlog_statement(dlog_statement_base_h1).ni is:\n{}", bcm1.dlog_statement.ni.to_hex());
        // log::info!("bcm1.com is:\n{}", bcm1.com.to_hex());
        // log::info!("bcm1.correct_key_proof is:\n{:#?}", bcm1.correct_key_proof);
        // log::info!("bcm1.composite_dlog_proof_base_h1.x is:\n{}", bcm1.composite_dlog_proof_base_h1.x.to_hex());
        // log::info!("bcm1.composite_dlog_proof_base_h1.y is:\n{}", bcm1.composite_dlog_proof_base_h1.y.to_hex());
        // log::info!("bcm1.composite_dlog_proof_base_h2.x is:\n{}", bcm1.composite_dlog_proof_base_h2.x.to_hex());
        // log::info!("bcm1.composite_dlog_proof_base_h2.y is:\n{}", bcm1.composite_dlog_proof_base_h2.y.to_hex());

        let decom1 = KeyGenDecommitMessage1 {
            blind_factor,
            Y_i: self.Y_i.clone(),
        };
        log::info!("decom1:\n{}", decom1);

        // log::info!("decom1.blind_factor is:\n{}", decom1.blind_factor.to_hex());
        // log::info!("decom1.y_i is:\n{:#?}", decom1.y_i);

        log::info!("-^^-Keys::phase1_broadcast_phase3_proof_of_correct_key_proof_of_correct_h1h2-^^-");
        log::info!("-^^_ returns  (bcm1, decom1) --^^--");

        (bcm1, decom1)
    }

    pub fn phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute(
        &self,
        params: &Parameters,
        decom_vec: &[KeyGenDecommitMessage1],
        bc1_vec: &[KeyGenBroadcastMessage1],
    ) -> Result<(VerifiableSS<Secp256k1>, Vec<Scalar<Secp256k1>>, usize), ErrorType> {
        log::info!("-vv- Keys::phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute -vv-");
        log::info!("params:\n{}", params);
        log::info!("decom_vec len:\n{}", decom_vec.len());
        log::info!("decom_vec[0]:\n{}", decom_vec[0]);
        log::info!("bc1_vec len:\n{}", bc1_vec.len());
        log::info!("bc1_vec[0]:\n{}", bc1_vec[0]);

        let mut bad_actors_vec = Vec::new();
        // test length:
        log::info!("Test length of decom_vec = share_count && bc1_vec = share_count");
        assert_eq!(decom_vec.len(), usize::from(params.share_count));
        assert_eq!(bc1_vec.len(), usize::from(params.share_count));

        // test paillier correct key, h1,h2 correct generation and test decommitments
        log::info!("test paillier correct key, h1,h2 correct generation and test decommitments");
        let correct_key_correct_decom_all = (0..bc1_vec.len())
            .map(|i| {
                log::info!("test index = {}:", i);
                let dlog_statement_base_h2 = DLogStatement {
                    N: bc1_vec[i].dlog_statement.N.clone(),
                    g: bc1_vec[i].dlog_statement.ni.clone(),
                    ni: bc1_vec[i].dlog_statement.g.clone(),
                };
                log::info!("dlog_statement_base_h2(bc1_vec[i]) is:\n\tN:\n{}\n\tg:\n{}\n\tni:\n{}", dlog_statement_base_h2.N.to_hex(), dlog_statement_base_h2.g.to_hex(), dlog_statement_base_h2.ni.to_hex());
                let hash1 = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                    &BigInt::from_bytes(&decom_vec[i].Y_i.to_bytes(true)),
                    &decom_vec[i].blind_factor,
                );
                log::info!("Sha256 of (decom_vec[i].y_i || decom_vec[i].blind_factor) is:\n{}", hash1.to_hex());
                log::info!("bc1_vec[i].com is:\n{}", bc1_vec[i].com.to_hex());
                let bool1 = hash1 == bc1_vec[i].com;
                log::info!("test-1(hash of decom and bc.com should equal) is {}", bool1);

                let bool2 = bc1_vec[i]
                    .correct_key_proof
                    .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                    .is_ok();
                log::info!("bc1_vec[i].correct_key_proof is:\n{}", bc1_vec[i].Display_correct_key_proof());
                log::info!("test-2(bc1_vec[i].correct_key_proof.verify result) is {}", bool2);

                let bool3 = bc1_vec[i].e.n.bit_length() >= PAILLIER_MIN_BIT_LENGTH;
                log::info!("test-3(bc1_vec[i].e.n.bit_length() >= PAILLIER_MIN_BIT_LENGTH verify result) is {}, where length is {}, should bigger than {}", bool3, bc1_vec[i].e.n.bit_length(), PAILLIER_MIN_BIT_LENGTH);

                let bool4 = bc1_vec[i].e.n.bit_length() <= PAILLIER_MAX_BIT_LENGTH;
                log::info!("test-4(bc1_vec[i].e.n.bit_length() <= PAILLIER_MAX_BIT_LENGTH verify result) is {}, where length is {}, should less than {}", bool4, bc1_vec[i].e.n.bit_length(), PAILLIER_MAX_BIT_LENGTH);

                let bool5 = bc1_vec[i].dlog_statement.N.bit_length() >= PAILLIER_MIN_BIT_LENGTH;
                log::info!("test-5(bc1_vec[i].dlog_statement.N.bit_length() >= PAILLIER_MIN_BIT_LENGTH) is {}, where length is {}, should bigger than {}", bool5, bc1_vec[i].dlog_statement.N.bit_length(), PAILLIER_MIN_BIT_LENGTH);

                let bool6 = bc1_vec[i].dlog_statement.N.bit_length() <= PAILLIER_MAX_BIT_LENGTH;
                log::info!("test-6(bc1_vec[i].dlog_statement.N.bit_length() <= PAILLIER_MAX_BIT_LENGTH) is {}, where length is {}, should less than {}", bool6, bc1_vec[i].dlog_statement.N.bit_length(), PAILLIER_MAX_BIT_LENGTH);

                //CompositeDLogProof: x,y(point on curve)
                // verify1: statement.N > 2^128; 
                // verify2: gcd(statement.g, statement.N)=1; 
                // verify3: gcd(statement.ni, statement.N)=1; 
                // let e = hash(x | g | N | ni);
                // let ni_e = ni^e mod N;\n
                // let g_y = g^y mod N;\n
                // let g_y_ni_e = g_y * ni_e mod N;\n
                // verify4: x == g_y_ni_e;
                let bool7 = bc1_vec[i]
                    .composite_dlog_proof_base_h1
                    .verify(&bc1_vec[i].dlog_statement)
                    .is_ok();
                log::info!("test-7(composite_dlog_proof_base_h1.verify) is {}", bool7);
                log::info!("CompositeDLogProof: x,y(point on curve);\nverify1: statement.N > 2^128;\nverify2: gcd(statement.g, statement.N)=1;\nverify3: gcd(statement.ni, statement.N)=1;\nlet e = hash(x | g | N | ni);\nlet ni_e = ni^e mod N;\nlet g_y = g^y mod N;\nlet g_y_ni_e = g_y * ni_e mod N;\nverify4: x == g_y_ni_e;");

                let bool8 = bc1_vec[i]
                    .composite_dlog_proof_base_h2
                    .verify(&dlog_statement_base_h2)
                    .is_ok();
                log::info!("test-8(composite_dlog_proof_base_h2.verify) is {}", bool8);

                let test_res = bool1 && bool2 && bool3 && bool4 && bool5 && bool6 && bool7 && bool8;

                log::info!("test index = {}, result = {}:", i, test_res);
                // let test_res =
                //     HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                //         &BigInt::from_bytes(&decom_vec[i].y_i.to_bytes(true)),
                //         &decom_vec[i].blind_factor,
                //     ) == bc1_vec[i].com
                //         && bc1_vec[i]
                //             .correct_key_proof
                //             .verify(&bc1_vec[i].e, zk_paillier::zkproofs::SALT_STRING)
                //             .is_ok()
                //         && bc1_vec[i].e.n.bit_length() >= PAILLIER_MIN_BIT_LENGTH
                //         && bc1_vec[i].e.n.bit_length() <= PAILLIER_MAX_BIT_LENGTH
                //         && bc1_vec[i].dlog_statement.N.bit_length() >= PAILLIER_MIN_BIT_LENGTH
                //         && bc1_vec[i].dlog_statement.N.bit_length() <= PAILLIER_MAX_BIT_LENGTH
                //         && bc1_vec[i]
                //             .composite_dlog_proof_base_h1
                //             .verify(&bc1_vec[i].dlog_statement)
                //             .is_ok()
                //         && bc1_vec[i]
                //             .composite_dlog_proof_base_h2
                //             .verify(&dlog_statement_base_h2)
                //             .is_ok();
                if !test_res {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let err_type = ErrorType {
            error_type: "invalid key".to_string(),
            bad_actors: bad_actors_vec,
        };

        //guy TODO: 需要底层实现，secret_shares 包括多项式pi(x) = ui + a1x + a1^2x + ...,令x=1，2，3，计算得到pi(1),pi(2),pi(3)，计算方为1时，发送p1(2)给2，发送p1(3)给3
        let (vss_scheme, secret_shares) =
            VerifiableSS::share(params.threshold, params.share_count, &self.u_i);
        log::info!("VerifiableSS::share, input t={}, n={}, secret(u)={}", params.threshold, params.share_count, self.u_i.to_bigint().to_hex());
        log::info!("vss_scheme is:\n{:#?}", vss_scheme);
        log::info!("secret_shares is:\n{:#?}", secret_shares.to_vec());
        
        log::info!("-^^- Keys::phase1_verify_com_phase3_verify_correct_key_verify_dlog_phase2_distribute -^^-");
        log::info!("returns vss_scheme, secret_shares, party_index");
        if correct_key_correct_decom_all {
            Ok((vss_scheme, secret_shares.to_vec(), self.party_index))
        } else {
            Err(err_type)
        }
    }

    pub fn phase2_verify_vss_construct_keypair_phase3_pok_dlog(
        &self,
        params: &Parameters,
        y_vec: &[Point<Secp256k1>],
        secret_shares_vec: &[Scalar<Secp256k1>],
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
        index: usize,
    ) -> Result<(SharedKeys, DLogProof<Secp256k1, Sha256>), ErrorType> {
        log::info!("--vv-- Keys.phase2_verify_vss_construct_keypair_phase3_pok_dlog --vv--");
        let mut bad_actors_vec = Vec::new();
        
        log::info!("verify y_vec.len() == secret_shares_vec.len() == vss_scheme_vec.len() == params.share_count = {}", usize::from(params.share_count));
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(secret_shares_vec.len(), usize::from(params.share_count));
        assert_eq!(vss_scheme_vec.len(), usize::from(params.share_count));

        log::info!("Loop for y_vec,secret_shares_vec,vss_scheme_vec to validate share.");
        let correct_ss_verify = (0..y_vec.len())
            .map(|i| {
                log::info!("validate_share for {}", i);
                log::info!("vss_scheme_vec[{}] is:\n{:#?}", i, vss_scheme_vec[i]);
                log::info!("secret_shares_vec[{}] is:\n{:#?}", i, secret_shares_vec[i]);
                log::info!("index(self.party_i) is:{}", index);
                let res = vss_scheme_vec[i]
                    .validate_share(&secret_shares_vec[i], index.try_into().unwrap())
                    .is_ok()
                    && vss_scheme_vec[i].commitments[0] == y_vec[i];
                log::info!("validate_share result is {}", res);
                if !res {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);
        log::info!("Finished loop to validate share, result is {}.", correct_ss_verify);

        let err_type = ErrorType {
            error_type: "invalid vss".to_string(),
            bad_actors: bad_actors_vec,
        };

        if correct_ss_verify {
            log::info!("Accumulate y_vec points.");
            let (head, tail) = y_vec.split_at(1);
            let y = tail.iter().fold(head[0].clone(), |acc, x| acc + x);
            log::info!("y=sum(y_vec) is:\n{:#?}", y);

            log::info!("Accumulate secret_shares_vec");
            let x_i = secret_shares_vec
                .iter()
                .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
            log::info!("x_i=sum(secret_shares_vec) is:\n{}", x_i.to_bigint().to_hex());

            log::info!("生成针对 x_i 的椭圆曲线零知识证明dlog_proof。");
            let dlog_proof = DLogProof::prove(&x_i);
            log::info!("dlog_proof is:\n{:#?}", dlog_proof);

            log::info!("--^^-- Keys.phase2_verify_vss_construct_keypair_phase3_pok_dlog --^^--");
            log::info!("returns: SharedKeys(y, x_i), dlog_proof");
            Ok((SharedKeys { Y: y, x_i }, dlog_proof))
        } else {
            Err(err_type)
        }
    }

    pub fn get_commitments_to_xi(
        vss_scheme_vec: &[VerifiableSS<Secp256k1>],
    ) -> Vec<Point<Secp256k1>> {
        log::info!("--vv-- Keys.get_commitments_to_xi --vv--");
        let len = vss_scheme_vec.len();
        let (head, tail) = vss_scheme_vec.split_at(1);
        let mut global_coefficients = head[0].commitments.clone();
        for vss in tail {

            for (i, coefficient_commitment) in vss.commitments.iter().enumerate() {
                global_coefficients[i] = &global_coefficients[i] + coefficient_commitment;
            }
        }
        log::info!("For i add vssi(com0, com1,...) in vss_scheme_vec into vss0(com0, com1, ...)");
        log::info!("vss0(head, also as global_vss) is:\n{:#?}", global_coefficients);

        let global_vss = VerifiableSS {
            parameters: vss_scheme_vec[0].parameters.clone(),
            commitments: global_coefficients,
        };
        log::info!("从i=1到i={}生成点多项式i^n*Pn+...+P1 in global_vss.commitments", len);
        let ret = (1..=len)
            .map(|i| global_vss.get_point_commitment(i.try_into().unwrap()))
            .collect::<Vec<Point<Secp256k1>>>();
        log::info!("ret is:\n{:#?}", ret);
        log::info!("--^^-- Keys.get_commitments_to_xi --^^--");
        ret
    }

    pub fn update_commitments_to_xi(
        comm: &Point<Secp256k1>,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: usize,
        s: &[usize],
    ) -> Point<Secp256k1> {
        let s: Vec<u16> = s.iter().map(|&i| i.try_into().unwrap()).collect();
        let li = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &vss_scheme.parameters,
            index.try_into().unwrap(),
            s.as_slice(),
        );
        comm * &li
    }

    pub fn verify_dlog_proofs_check_against_vss(
        params: &Parameters,
        dlog_proofs_vec: &[DLogProof<Secp256k1, Sha256>],
        y_vec: &[Point<Secp256k1>],
        vss_vec: &[VerifiableSS<Secp256k1>],
    ) -> Result<(), ErrorType> {
        log::info!("--vv-- Keys.verify_dlog_proofs_check_against_vss --vv--");
        let mut bad_actors_vec = Vec::new();

        log::info!("check y_vec.len == dlog_proofs_vec.len == params.share_count = {}", usize::from(params.share_count));
        assert_eq!(y_vec.len(), usize::from(params.share_count));
        assert_eq!(dlog_proofs_vec.len(), usize::from(params.share_count));

        let xi_commitments = Keys::get_commitments_to_xi(vss_vec);

        log::info!("loop to verify dlog_proofs_vec[i] for i in [0, {})", y_vec.len());
        let xi_dlog_verify = (0..y_vec.len())
            .map(|i| {
                let ver_res = DLogProof::verify(&dlog_proofs_vec[i]).is_ok();
                let verify_against_vss = xi_commitments[i] == dlog_proofs_vec[i].pk;
                if !ver_res || !verify_against_vss {
                    bad_actors_vec.push(i);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);
        log::info!("verify result is {}", xi_dlog_verify);

        let err_type = ErrorType {
            error_type: "bad dlog proof".to_string(),
            bad_actors: bad_actors_vec,
        };
        log::info!("--^^-- Keys.verify_dlog_proofs_check_against_vss --^^--");

        if xi_dlog_verify {
            Ok(())
        } else {
            Err(err_type)
        }
    }
}

impl PartyPrivate {
    pub fn set_private(key: Keys, shared_key: SharedKeys) -> Self {
        Self {
            u_i: key.u_i,
            x_i: shared_key.x_i,
            dk: key.dk,
        }
    }

    pub fn y_i(&self) -> Point<Secp256k1> {
        let g = Point::generator();
        g * &self.u_i
    }

    pub fn decrypt(&self, ciphertext: BigInt) -> RawPlaintext {
        Paillier::decrypt(&self.dk, &RawCiphertext::from(ciphertext))
    }

    pub fn refresh_private_key(&self, factor: &Scalar<Secp256k1>, index: usize) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair().keys();

        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Keys {
            u_i: u,
            Y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    // we recommend using safe primes if the code is used in production
    pub fn refresh_private_key_safe_prime(&self, factor: &Scalar<Secp256k1>, index: usize) -> Keys {
        let u: Scalar<Secp256k1> = &self.u_i + factor;
        let y = Point::generator() * &u;
        let (ek, dk) = Paillier::keypair_safe_primes().keys();

        let (N_tilde, h1, h2, xhi, xhi_inv) = generate_h1_h2_N_tilde();

        Keys {
            u_i: u,
            Y_i: y,
            dk,
            ek,
            party_index: index,
            N_tilde,
            h1,
            h2,
            xhi,
            xhi_inv,
        }
    }

    // used for verifiable recovery
    pub fn to_encrypted_segment(
        &self,
        segment_size: usize,
        num_of_segments: usize,
        pub_ke_y: &Point<Secp256k1>,
        g: &Point<Secp256k1>,
    ) -> (Witness, Helgamalsegmented) {
        Msegmentation::to_encrypted_segments(&self.u_i, &segment_size, num_of_segments, pub_ke_y, g)
    }

    pub fn update_private_key(
        &self,
        factor_u_i: &Scalar<Secp256k1>,
        factor_x_i: &Scalar<Secp256k1>,
    ) -> Self {
        PartyPrivate {
            u_i: &self.u_i + factor_u_i,
            x_i: &self.x_i + factor_x_i,
            dk: self.dk.clone(),
        }
    }
}

impl SignKeys {
    pub fn g_w_vec(
        pk_vec: &[Point<Secp256k1>],
        s: &[usize],
        vss_scheme: &VerifiableSS<Secp256k1>,
    ) -> Vec<Point<Secp256k1>> {
        let s: Vec<u16> = s.iter().map(|&i| i.try_into().unwrap()).collect();
        // TODO: check bounds
        (0..s.len())
            .map(|i| {
                let li = VerifiableSS::<Secp256k1>::map_share_to_new_params(
                    &vss_scheme.parameters,
                    s[i],
                    s.as_slice(),
                );
                &pk_vec[s[i] as usize] * &li
            })
            .collect::<Vec<Point<Secp256k1>>>()
    }

    pub fn create(
        private_x_i: &Scalar<Secp256k1>,
        vss_scheme: &VerifiableSS<Secp256k1>,
        index: usize,
        s: &[usize],
    ) -> Self {
        log::info!("--vv--SignKeys.create--vv--");
        log::info!("args private_x_i:\n{}", private_x_i.to_bigint().to_hex());
        log::info!("args vss_scheme:\n{:#?}", vss_scheme);
        log::info!("args index={}", index);
        log::info!("args s={:#?}", s);

        let s: Vec<u16> = s.iter().map(|&i| i.try_into().unwrap()).collect();
        //log::info!("compute lambda_{{index,S}}, a lagrangian coefficient that change the (t,n) scheme to (|S|,|S|), used in http://stevengoldfeder.com/papers/GG18.pdf, also Evaluates lagrange basis polynomial.");
        log::info!("map_share_to_new_params, input:vss_scheme.parameters(not used), index={}, s={:#?}", index, s);
        let li = VerifiableSS::<Secp256k1>::map_share_to_new_params(
            &vss_scheme.parameters,
            index.try_into().unwrap(),
            s.as_slice(),
        );
        log::info!("map_share_to_new_params, return li:Scalar:\n{}", li.to_bigint().to_hex());

        let w_i = li * private_x_i;
        log::info!("w_i = li * private_x_i:\n{}", w_i.to_bigint().to_hex());

        let g = Point::generator();
        let g_w_i = g * &w_i;
        log::info!("g_w_i = w_i*G,G is generator:\nx:\n\t{}\ny:\n\t{}", g_w_i.x_coord().unwrap().to_hex(), g_w_i.y_coord().unwrap().to_hex());

        let gamma_i = Scalar::<Secp256k1>::random();
        log::info!("gamma_i is a random scalar:\n{}", gamma_i.to_bigint().to_hex());

        let g_gamma_i = g * &gamma_i;
        log::info!("g_gamma_i = gamma_i*G,G is generator:\nx:\n\t{}\ny:\n\t{}", g_gamma_i.x_coord().unwrap().to_hex(), g_gamma_i.y_coord().unwrap().to_hex());

        let k_i = Scalar::<Secp256k1>::random();
        log::info!("k_i is a random scalar:\n{}", k_i.to_bigint().to_hex());

        log::info!("--^^--SignKeys.create, returns w_i, g_w_i, k_i, gamma_i, g_gamma_i.--^^--");

        Self {
            w_i,
            g_w_i,
            k_i,
            gamma_i,
            g_gamma_i,
        }
    }

    pub fn phase1_broadcast(&self) -> (SignBroadcastPhase1, SignDecommitPhase1) {
        log::info!("--vv--SignKeys.phase1_broadcast--vv--");

        let blind_factor = BigInt::sample(SECURITY);
        log::info!("blind_factor is a random number of 256bits:\n{}", blind_factor.to_hex());

        //let g = Point::generator();
        let g_gamma_i = self.g_gamma_i.clone();// 这里，使用已经计算的结果 g * &self.gamma_i;
        //log::info!("g_gamma_i = self.gamma_i*G,G is generator:\nx:\n\t{}\ny:\n\t{}", g_gamma_i.x_coord().unwrap().to_hex(), g_gamma_i.y_coord().unwrap().to_hex());

        let com = HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
            &BigInt::from_bytes(g_gamma_i.to_bytes(true).as_ref()),
            &blind_factor,
        );
        log::info!("com=h(g_gamma_i-compressed | blind_factor):\n{}", com.to_hex());

        log::info!("--^^--SignKeys.phase1_broadcast, returns SignBroadcastPhase1 {{ com }}, SignDecommitPhase1 {{blind_factor, g_gamma_i}}--^^--");
        (
            SignBroadcastPhase1 { com },
            SignDecommitPhase1 {
                blind_factor,
                g_gamma_i: self.g_gamma_i.clone(),
            },
        )
    }

    pub fn phase2_delta_i(
        &self,
        alpha_vec: &[Scalar<Secp256k1>],
        beta_vec: &[Scalar<Secp256k1>],
    ) -> Scalar<Secp256k1> {
        let vec_len = alpha_vec.len();
        assert_eq!(alpha_vec.len(), beta_vec.len());
        // assert_eq!(alpha_vec.len(), self.s.len() - 1);
        let ki_gamma_i = &self.k_i * &self.gamma_i;

        (0..vec_len)
            .map(|i| &alpha_vec[i] + &beta_vec[i])
            .fold(ki_gamma_i, |acc, x| acc + x)
    }

    pub fn phase2_sigma_i(
        &self,
        miu_vec: &[Scalar<Secp256k1>],
        ni_vec: &[Scalar<Secp256k1>],
    ) -> Scalar<Secp256k1> {
        let vec_len = miu_vec.len();
        assert_eq!(miu_vec.len(), ni_vec.len());
        //assert_eq!(miu_vec.len(), self.s.len() - 1);
        let ki_w_i = &self.k_i * &self.w_i;
        (0..vec_len)
            .map(|i| &miu_vec[i] + &ni_vec[i])
            .fold(ki_w_i, |acc, x| acc + x)
    }

    pub fn phase3_compute_t_i(
        sigma_i: &Scalar<Secp256k1>,
    ) -> (
        Point<Secp256k1>,
        Scalar<Secp256k1>,
        PedersenProof<Secp256k1, Sha256>,
    ) {
        let g_sigma_i = Point::generator() * sigma_i;
        let l = Scalar::<Secp256k1>::random();
        let h_l = Point::<Secp256k1>::base_point2() * &l;
        let T = g_sigma_i + h_l;
        let T_zk_proof = PedersenProof::<Secp256k1, Sha256>::prove(sigma_i, &l);

        (T, l, T_zk_proof)
    }
    pub fn phase3_reconstruct_delta(delta_vec: &[Scalar<Secp256k1>]) -> Scalar<Secp256k1> {
        let sum = delta_vec
            .iter()
            .fold(Scalar::<Secp256k1>::zero(), |acc, x| acc + x);
        sum.invert().unwrap()
    }

    pub fn phase4(
        delta_inv: &Scalar<Secp256k1>,
        b_proof_vec: &[&DLogProof<Secp256k1, Sha256>],
        phase1_decommit_vec: Vec<SignDecommitPhase1>,
        bc1_vec: &[SignBroadcastPhase1],
        index: usize,
    ) -> Result<Point<Secp256k1>, ErrorType> {
        let mut bad_actors_vec = Vec::new();
        let test_b_vec_and_com = (0..b_proof_vec.len())
            .map(|j| {
                let ind = if j < index { j } else { j + 1 };
                let res = b_proof_vec[j].pk == phase1_decommit_vec[ind].g_gamma_i
                    && HashCommitment::<Sha256>::create_commitment_with_user_defined_randomness(
                        &BigInt::from_bytes(
                            phase1_decommit_vec[ind].g_gamma_i.to_bytes(true).as_ref(),
                        ),
                        &phase1_decommit_vec[ind].blind_factor,
                    ) == bc1_vec[ind].com;
                if !res {
                    bad_actors_vec.push(ind);
                    false
                } else {
                    true
                }
            })
            .all(|x| x);

        let mut g_gamma_i_iter = phase1_decommit_vec.iter();
        let head = g_gamma_i_iter.next().unwrap();
        let tail = g_gamma_i_iter;

        let err_type = ErrorType {
            error_type: "bad gamma_i decommit".to_string(),
            bad_actors: bad_actors_vec,
        };

        if test_b_vec_and_com {
            Ok({
                let gamma_sum = tail.fold(head.g_gamma_i.clone(), |acc, x| acc + &x.g_gamma_i);
                // R
                gamma_sum * delta_inv
            })
        } else {
            Err(err_type)
        }
    }
}

impl LocalSignature {
    pub fn phase5_proof_pdl(
        R_dash: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
        k_ciphertext: &BigInt,
        ek: &EncryptionKey,
        k_i: &Scalar<Secp256k1>,
        k_enc_randomness: &BigInt,
        dlog_statement: &DLogStatement,
    ) -> PDLwSlackProof {
        // Generate PDL with slack statement, witness and proof
        let pdl_w_slack_statement = PDLwSlackStatement {
            ciphertext: k_ciphertext.clone(),
            ek: ek.clone(),
            Q: R_dash.clone(),
            G: R.clone(),
            h1: dlog_statement.g.clone(),
            h2: dlog_statement.ni.clone(),
            N_tilde: dlog_statement.N.clone(),
        };

        let pdl_w_slack_witness = PDLwSlackWitness {
            x: k_i.clone(),
            r: k_enc_randomness.clone(),
        };

        PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement)
    }

    pub fn phase5_verify_pdl(
        pdl_w_slack_proof_vec: &[PDLwSlackProof],
        R_dash: &Point<Secp256k1>,
        R: &Point<Secp256k1>,
        k_ciphertext: &BigInt,
        ek: &EncryptionKey,
        dlog_statement: &[DLogStatement],
        s: &[usize],
        i: usize,
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();

        let num_of_other_participants = s.len() - 1;
        if pdl_w_slack_proof_vec.len() != num_of_other_participants {
            bad_actors_vec.push(i);
        } else {
            let proofs_verification = (0..pdl_w_slack_proof_vec.len())
                .map(|j| {
                    let ind = if j < i { j } else { j + 1 };
                    let pdl_w_slack_statement = PDLwSlackStatement {
                        ciphertext: k_ciphertext.clone(),
                        ek: ek.clone(),
                        Q: R_dash.clone(),
                        G: R.clone(),
                        h1: dlog_statement[s[ind]].g.clone(),
                        h2: dlog_statement[s[ind]].ni.clone(),
                        N_tilde: dlog_statement[s[ind]].N.clone(),
                    };
                    let ver_res = pdl_w_slack_proof_vec[j].verify(&pdl_w_slack_statement);
                    if ver_res.is_err() {
                        bad_actors_vec.push(i);
                        false
                    } else {
                        true
                    }
                })
                .all(|x| x);
            if proofs_verification {
                return Ok(());
            }
        }

        let err_type = ErrorType {
            error_type: "Bad PDLwSlack proof".to_string(),
            bad_actors: bad_actors_vec,
        };
        Err(err_type)
    }

    pub fn phase5_check_R_dash_sum(R_dash_vec: &[Point<Secp256k1>]) -> Result<(), Error> {
        let sum = R_dash_vec
            .iter()
            .fold(Point::generator().to_point(), |acc, x| acc + x);
        match sum - &Point::generator().to_point() == Point::generator().to_point() {
            true => Ok(()),
            false => Err(Phase5BadSum),
        }
    }

    pub fn phase6_compute_S_i_and_proof_of_consistency(
        R: &Point<Secp256k1>,
        T: &Point<Secp256k1>,
        sigma: &Scalar<Secp256k1>,
        l: &Scalar<Secp256k1>,
    ) -> (Point<Secp256k1>, HomoELGamalProof<Secp256k1, Sha256>) {
        let S = R * sigma;
        let delta = HomoElGamalStatement {
            G: R.clone(),
            H: Point::<Secp256k1>::base_point2().clone(),
            Y: Point::generator().to_point(),
            D: T.clone(),
            E: S.clone(),
        };
        let witness = HomoElGamalWitness {
            x: l.clone(),
            r: sigma.clone(),
        };
        let proof = HomoELGamalProof::prove(&witness, &delta);

        (S, proof)
    }

    pub fn phase6_verify_proof(
        S_vec: &[Point<Secp256k1>],
        proof_vec: &[HomoELGamalProof<Secp256k1, Sha256>],
        R_vec: &[Point<Secp256k1>],
        T_vec: &[Point<Secp256k1>],
    ) -> Result<(), ErrorType> {
        let mut bad_actors_vec = Vec::new();
        let mut verify_proofs = true;
        for i in 0..proof_vec.len() {
            let delta = HomoElGamalStatement {
                G: R_vec[i].clone(),
                H: Point::<Secp256k1>::base_point2().clone(),
                Y: Point::generator().to_point(),
                D: T_vec[i].clone(),
                E: S_vec[i].clone(),
            };
            if proof_vec[i].verify(&delta).is_err() {
                verify_proofs = false;
                bad_actors_vec.push(i);
            };
        }

        match verify_proofs {
            true => Ok(()),
            false => {
                let err_type = ErrorType {
                    error_type: "phase6".to_string(),
                    bad_actors: bad_actors_vec,
                };
                Err(err_type)
            }
        }
    }

    pub fn phase6_check_S_i_sum(
        pubkey_y: &Point<Secp256k1>,
        S_vec: &[Point<Secp256k1>],
    ) -> Result<(), Error> {
        let sum_plus_g = S_vec
            .iter()
            .fold(Point::generator().to_point(), |acc, x| acc + x);
        let sum = sum_plus_g - &Point::generator().to_point();

        match &sum == pubkey_y {
            true => Ok(()),
            false => Err(Phase6Error),
        }
    }

    pub fn phase7_local_sig(
        k_i: &Scalar<Secp256k1>,
        message: &BigInt,
        R: &Point<Secp256k1>,
        sigma_i: &Scalar<Secp256k1>,
        pubkey: &Point<Secp256k1>,
    ) -> Self {
        let m_fe = Scalar::<Secp256k1>::from(message);
        let r = Scalar::<Secp256k1>::from(
            &R.x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let s_i = m_fe * k_i + &r * sigma_i;
        Self {
            r,
            R: R.clone(),
            s_i,
            m: message.clone(),
            y: pubkey.clone(),
        }
    }

    pub fn output_signature(&self, s_vec: &[Scalar<Secp256k1>]) -> Result<SignatureRecid, Error> {
        let mut s = s_vec.iter().fold(self.s_i.clone(), |acc, x| acc + x);
        let s_bn = s.to_bigint();

        let r = Scalar::<Secp256k1>::from(
            &self
                .R
                .x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        );
        let ry: BigInt = self
            .R
            .y_coord()
            .unwrap()
            .mod_floor(Scalar::<Secp256k1>::group_order());

        /*
         Calculate recovery id - it is not possible to compute the public key out of the signature
         itself. Recovery id is used to enable extracting the public key uniquely.
         1. id = R.y & 1
         2. if (s > curve.q / 2) id = id ^ 1
        */
        let is_ry_odd = ry.test_bit(0);
        let mut recid = if is_ry_odd { 1 } else { 0 };
        let s_tag_bn = Scalar::<Secp256k1>::group_order() - &s_bn;
        if s_bn > s_tag_bn {
            s = Scalar::<Secp256k1>::from(&s_tag_bn);
            recid ^= 1;
        }
        let sig = SignatureRecid { r, s, recid };
        let ver = verify(&sig, &self.y, &self.m).is_ok();
        if ver {
            Ok(sig)
        } else {
            Err(InvalidSig)
        }
    }
}

pub fn verify(sig: &SignatureRecid, y: &Point<Secp256k1>, message: &BigInt) -> Result<(), Error> {
    let b = sig.s.invert().unwrap();
    let a = Scalar::<Secp256k1>::from(message);
    let u1 = a * &b;
    let u2 = &sig.r * &b;

    let g = Point::generator();
    let gu1 = g * u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick

    if sig.r
        == Scalar::<Secp256k1>::from(
            &(gu1 + yu2)
                .x_coord()
                .unwrap()
                .mod_floor(Scalar::<Secp256k1>::group_order()),
        )
    {
        Ok(())
    } else {
        Err(InvalidSig)
    }
}
