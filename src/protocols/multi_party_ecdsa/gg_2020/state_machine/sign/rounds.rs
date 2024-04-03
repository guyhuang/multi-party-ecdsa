#![allow(non_snake_case)]

use core::fmt;
use std::convert::TryFrom;
use std::iter;

use curv::arithmetic::Converter;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use sha2::Sha256;

use round_based::containers::push::Push;
use round_based::containers::{self, BroadcastMsgs, P2PMsgs, Store};
use round_based::Msg;

use crate::utilities::mta::{MessageA, MessageB};

use crate::protocols::multi_party_ecdsa::gg_2020 as gg20;
use crate::utilities::zk_pdl_with_slack::PDLwSlackProof;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::HomoELGamalProof;
use curv::cryptographic_primitives::proofs::sigma_valid_pedersen::PedersenProof;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use gg20::party_i::{
    LocalSignature, SignBroadcastPhase1, SignDecommitPhase1, SignKeys, SignatureRecid,
};
use gg20::state_machine::keygen::LocalKey;
use gg20::ErrorType;

type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Serialize, Deserialize, Debug, Clone)]
#[allow(clippy::upper_case_acronyms)]
pub struct GWI(pub Point<Secp256k1>);
impl fmt::Display for GWI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x:{}\ny:{}", self.0.x_coord().unwrap().to_hex(), self.0.y_coord().unwrap().to_hex())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GammaI(pub MessageB);
impl fmt::Display for GammaI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct WI(pub MessageB);
impl fmt::Display for WI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DeltaI(Scalar<Secp256k1>);
impl fmt::Display for DeltaI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_bigint().to_hex())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TI(pub Point<Secp256k1>);
impl fmt::Display for TI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x:{}\ny:{}", self.0.x_coord().unwrap().to_hex(), self.0.y_coord().unwrap().to_hex())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TIProof(pub PedersenProof<Secp256k1, Sha256>);
impl fmt::Display for TIProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#?}", self.0)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RDash(Point<Secp256k1>);
impl fmt::Display for RDash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x:{}\ny:{}", self.0.x_coord().unwrap().to_hex(), self.0.y_coord().unwrap().to_hex())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SI(pub Point<Secp256k1>);
impl fmt::Display for SI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "x:{}\ny:{}", self.0.x_coord().unwrap().to_hex(), self.0.y_coord().unwrap().to_hex())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HEGProof(pub HomoELGamalProof<Secp256k1, Sha256>);
impl fmt::Display for HEGProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", Round6::Display_homo_elgamal_proof(&self.0))
    }
}

pub struct Round0 {
    /// Index of this party
    ///
    /// Must be in range `[0; n)` where `n` is number of parties involved in signing.
    pub i: u16,

    /// List of parties' indexes from keygen protocol
    ///
    /// I.e. `s_l[i]` must be an index of party `i` that was used by this party in keygen protocol.
    // s_l.len()` equals to `n` (number of parties involved in signing)
    pub s_l: Vec<u16>,

    /// Party local secret share
    pub local_key: LocalKey<Secp256k1>,
}

impl fmt::Display for Round0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "i:{}\ns_l:{:#?}\nlocal_key:\n{}", self.i, self.s_l, self.local_key)
    }
}

impl Round0 { // 文档步骤1
    pub fn Display_point(point: &Point<Secp256k1>) -> String {
        let mut ret = String::new();
        ret.push_str(format!("x:{}\ny:{}", point.x_coord().unwrap().to_hex(), point.y_coord().unwrap().to_hex()).as_str());
        ret.trim_end().into()
    }

    pub fn proceed<O>(self, mut output: O) -> Result<Round1>
    where
        O: Push<Msg<(MessageA, SignBroadcastPhase1)>>,
    {
        log::info!("====Round 0 start=====");
        //log::info!("Round 0 self is:\n{}", self);

        let sign_keys = SignKeys::create(
            &self.local_key.keys_linear.x_i,
            &self.local_key.vss_scheme.clone(),
            usize::from(self.s_l[usize::from(self.i - 1)]) - 1,
            &self
                .s_l
                .iter()
                .map(|&i| usize::from(i) - 1)
                .collect::<Vec<_>>(),
        );
        //log::info!("sign_keys is create from self.local_key.keys_linear.x_i, self.local_key.vss_scheme, self.s_l[(self.i - 1)] - 1, self.s_l:\n{}", sign_keys);

        let (bc1, decom1) = sign_keys.phase1_broadcast();
        log::info!("bc1, generated by sign_keys:\n{}", bc1);
        log::info!("decom1, generated by sign_keys:\n{}", decom1);

        let party_ek = self.local_key.paillier_key_vec[usize::from(self.local_key.i - 1)].clone();
        log::info!("party_ek is local_key.paillier_key_vec[local_key.i - 1]:\nn:\n\t{}\nnn:\n\t{}", party_ek.n.to_hex(), party_ek.nn.to_hex());

        let m_a = MessageA::a(&sign_keys.k_i, &party_ek, &self.local_key.h1_h2_n_tilde_vec);
        log::info!("m_a, MessageA from sign_keys.k_i, party_ek, self.local_key.h1_h2_n_tilde_vec is:\nmessageA:\n\t{}bigint:\n\t{}", m_a.0, m_a.1.to_hex());

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (m_a.0.clone(), bc1.clone()),
        });
        log::info!("output: sender={}, receiver=None, body=(m_a.0, bc1)", self.i);
        
        log::info!("====Round 0 finished=====");

        let round1 = Round1 {
            i: self.i,
            s_l: self.s_l.clone(),
            local_key: self.local_key,
            m_a,
            sign_keys,
            phase1_com: bc1,
            phase1_decom: decom1,
        };

        Ok(round1)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round1 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey<Secp256k1>,
    m_a: (MessageA, BigInt),
    sign_keys: SignKeys,
    phase1_com: SignBroadcastPhase1,
    phase1_decom: SignDecommitPhase1,
}

impl fmt::Display for Round1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"i:{}
s_l:{:#?}
local_key:
    {}
m_a:
    messageA:
        {}
    bigInt:{}
sign_keys:
    {}
phase1_com:
    {}
phase1_decom:
    {}"#, self.i, self.s_l, self.local_key, self.m_a.0, self.m_a.1.to_hex(), self.sign_keys, self.phase1_com, self.phase1_decom)
    }
}

impl Round1 {
    pub fn Display_phase1_decom_vec(phase1_decom_vec :&Vec<SignDecommitPhase1>) -> String {
        let mut ret = String::new();
        for (i, x) in phase1_decom_vec.iter().enumerate(){
            ret.push_str(format!("inxe-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(MessageA, SignBroadcastPhase1)>,
        mut output: O,
    ) -> Result<Round2>
    where
        O: Push<Msg<(GammaI, WI)>>,
    {
        log::info!("====Round 1 start=====");
        log::info!("args:self(Round1):\n{}", self);
        log::info!("args:\ninput(BroadcastMsgs<(MessageA, SignBroadcastPhase1)>):\n{:#?}\n", input);

        let (m_a_vec, bc_vec): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((self.m_a.0.clone(), self.phase1_com.clone()))
            .into_iter()
            .unzip();
        log::info!("add self into input and unzip:\nm_a_vec:{}\nbc_vec:{}", Round2::Display_m_a_vec(&m_a_vec), Round2::Display_bc_vec(&bc_vec));

        let mut m_b_gamma_vec = Vec::new();
        let mut beta_vec = Vec::new();
        let mut m_b_w_vec = Vec::new();
        let mut ni_vec = Vec::new();

        let ttag = self.s_l.len();
        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        log::info!("l_s is:{:#?}", l_s);

        let i = usize::from(self.i - 1);
        log::info!("i is:{:#?}", i);

        log::info!("Loop for j from 0 to {}", ttag-1);
        for j in 0..ttag - 1 {
            let ind = if j < i { j } else { j + 1 };
            log::info!("index {} in vec", ind);

            let (m_b_gamma, beta_gamma, _beta_randomness, _beta_tag) = MessageB::b(
                &self.sign_keys.gamma_i,
                &self.local_key.paillier_key_vec[l_s[ind]],
                m_a_vec[ind].clone(),
                &self.local_key.h1_h2_n_tilde_vec,
            )
            .map_err(|e| {
                Error::Round1(ErrorType {
                    error_type: e.to_string(),
                    bad_actors: vec![],
                })
            })?;
            log::info!("Create MessageB from self.sign_keys.gamma_i, self.local_key.paillier_key_vec[{}], m_a_vec[{}], self.local_key.h1_h2_n_tilde_vec", l_s[ind], ind, );
            log::info!("m_b_gamma:{}", m_b_gamma);
            log::info!("beta_gamma:{}", beta_gamma.to_bigint().to_hex());
            log::info!("_beta_randomness:{}", _beta_randomness.to_hex());
            log::info!("_beta_tag:{}", _beta_tag.to_hex());

            let (m_b_w, beta_wi, _, _) = MessageB::b(
                &self.sign_keys.w_i,
                &self.local_key.paillier_key_vec[l_s[ind]],
                m_a_vec[ind].clone(),
                &self.local_key.h1_h2_n_tilde_vec,
            )
            .map_err(|e| {
                Error::Round1(ErrorType {
                    error_type: e.to_string(),
                    bad_actors: vec![],
                })
            })?;
            log::info!("Create MessageB from self.sign_keys.w_i, self.local_key.paillier_key_vec[{}], m_a_vec[{}], self.local_key.h1_h2_n_tilde_vec", l_s[ind], ind, );
            log::info!("m_b_w:{}", m_b_w);
            log::info!("beta_wi:{}", beta_wi.to_bigint().to_hex());

            m_b_gamma_vec.push(m_b_gamma);
            beta_vec.push(beta_gamma);
            m_b_w_vec.push(m_b_w);
            ni_vec.push(beta_wi);
        }
        log::info!("Loop ended, result is:");
        log::info!("m_b_gamma_vec:\n{}", Round3::Display_mb_gamma_s(&m_b_gamma_vec));
        log::info!("beta_vec:\n{}", Round2::Display_beta_vec(&beta_vec));        
        log::info!("m_b_w_vec:\n{}", Round3::Display_mb_gamma_s(&m_b_w_vec));
        log::info!("ni_vec:\n{}", Round2::Display_beta_vec(&ni_vec));

        let party_indices = (1..=self.s_l.len())
            .map(|j| u16::try_from(j).unwrap())
            .filter(|&j| j != self.i);
        log::info!("Loop in j != self.i:{}", self.i);

        for ((j, gamma_i), w_i) in party_indices.zip(m_b_gamma_vec).zip(m_b_w_vec) {
            log::info!("sender = {}, receiver = index j={}:\n\tgamma_i:\n\t\t{}\n\tw_i:\n\t\t{}", self.i, j, gamma_i, w_i);
            output.push(Msg {
                sender: self.i,
                receiver: Some(j),
                body: (GammaI(gamma_i.clone()), WI(w_i.clone())),
            });
        }

        log::info!("====Round 1 finished=====");

        Ok(Round2 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            beta_vec,
            ni_vec,
            bc_vec,
            m_a_vec,
            phase1_decom: self.phase1_decom,
        })
    }

    pub fn expects_messages(
        i: u16,
        n: u16,
    ) -> Store<BroadcastMsgs<(MessageA, SignBroadcastPhase1)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round2 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey<Secp256k1>,
    sign_keys: SignKeys,
    m_a: (MessageA, BigInt),
    beta_vec: Vec<Scalar<Secp256k1>>,
    ni_vec: Vec<Scalar<Secp256k1>>,
    bc_vec: Vec<SignBroadcastPhase1>,
    m_a_vec: Vec<MessageA>,
    phase1_decom: SignDecommitPhase1,
}

impl fmt::Display for Round2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"i:{}
s_l:{:#?}
local_key:
    {}
sign_keys:
    {}
m_a:
    messageA:
        {}
    bigInt:{}
beta_vec:
    {}
ni_vec:
    {}
bc_vec:
    {}
m_a_vec:
    {}
phase1_decom:
    {}"#, self.i, self.s_l, self.local_key, self.sign_keys, self.m_a.0, self.m_a.1.to_hex(), 
    Round2::Display_beta_vec(&self.beta_vec), Round2::Display_ni_vec(&self.ni_vec), 
    Round2::Display_bc_vec(&self.bc_vec), Round2::Display_m_a_vec(&self.m_a_vec), self.phase1_decom)
    }
}

impl Round2 {
    pub fn Display_beta_vec(beta_vec: &Vec<Scalar<Secp256k1>>) -> String{
        let mut ret = String::new();
        for (i, x) in beta_vec.iter().enumerate(){
            ret.push_str(format!("inxe-{}:{},\n", i, x.to_bigint().to_hex()).as_str());
        }
        ret.trim_end().into()
    }

    pub fn Display_ni_vec(ni_vec: &Vec<Scalar<Secp256k1>>) -> String{
        let mut ret = String::new();
        for (i, x) in ni_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x.to_bigint().to_hex()).as_str());
        }
        ret.trim_end().into()
    }

    pub fn Display_bc_vec(bc_vec: &Vec<SignBroadcastPhase1>) -> String{
        let mut ret = String::new();
        for (i, x) in bc_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }

    pub fn Display_m_a_vec(m_a_vec: &Vec<MessageA>) -> String{
        let mut ret = String::new();
        for (i, x) in m_a_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }

    pub fn proceed<O>(self, input_p2p: P2PMsgs<(GammaI, WI)>, mut output: O) -> Result<Round3>
    where
        O: Push<Msg<(DeltaI, TI, TIProof)>>, // TODO: unify TI and TIProof
    {
        log::info!("====Round 2 start=====");
        log::info!("args:self(Round2):\n{}", self);
        log::info!("args:input_p2p(P2PMsgs<(GammaI, WI)>):\n{:#?}", input_p2p);

        let (m_b_gamma_s, m_b_w_s): (Vec<_>, Vec<_>) = input_p2p
            .into_vec()
            .into_iter()
            .map(|(gamma_i, w_i)| (gamma_i.0, w_i.0))
            .unzip();
        log::info!("Unzip input_p2p into m_b_gamma_s and m_b_w_s:");
        log::info!("m_b_gamma_s:\n{}", Round3::Display_mb_gamma_s(&m_b_gamma_s));
        log::info!("m_b_w_s:\n{}", Round3::Display_mb_gamma_s(&m_b_w_s));

        let mut alpha_vec = Vec::new();
        let mut miu_vec = Vec::new();

        let ttag = self.s_l.len();
        let index = usize::from(self.i) - 1;
        log::info!("ttag(s_l.len)={}, index(self.i-1)={}", ttag, index);

        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        log::info!("l_s(self.s_l[x] -1:{:#?}", l_s);

        let g_w_vec = SignKeys::g_w_vec(
            &self.local_key.pk_vec[..],
            &l_s[..],
            &self.local_key.vss_scheme,
        );
        log::info!("g_w_vec is:\n{}", Round4::Display_t_vec(&g_w_vec));

        log::info!("Loop j from 0 to {}(=ttage-1)", ttag-1);
        for j in 0..ttag - 1 {
            let ind = if j < index { j } else { j + 1 };
            log::info!("index {}(j or j+1) in vec", ind);

            let m_b = m_b_gamma_s[j].clone();
            log::info!("m_b( m_b_gamma_s[j]):\n{}", m_b);

            let alpha_ij_gamma = m_b
                .verify_proofs_get_alpha(&self.local_key.paillier_dk, &self.sign_keys.k_i)
                .map_err(|e| {
                    Error::Round3(ErrorType {
                        error_type: e.to_string(),
                        bad_actors: vec![],
                    })
                })?;
            log::info!("alpha_ij_gamma.0:{}\nalpha_ij_gamma.1:{}", alpha_ij_gamma.0.to_bigint().to_hex(), alpha_ij_gamma.1.to_hex());
            
            let m_b = m_b_w_s[j].clone();
            log::info!("m_b(MessageB of m_b_w_s[{}]:\n{}", j, m_b);

            let alpha_ij_wi = m_b
                .verify_proofs_get_alpha(&self.local_key.paillier_dk, &self.sign_keys.k_i)
                .map_err(|e| {
                    Error::Round3(ErrorType {
                        error_type: e.to_string(),
                        bad_actors: vec![],
                    })
                })?;
            log::info!("alpha_ij_wi.0:{}\nalpha_ij_wi.1:{}", alpha_ij_wi.0.to_bigint().to_hex(), alpha_ij_wi.1.to_hex());
            
            assert_eq!(m_b.b_proof.pk, g_w_vec[ind]); //TODO: return error
            log::info!("ensure m_b.b_proof.pk === g_w_vec[{}]", ind);

            alpha_vec.push(alpha_ij_gamma.0);
            miu_vec.push(alpha_ij_wi.0);
        }
        log::info!("Loop ended, result is:");
        log::info!("alpha_vec:\n{}", Round2::Display_beta_vec(&alpha_vec));
        log::info!("miu_vec:\n{}", Round2::Display_beta_vec(&miu_vec));      

        let delta_i = self.sign_keys.phase2_delta_i(&alpha_vec, &self.beta_vec);
        log::info!("Make phase2_delta_i using alpha_vec and self.beta_vec:{}", delta_i.to_bigint().to_hex());

        let sigma_i = self.sign_keys.phase2_sigma_i(&miu_vec, &self.ni_vec);
        log::info!("Make phase2_sigma_i using miu_vec and self.ni_vec:{}", sigma_i.to_bigint().to_hex());

        let (t_i, l_i, t_i_proof) = SignKeys::phase3_compute_t_i(&sigma_i);
        log::info!("Make phase3_compute_t_i using sigma_i:\nt_i:\n\tx:{}\n\ty:{}\nl_i:{}\nt_i_proof:{:#?}", t_i.x_coord().unwrap().to_hex(), t_i.y_coord().unwrap().to_hex(), l_i.to_bigint().to_hex(), t_i_proof);

        log::info!("sender = {}, receiver = None, body = :\n\tDeltaI:\n\t\t{}\n\tTI:\n\t\tx:{}\n\t\ty:{}\n\tTIProof:\n\t\t{:#?}", self.i, delta_i.to_bigint().to_hex(), t_i.x_coord().unwrap().to_hex(), t_i.y_coord().unwrap().to_hex(), t_i_proof);

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (
                DeltaI(delta_i.clone()),
                TI(t_i.clone()),
                TIProof(t_i_proof.clone()),
            ),
        });
        log::info!("====Round 2 finished=====");

        Ok(Round3 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            mb_gamma_s: m_b_gamma_s,
            bc_vec: self.bc_vec,
            m_a_vec: self.m_a_vec,
            delta_i,
            t_i,
            l_i,
            sigma_i,
            t_i_proof,
            phase1_decom: self.phase1_decom,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<P2PMsgs<(GammaI, WI)>> {
        containers::P2PMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round3 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey<Secp256k1>,
    sign_keys: SignKeys,
    m_a: (MessageA, BigInt),
    mb_gamma_s: Vec<MessageB>,
    bc_vec: Vec<SignBroadcastPhase1>,
    m_a_vec: Vec<MessageA>,
    delta_i: Scalar<Secp256k1>,
    t_i: Point<Secp256k1>,
    l_i: Scalar<Secp256k1>,
    sigma_i: Scalar<Secp256k1>,
    t_i_proof: PedersenProof<Secp256k1, Sha256>,
    phase1_decom: SignDecommitPhase1,
}

impl fmt::Display for Round3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"i:{}
s_l:{:#?}
local_key:
    {}
sign_keys:
    {}
m_a:
    messageA:
        {}
    bigInt:{}
mb_gamma_s:
    {}
bc_vec:
    {}
m_a_vec:
    {}
delta_i:{}
t_i:
    x:{}
    y:{}
l_i:{}
sigma_i:{}
t_i_proof:
    {:#?}
phase1_decom:
    {}"#, 
        self.i, self.s_l, self.local_key, self.sign_keys, self.m_a.0, self.m_a.1.to_hex(), 
        Round3::Display_mb_gamma_s(&self.mb_gamma_s), Round3::Display_bc_vec(&self.bc_vec), Round3::Display_m_a_vec(&self.m_a_vec), 
        self.delta_i.to_bigint().to_hex(), self.t_i.x_coord().unwrap().to_hex(), self.t_i.y_coord().unwrap().to_hex(), self.l_i.to_bigint().to_hex(), 
        self.sigma_i.to_bigint().to_hex(), self.t_i_proof, self.phase1_decom)
    }
}

impl Round3 {
    pub fn Display_mb_gamma_s(mb_gamma_s: &Vec<MessageB>) -> String{
        let mut ret = String::new();
        for (i, x) in mb_gamma_s.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_bc_vec(bc_vec: &Vec<SignBroadcastPhase1>) -> String{
        let mut ret = String::new();
        for (i,x) in bc_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_m_a_vec(m_a_vec: &Vec<MessageA>) -> String{
        let mut ret = String::new();
        for (i,x) in m_a_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }

    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(DeltaI, TI, TIProof)>,
        mut output: O,
    ) -> Result<Round4>
    where
        O: Push<Msg<SignDecommitPhase1>>,
    {
        log::info!("====Round 3 start=====");
        log::info!("args:self(Round3):\n{}", self);
        log::info!("args:inputBroadcastMsgs<(DeltaI, TI, TIProof)>):\n{:#?}", input);

        let (delta_vec, t_vec, t_proof_vec) = input
            .into_vec_including_me((
                DeltaI(self.delta_i),
                TI(self.t_i.clone()),
                TIProof(self.t_i_proof),
            ))
            .into_iter()
            .map(|(delta_i, t_i, t_i_proof)| (delta_i.0, t_i.0, t_i_proof.0))
            .unzip3();        
        log::info!("add self into input and unzip:\ndelta_vec:{}\nt_vec:{}\nt_proof_vec:{:#?}", Round2::Display_ni_vec(&delta_vec), Round4::Display_t_vec(&t_vec), t_proof_vec);

        log::info!("Loop from 0 to {}(t_vec.len) to ensure t_vec[i] === t_proof_vec[i]", t_vec.len());
        for i in 0..t_vec.len() {
            assert_eq!(t_vec[i], t_proof_vec[i].com);
        }

        let delta_inv = SignKeys::phase3_reconstruct_delta(&delta_vec);
        log::info!("Make phase3_reconstruct_delta(delta_inv) from delta_vec:{}", delta_inv.to_bigint().to_hex());

        let ttag = self.s_l.len();
        log::info!("Loop in t_proof_vec[0~{}] for verify PedersonProof.", ttag);
        for proof in t_proof_vec.iter().take(ttag) {
            PedersenProof::verify(proof).map_err(|e| {
                Error::Round3(ErrorType {
                    error_type: e.to_string(),
                    bad_actors: vec![],
                })
            })?;
        }

        log::info!("sender = {}, receiver = None, body = :\n{}", self.i, self.phase1_decom);
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: self.phase1_decom.clone(),
        });
        log::info!("====Round 3 finished=====");

        Ok(Round4 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            m_a: self.m_a,
            mb_gamma_s: self.mb_gamma_s,
            bc_vec: self.bc_vec,
            m_a_vec: self.m_a_vec,
            t_i: self.t_i,
            l_i: self.l_i,
            sigma_i: self.sigma_i,
            phase1_decom: self.phase1_decom,
            delta_inv,
            t_vec,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(DeltaI, TI, TIProof)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round4 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey<Secp256k1>,
    sign_keys: SignKeys,
    m_a: (MessageA, BigInt),
    mb_gamma_s: Vec<MessageB>,
    bc_vec: Vec<SignBroadcastPhase1>,
    m_a_vec: Vec<MessageA>,
    t_i: Point<Secp256k1>,
    l_i: Scalar<Secp256k1>,
    sigma_i: Scalar<Secp256k1>,
    delta_inv: Scalar<Secp256k1>,
    t_vec: Vec<Point<Secp256k1>>,
    phase1_decom: SignDecommitPhase1,
}

impl fmt::Display for Round4{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"i:{}
s_l:{:#?}
local_keys:
    {}
sign_keys:
    {}
m_a:
    messageA:
        {}
    bigInt:{}
mb_gamma_s:
    {}
bc_vec:
    {}
m_a_vec:
    {}
t_i:
    x:{}
    y:{}
l_i:{}
sigma_i:{}
delta_inv:{}
t_vec:
    {}
phase1_decom:
    {}"#, self.i, self.s_l, self.local_key, self.sign_keys, self.m_a.0, self.m_a.1.to_hex(), 
        Round4::Display_mb_gamma_s(&self.mb_gamma_s), Round4::Display_bc_vec(&self.bc_vec), Round4::Display_m_a_vec(&self.m_a_vec), 
            self.t_i.x_coord().unwrap().to_hex(), self.t_i.y_coord().unwrap().to_hex(), self.l_i.to_bigint().to_hex(),
            self.sigma_i.to_bigint().to_hex(), self.delta_inv.to_bigint().to_hex(), Round4::Display_t_vec(&self.t_vec), self.phase1_decom)
    }
}

impl Round4 {
    pub fn Display_mb_gamma_s(mb_gamma_s: &Vec<MessageB>) -> String{
        let mut ret = String::new();
        for (i,x) in mb_gamma_s.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_bc_vec(bc_vec: &Vec<SignBroadcastPhase1>) -> String{
        let mut ret = String::new();
        for (i,x) in bc_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_m_a_vec(m_a_vec: &Vec<MessageA>) -> String{
        let mut ret = String::new();
        for (i,x) in m_a_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_t_vec(t_vec: &Vec<Point<Secp256k1>>) -> String{
        let mut ret = String::new();
        for (i, x) in t_vec.iter().enumerate(){
            ret.push_str(format!("x{}:{},\ny{}:{}", i, x.x_coord().unwrap().to_hex(), i, x.y_coord().unwrap().to_hex()).as_str());
        }
        ret.trim_end().into()
    }

    pub fn Display_dlog_proof(dlog_proof:&DLogProof<Secp256k1, Sha256>) -> String {
        let mut ret = String::new();
        ret.push_str(format!("pk:\n\tx:{}\n\ty:{}\npk_t_rand_commitment:\n\tx:{}\n\ty:{}\nchallenge_response:{}\nhash_choice:{:#?}", dlog_proof.pk.x_coord().unwrap().to_hex(), dlog_proof.pk.y_coord().unwrap().to_hex(),
        dlog_proof.pk_t_rand_commitment.x_coord().unwrap().to_hex(), dlog_proof.pk_t_rand_commitment.y_coord().unwrap().to_hex(),
        dlog_proof.challenge_response.to_bigint().to_hex(), dlog_proof.hash_choice).as_str());
        
        ret.trim_end().into()
    }

    pub fn Display_b_proof_vec(b_proof_vec:&Vec<&DLogProof<Secp256k1, Sha256>>) -> String {
        let mut ret = String::new();
        for (i, x) in b_proof_vec.iter().enumerate(){
            let y = *x;
            ret.push_str(format!("index-{}:{}", i, Round4::Display_dlog_proof(y)).as_str());
        }
        ret.trim_end().into()

    }
    pub fn proceed<O>(
        self,
        decommit_round1: BroadcastMsgs<SignDecommitPhase1>,
        mut output: O,
    ) -> Result<Round5>
    where
        O: Push<Msg<(RDash, Vec<PDLwSlackProof>)>>,
    {
        log::info!("====Round 4 start=====");
        log::info!("args:self(Round4):\n{}", self);
        log::info!("args:decommit_round1(BroadcastMsgs<SignDecommitPhase1>):\n{:#?}", decommit_round1);

        let decom_vec: Vec<_> = decommit_round1.into_vec_including_me(self.phase1_decom.clone());
        log::info!("add self.phase1_decom into decommit_round1 and unzip:\ndecom_vec:{}", Round1::Display_phase1_decom_vec(&decom_vec));

        let ttag = self.s_l.len();
        log::info!("Loop in mb_gamma_s[0~{}] to get b_proof.", ttag-1);
        let b_proof_vec: Vec<_> = (0..ttag - 1).map(|i| &self.mb_gamma_s[i].b_proof).collect();
        log::info!("b_proof_vec:\n{}", Round4::Display_b_proof_vec(&b_proof_vec));

        let R = SignKeys::phase4(
            &self.delta_inv,
            &b_proof_vec[..],
            decom_vec,
            &self.bc_vec,
            usize::from(self.i - 1),
        )
        .map_err(Error::Round5)?;
        log::info!("Make phase4(R) from self.delta_inv, b_proof_vec, decom_vec, self.bc_vec, {}", self.i - 1);
        log::info!("R:\n\t{}", Round0::Display_point(&R));

        let R_dash = &R * &self.sign_keys.k_i;
        log::info!("R_dash(R*self.sign_keys.k_i):\n{}", Round0::Display_point(&R_dash));

        // each party sends first message to all other parties
        let mut phase5_proofs_vec = Vec::new();

        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        log::info!("l_s:{:#?}", l_s);

        let index = usize::from(self.i - 1);
        log::info!("index:{}", index);

        log::info!("Loop from 0 to {} to make phase5_proof_pdl into phase5_proofs_vec:", ttag - 1);
        for j in 0..ttag - 1 {
            let ind = if j < index { j } else { j + 1 };
            let proof = LocalSignature::phase5_proof_pdl(
                &R_dash,
                &R,
                &self.m_a.0.c,
                &self.local_key.paillier_key_vec[l_s[index]],
                &self.sign_keys.k_i,
                &self.m_a.1,
                &self.local_key.h1_h2_n_tilde_vec[l_s[ind]],
            );
            log::info!("index {} of phase5_proof_pdl:\n{}", j, proof);

            phase5_proofs_vec.push(proof);
        }

        log::info!("sender = {}, receiver = None, body = :\nR_dash:\n\t{}\nphase5_proofs_vec\n\t{}", 
            self.i, Round0::Display_point(&R_dash), Round5::Display_phase5_proofs_vec(&phase5_proofs_vec));

        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (RDash(R_dash.clone()), phase5_proofs_vec.clone()),
        });
        log::info!("====Round 4 finished=====");

        Ok(Round5 {
            i: self.i,
            s_l: self.s_l,
            local_key: self.local_key,
            sign_keys: self.sign_keys,
            t_vec: self.t_vec,
            m_a_vec: self.m_a_vec,
            t_i: self.t_i,
            l_i: self.l_i,
            sigma_i: self.sigma_i,
            R,
            R_dash,
            phase5_proofs_vec,
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<SignDecommitPhase1>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round5 {
    i: u16,
    s_l: Vec<u16>,
    local_key: LocalKey<Secp256k1>,
    sign_keys: SignKeys,
    t_vec: Vec<Point<Secp256k1>>,
    m_a_vec: Vec<MessageA>,
    t_i: Point<Secp256k1>,
    l_i: Scalar<Secp256k1>,
    sigma_i: Scalar<Secp256k1>,
    R: Point<Secp256k1>,
    R_dash: Point<Secp256k1>,
    phase5_proofs_vec: Vec<PDLwSlackProof>,
}

impl fmt::Display for Round5 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"i:{}
s_l:{:#?}
local_key:
    {}
sign_keys:
    {}
t_vec:
    {}
m_a_vec:
    {}
t_i:
    x:{}
    y:{}
l_i:{}
sigma_i:{}
R:
    x:{}
    y:{}
R_dash:
    x:{}
    y:{}
phase5_proofs_vec:
    {}"#, self.i, self.s_l, self.local_key, self.sign_keys, Round5::Display_t_vec(&self.t_vec), Round5::Display_m_a_vec(&self.m_a_vec), 
            self.t_i.x_coord().unwrap().to_hex(), self.t_i.y_coord().unwrap().to_hex(), self.l_i.to_bigint().to_hex(), self.sigma_i.to_bigint().to_hex(),
            self.R.x_coord().unwrap().to_hex(), self.R.y_coord().unwrap().to_hex(), self.R_dash.x_coord().unwrap().to_hex(), self.R_dash.y_coord().unwrap().to_hex(),
            Round5::Display_phase5_proofs_vec(&self.phase5_proofs_vec))
    }
}

impl Round5 {
    pub fn Display_t_vec(t_vec: &Vec<Point<Secp256k1>>) -> String{
        let mut ret = String::new();
        for (i, x) in t_vec.iter().enumerate(){
            ret.push_str(format!("x{}:{},\ny{}:{}", i, x.x_coord().unwrap().to_hex(), i, x.y_coord().unwrap().to_hex()).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_m_a_vec(m_a_vec: &Vec<MessageA>) -> String{
        let mut ret = String::new();
        for (i,x) in m_a_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_phase5_proofs_vec(phase5_proofs_vec: &Vec<PDLwSlackProof>) -> String{
        let mut ret = String::new();
        for (i,x) in phase5_proofs_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:{},\n", i, x).as_str());
        }
        ret.trim_end().into()
    }
    pub fn Display_phase5_proofs_vec_vec(phase5_proofs_vec_vec: &Vec<Vec<PDLwSlackProof>>) -> String {
        let mut ret = String::new();
        for (i,x) in phase5_proofs_vec_vec.iter().enumerate(){
            let mut ret_in = String::new();
            for (j,y) in x.iter().enumerate(){
                ret_in.push_str(format!("\tjndex-{}:{},\n", j, y).as_str());
            }
            ret.push_str(format!("index-{}:\n{},\n", i, ret_in.trim_end()).as_str());
        }
        ret.trim_end().into()
    }
    pub fn proceed<O>(
        self,
        input: BroadcastMsgs<(RDash, Vec<PDLwSlackProof>)>,
        mut output: O,
    ) -> Result<Round6>
    where
        O: Push<Msg<(SI, HEGProof)>>,
    {
        log::info!("====Round 5 start=====");
        log::info!("args:self(Round5):\n{}", self);
        log::info!("args:input(BroadcastMsgs<(RDash, Vec<PDLwSlackProof>)>):\n{:#?}", input);

        let (r_dash_vec, pdl_proof_mat_inc_me): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((RDash(self.R_dash), self.phase5_proofs_vec))
            .into_iter()
            .map(|(r_dash, pdl_proof)| (r_dash.0, pdl_proof))
            .unzip();
        log::info!("add self.R_dash and self.phase5_proofs_vec into input and unzip:\nr_dash_vec:\n{}\npdl_proof_mat_inc_me:\n{}", Round4::Display_t_vec(&r_dash_vec), Round5::Display_phase5_proofs_vec_vec(&pdl_proof_mat_inc_me));

        let l_s: Vec<_> = self
            .s_l
            .iter()
            .cloned()
            .map(|i| usize::from(i) - 1)
            .collect();
        log::info!("l_s:{:#?}", l_s);

        let ttag = self.s_l.len();
        log::info!("Loop i from 0 - {} to verify pd1(pdl_proof_mat_inc_me[i], r_dash_vec[i], self.R, self.m_a_vec[i].c, self.local_key.paillier_key_vec[l_s[i]], self.local_key.h1_h2_n_tilde_vec, l_s, i):", ttag);
        for i in 0..ttag {
            LocalSignature::phase5_verify_pdl(
                &pdl_proof_mat_inc_me[i],
                &r_dash_vec[i],
                &self.R,
                &self.m_a_vec[i].c,
                &self.local_key.paillier_key_vec[l_s[i]],
                &self.local_key.h1_h2_n_tilde_vec,
                &l_s,
                i,
            )
            .map_err(Error::Round5)?;
        }

        log::info!("phase5_check_R_dash_sum for r_dash_vec");
        LocalSignature::phase5_check_R_dash_sum(&r_dash_vec).map_err(|e| {
            Error::Round5(ErrorType {
                error_type: e.to_string(),
                bad_actors: vec![],
            })
        })?;

        let (S_i, homo_elgamal_proof) = LocalSignature::phase6_compute_S_i_and_proof_of_consistency(
            &self.R,
            &self.t_i,
            &self.sigma_i,
            &self.l_i,
        );
        log::info!("Compute phase6_compute_S_i_and_proof_of_consistency(S_i, homo_elgamal_proof) from self.R, self.t_i, self.sigma_i, self.l_i");
        log::info!("S_i:\n{}", Round0::Display_point(&S_i));
        log::info!("homo_elgamal_proof:\n{}", Round6::Display_homo_elgamal_proof(&homo_elgamal_proof));

        log::info!("sender = {}, receiver = None, body = S_i, homo_elgamal_proof", self.i);
        output.push(Msg {
            sender: self.i,
            receiver: None,
            body: (SI(S_i.clone()), HEGProof(homo_elgamal_proof.clone())),
        });
        log::info!("====Round 5 finished=====");

        Ok(Round6 {
            S_i,
            homo_elgamal_proof,
            s_l: self.s_l,
            protocol_output: CompletedOfflineStage {
                i: self.i,
                local_key: self.local_key,
                sign_keys: self.sign_keys,
                t_vec: self.t_vec,
                R: self.R,
                sigma_i: self.sigma_i,
            },
        })
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(RDash, Vec<PDLwSlackProof>)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

pub struct Round6 {
    S_i: Point<Secp256k1>,
    homo_elgamal_proof: HomoELGamalProof<Secp256k1, Sha256>,
    s_l: Vec<u16>,
    /// Round 6 guards protocol output until final checks are taken the place
    protocol_output: CompletedOfflineStage,
}

impl fmt::Display for Round6 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"S_i:
    x:{}
    y:{}
homo_elgamal_proof:
    {}
s_l:{:#?}
protocol_output:
    {}
"#, self.S_i.x_coord().unwrap().to_hex(), self.S_i.y_coord().unwrap().to_hex(), Round6::Display_homo_elgamal_proof(&self.homo_elgamal_proof), self.s_l, self.protocol_output)
    }
}

impl Round6 {
    pub fn Display_homo_elgamal_proof(homo_elgamal_proof: &HomoELGamalProof<Secp256k1, Sha256>) -> String{
        let mut ret = String::new();
        ret.push_str(format!(r#"T:
    x:{}
    y:{}
A3:
    x:{}
    y:{}
z1:{}
z2:{},
hash_choice:{:#?}"#, homo_elgamal_proof.T.x_coord().unwrap().to_hex(), homo_elgamal_proof.T.y_coord().unwrap().to_hex(), 
        homo_elgamal_proof.A3.x_coord().unwrap().to_hex(), homo_elgamal_proof.A3.y_coord().unwrap().to_hex(),
        homo_elgamal_proof.z1.to_bigint().to_hex(), homo_elgamal_proof.z2.to_bigint().to_hex(),homo_elgamal_proof.hash_choice).as_str());
        ret.trim_end().into()
    }

    pub fn Display_homo_elgamal_proof_vec(homo_elgamal_proof_vec: &Vec<HomoELGamalProof<Secp256k1, Sha256>>) -> String{
        let mut ret = String::new();
        for (i,x) in homo_elgamal_proof_vec.iter().enumerate(){
            ret.push_str(format!("index-{}:\n\t{},\n", i, Round6::Display_homo_elgamal_proof(x)).as_str());
        }
        ret.trim_end().into()
    }
    pub fn proceed(
        self,
        input: BroadcastMsgs<(SI, HEGProof)>,
    ) -> Result<CompletedOfflineStage, Error> {
        log::info!("====Round 6 start=====");
        log::info!("args:self(Round6):\n{}", self);
        log::info!("args:input(BroadcastMsgs<(SI, HEGProof)>):\n{:#?}", input);

        let (S_i_vec, hegp_vec): (Vec<_>, Vec<_>) = input
            .into_vec_including_me((SI(self.S_i.clone()), HEGProof(self.homo_elgamal_proof.clone())))
            .into_iter()
            .map(|(s_i, hegp_i)| (s_i.0, hegp_i.0))
            .unzip();

        log::info!("add self.S_i and self.homo_elgamal_proof into input and unzip:\nS_i_vec:\n{}\nhegp_vec:\n{}", Round4::Display_t_vec(&S_i_vec), Round6::Display_homo_elgamal_proof_vec(&hegp_vec));

        let R_vec: Vec<_> = iter::repeat(self.protocol_output.R.clone())
            .take(self.s_l.len())
            .collect();
        log::info!("Repeat self.protocol_output.R for {} times, get R_vec:\n{}.", self.s_l.len(), Round4::Display_t_vec(&R_vec));

        LocalSignature::phase6_verify_proof(
            &S_i_vec,
            &hegp_vec,
            &R_vec,
            &self.protocol_output.t_vec,
        )
        .map_err(Error::Round6VerifyProof)?;
        log::info!("Verify phase6 proof(S_i_vec, hegp_vec, R_vec, self.protocol_output.t_vec)");

        LocalSignature::phase6_check_S_i_sum(&self.protocol_output.local_key.y_sum_s, &S_i_vec)
            .map_err(Error::Round6CheckSig)?;
        log::info!("phase6_check_S_i_sum(self.protocol_output.local_key.y_sum_s, S_i_vec)");
        
        log::info!("return self.protocol_output:self(Round6):\n{}", self);
        log::info!("====Round 6 finished=====");

        Ok(self.protocol_output)
    }

    pub fn expects_messages(i: u16, n: u16) -> Store<BroadcastMsgs<(SI, HEGProof)>> {
        containers::BroadcastMsgsStore::new(i, n)
    }

    pub fn is_expensive(&self) -> bool {
        true
    }
}

#[derive(Clone)]
pub struct CompletedOfflineStage {
    i: u16,
    local_key: LocalKey<Secp256k1>,
    sign_keys: SignKeys,
    t_vec: Vec<Point<Secp256k1>>,
    R: Point<Secp256k1>,
    sigma_i: Scalar<Secp256k1>,
}

impl fmt::Display for CompletedOfflineStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"i:{}
local_key:
    {}
sign_keys:
    {}
t_vec:
    {}
R:
    x:{}
    y:{}
sigma_i:{}"#, self.i, self.local_key, self.sign_keys, CompletedOfflineStage::Display_t_vec(&self.t_vec), self.R.x_coord().unwrap().to_hex(), self.R.y_coord().unwrap().to_hex(), self.sigma_i.to_bigint().to_hex())
    }
}

impl CompletedOfflineStage {
    pub fn Display_t_vec(t_vec: &Vec<Point<Secp256k1>>) -> String{
        let mut ret = String::new();
        for (i, x) in t_vec.iter().enumerate(){
            ret.push_str(format!("x{}:{},\ny{}:{}", i, x.x_coord().unwrap().to_hex(), i, x.y_coord().unwrap().to_hex()).as_str());
        }
        ret.trim_end().into()
    }

    pub fn public_key(&self) -> &Point<Secp256k1> {
        &self.local_key.y_sum_s
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PartialSignature(Scalar<Secp256k1>);

impl fmt::Display for PartialSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_bigint().to_hex())
    }
}

#[derive(Clone)]
pub struct Round7 {
    local_signature: LocalSignature,
}

impl fmt::Display for Round7 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "local_signature:\n\t{}", self.local_signature)
    }
}

impl Round7 {
    pub fn new(
        message: &BigInt,
        completed_offline_stage: CompletedOfflineStage,
    ) -> Result<(Self, PartialSignature)> {
        log::info!("====Round 7 new start=====");
        log::info!("args: message:{}", message.to_hex());
        log::info!("args: completed_offline_stage:\n{}", completed_offline_stage);

        let local_signature = LocalSignature::phase7_local_sig(
            &completed_offline_stage.sign_keys.k_i,
            message,
            &completed_offline_stage.R,
            &completed_offline_stage.sigma_i,
            &completed_offline_stage.local_key.y_sum_s,
        );
        log::info!("phase7_local_sig from completed_offline_stage.(sign_keys.k_i, R, sigma_i, local_key.y_sum_s), message), local_signature(s_i is also partial):\n{}", local_signature);

        let partial = PartialSignature(local_signature.s_i.clone());
        let ret = (Self { local_signature }, partial);
        log::info!("Round7 is:\n{}", ret.0);
        log::info!("PartialSignature is:{}", ret.1);
        log::info!("====Round 7 new finished=====");
        
        Ok(ret)
        //Ok((Self { local_signature }, partial))
    }

    pub fn proceed_manual(self, sigs: &[PartialSignature]) -> Result<SignatureRecid> {
        let sigs = sigs.iter().map(|s_i| s_i.0.clone()).collect::<Vec<_>>();
        self.local_signature
            .output_signature(&sigs)
            .map_err(Error::Round7)
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("round 1: {0:?}")]
    Round1(ErrorType),
    #[error("round 2 stage 3: {0:?}")]
    Round2Stage3(crate::Error),
    #[error("round 2 stage 4: {0:?}")]
    Round2Stage4(ErrorType),
    #[error("round 3: {0:?}")]
    Round3(ErrorType),
    #[error("round 5: {0:?}")]
    Round5(ErrorType),
    #[error("round 6: verify proof: {0:?}")]
    Round6VerifyProof(ErrorType),
    #[error("round 6: check sig: {0:?}")]
    Round6CheckSig(crate::Error),
    #[error("round 7: {0:?}")]
    Round7(crate::Error),
}

trait IteratorExt: Iterator {
    fn unzip3<A, B, C>(self) -> (Vec<A>, Vec<B>, Vec<C>)
    where
        Self: Iterator<Item = (A, B, C)> + Sized,
    {
        let (mut a, mut b, mut c) = (vec![], vec![], vec![]);
        for (a_i, b_i, c_i) in self {
            a.push(a_i);
            b.push(b_i);
            c.push(c_i);
        }
        (a, b, c)
    }
}

impl<I> IteratorExt for I where I: Iterator {}
