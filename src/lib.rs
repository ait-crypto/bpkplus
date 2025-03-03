use std::sync::OnceLock;

use ark_bls12_381::Bls12_381;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::{Field, UniformRand};
use ark_serialize::CanonicalSerialize;
use rand::{RngCore, SeedableRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256 as Hasher, digest::consts::U32};

type G1Projective = <Bls12_381 as Pairing>::G1;
type G2Projective = <Bls12_381 as Pairing>::G2;
type Gt = PairingOutput<Bls12_381>;
type Scalar = <Bls12_381 as Pairing>::ScalarField;

#[inline]
fn hash_with_domain_separation_1(msg: &[u8], domain_separator: &[u8]) -> G1Projective {
    let mut digest = sha2::Sha256::new();
    digest.update(domain_separator);
    digest.update(msg);

    let mut rng = ChaCha20Rng::from_seed(digest.finalize().into());
    G1Projective::rand(&mut rng)
}

#[inline]
fn hash_with_domain_separation_2(msg: &[u8], domain_separator: &[u8]) -> G2Projective {
    let mut digest = sha2::Sha256::new();
    digest.update(domain_separator);
    digest.update(msg);

    let mut rng = ChaCha20Rng::from_seed(digest.finalize().into());
    G2Projective::rand(&mut rng)
}

fn hash_gx<D, C>(hasher: &mut D, g: &C)
where
    D: Digest,
    C: CanonicalSerialize,
{
    let mut storage = Vec::new();
    g.serialize_uncompressed(&mut storage).unwrap();
    hasher.update(storage);
}

fn hash_base<D>(hasher: &mut D)
where
    D: Digest,
{
    let pp = PP::default();

    hash_gx(hasher, &pp.groth.g);
    hash_gx(hasher, &pp.groth.ghat);
    hash_gx(hasher, &pp.groth.y);
    hash_gx(hasher, &pp.h);
    hash_gx(hasher, &pp.k);
}

fn hash_context() -> Hasher {
    static INSTANCE: OnceLock<Hasher> = OnceLock::new();
    INSTANCE
        .get_or_init(|| {
            let mut hasher = Hasher::new();
            hasher.update(b"nym");
            hash_base(&mut hasher);
            hasher
        })
        .clone()
}

fn hash_extract_scalar<D>(hasher: D) -> Scalar
where
    D: Digest<OutputSize = U32>,
{
    let digest = hasher.finalize();
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(digest.into());
    loop {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes);
        if let Some(scalar) = Scalar::from_random_bytes(&bytes) {
            return scalar;
        }
    }
}

pub struct GrothPP {
    y: G1Projective,
    g: G1Projective,
    ghat: G2Projective,
}

impl Default for GrothPP {
    fn default() -> Self {
        let y = hash_with_domain_separation_1(b"y", b"Groth PP");
        let g = hash_with_domain_separation_1(b"g", b"Groth PP");
        let ghat = hash_with_domain_separation_2(b"ghat", b"Groth PP");

        Self { y, g, ghat }
    }
}

pub struct PP {
    groth: GrothPP,
    h: G1Projective,
    k: G1Projective,
}

impl Default for PP {
    fn default() -> Self {
        let h = hash_with_domain_separation_1(b"h", b"PP");
        let k = hash_with_domain_separation_1(b"k", b"PP");

        Self {
            groth: GrothPP::default(),
            h,
            k,
        }
    }
}

pub struct GrothSK {
    sk: Scalar,
}

pub struct GrothPK {
    pk: G2Projective,
}

pub struct GrothSignature {
    rhat: G2Projective,
    s: G1Projective,
    t: G1Projective,
}

impl GrothSK {
    pub fn rand(pp: &GrothPP) -> (Self, GrothPK) {
        let mut rng = rand::thread_rng();
        let sk = Scalar::rand(&mut rng);

        (Self { sk }, GrothPK { pk: pp.ghat * sk })
    }

    pub fn sign(&self, pp: &GrothPP, msg: &G1Projective) -> GrothSignature {
        let mut rng = rand::thread_rng();
        let r = Scalar::rand(&mut rng);
        let rinv = r.inverse().unwrap();

        let rhat = pp.ghat * r;
        let s = (pp.g * self.sk + pp.y) * rinv;
        let t = (pp.y * self.sk + msg) * rinv;

        GrothSignature { rhat, s, t }
    }
}

impl GrothSignature {
    fn rand(&self, rprime: &Scalar) -> Self {
        let rinv = rprime.inverse().unwrap();
        Self {
            rhat: self.rhat * rprime,
            s: self.s * rinv,
            t: self.t * rinv,
        }
    }
}

impl GrothPK {
    pub fn verify(&self, pp: &GrothPP, msg: &G1Projective, sig: &GrothSignature) -> bool {
        Bls12_381::pairing(sig.s, sig.rhat)
            == Bls12_381::pairing(pp.y, pp.ghat) + Bls12_381::pairing(pp.g, self.pk)
            && Bls12_381::pairing(sig.t, sig.rhat)
                == Bls12_381::pairing(pp.y, self.pk) + Bls12_381::pairing(msg, pp.ghat)
    }
}

pub struct CentralAuthroitySK {
    sig_sk: GrothSK,
    _enc_sk: Scalar,
}

pub struct CentralAuthorityPK {
    sig_pk: GrothPK,
    enc_pk: G1Projective,
}

impl CentralAuthroitySK {
    pub fn rand(pp: &PP) -> (Self, CentralAuthorityPK) {
        let (sk, pk) = GrothSK::rand(&pp.groth);
        let mut rng = rand::thread_rng();
        let enc_sk = Scalar::rand(&mut rng);
        let enc_pk = pp.k * enc_sk;

        (
            Self {
                sig_sk: sk,
                _enc_sk: enc_sk,
            },
            CentralAuthorityPK { sig_pk: pk, enc_pk },
        )
    }

    pub fn rand_user(&self, pp: &PP) -> (UserSK, UserPK) {
        let mut rng = rand::thread_rng();
        let sk = Scalar::rand(&mut rng);
        let pk = pp.h * sk;

        let sigma = self.sig_sk.sign(&pp.groth, &pk);
        (
            UserSK {
                dh_sk: sk,
                dh_pk: pk,
                sigma,
            },
            UserPK { _dh_pk: pk },
        )
    }
}

pub struct UserSK {
    dh_sk: Scalar,
    dh_pk: G1Projective,
    sigma: GrothSignature,
}

pub struct UserPK {
    _dh_pk: G1Projective,
}

pub struct ServiceProviderSK {
    _dh_sk: Scalar,
}

pub struct ServiceProviderPK {
    dh_pk: G1Projective,
}

impl ServiceProviderSK {
    pub fn rand(pp: &PP) -> (Self, ServiceProviderPK) {
        let mut rng = rand::thread_rng();
        let dh_sk = Scalar::rand(&mut rng);
        let dh_pk = pp.k * dh_sk;

        (Self { _dh_sk: dh_sk }, ServiceProviderPK { dh_pk })
    }
}

pub struct Proof {
    c_1: G1Projective,
    c_2: G1Projective,
    r_hat_prime_prime: G2Projective,
    s_prime_prime: G1Projective,
    t_prime_prime: G1Projective,
    upk_prime: G1Projective,
    a_1: Gt,
    s_1: Scalar,
    a_2: G1Projective,
    s_2: Scalar,
    a_3: G1Projective,
    s_3: Scalar,
    a_4: G1Projective,
    s_4: Scalar,
    a_5: G1Projective,
    s_5_1: Scalar,
    s_5_2: Scalar,
    a_6: Gt,
    s_6_1: Scalar,
    s_6_2: Scalar,
}

impl UserSK {
    pub fn nymgen(
        &self,
        pp: &PP,
        sppk: &ServiceProviderPK,
        mpk: &CentralAuthorityPK,
    ) -> (G1Projective, Proof) {
        let nym = sppk.dh_pk * self.dh_sk;

        let mut rng = rand::thread_rng();
        let r = Scalar::rand(&mut rng);
        let c_1 = pp.k * r;
        let c_2 = mpk.enc_pk * r + self.dh_pk;

        let rprime = Scalar::rand(&mut rng);
        let sigma_prime = self.sigma.rand(&rprime);

        let alpha = Scalar::rand(&mut rng);
        let beta = Scalar::rand(&mut rng);

        let r_hat_prime_prime = sigma_prime.rhat;
        let s_prime_prime = sigma_prime.s * alpha.inverse().unwrap();
        let t_prime_prime = sigma_prime.t * beta.inverse().unwrap();

        let s = Scalar::rand(&mut rng);
        let sinv = s.inverse().unwrap();
        let upk_prime = self.dh_pk * sinv;

        // hash the statement
        let mut hasher = hash_context();
        hash_gx(&mut hasher, &sppk.dh_pk);
        hash_gx(&mut hasher, &mpk.enc_pk);
        hash_gx(&mut hasher, &mpk.sig_pk.pk);
        hash_gx(&mut hasher, &c_1);
        hash_gx(&mut hasher, &c_2);
        hash_gx(&mut hasher, &upk_prime);
        hash_gx(&mut hasher, &r_hat_prime_prime);
        hash_gx(&mut hasher, &s_prime_prime);
        hash_gx(&mut hasher, &t_prime_prime);
        hash_gx(&mut hasher, &nym);

        // e(s'', r'') ^ alpha = e(y, ghat) e(g, mpk_groth)
        let r_1 = Scalar::rand(&mut rng);
        let a_1 = Bls12_381::pairing(s_prime_prime * r_1, r_hat_prime_prime);
        // upk'^s = H^usk => upk' = H^(usk / s)
        let r_2 = Scalar::rand(&mut rng);
        let a_2 = pp.h * r_2;
        // nym = sppk^usk
        let r_3 = Scalar::rand(&mut rng);
        let a_3 = sppk.dh_pk * r_3;
        // c_1 = K^r
        let r_4 = Scalar::rand(&mut rng);
        let a_4 = pp.k * r_4;
        // c_2 = upks'^s mpk_elgamal^r
        let r_5_1 = Scalar::rand(&mut rng);
        let r_5_2 = Scalar::rand(&mut rng);
        let a_5 = upk_prime * r_5_1 + mpk.enc_pk * r_5_2;
        // e(t'', r'')^\beta = e(y,mpk_groth) e(upk', ghat)^s => e(t'', r'')^\beta e(upk', ghat)^-s  = e(y,mpk_groth)
        let r_6_1 = Scalar::rand(&mut rng);
        let r_6_2 = Scalar::rand(&mut rng);
        let a_6 = Bls12_381::multi_pairing(
            [t_prime_prime * r_6_1, upk_prime * r_6_2],
            [r_hat_prime_prime, pp.groth.ghat],
        );

        hash_gx(&mut hasher, &a_1);
        hash_gx(&mut hasher, &a_2);
        hash_gx(&mut hasher, &a_3);
        hash_gx(&mut hasher, &a_4);
        hash_gx(&mut hasher, &a_5);
        hash_gx(&mut hasher, &a_6);
        let c = hash_extract_scalar(hasher);

        (
            nym,
            Proof {
                c_1,
                c_2,
                r_hat_prime_prime,
                s_prime_prime,
                t_prime_prime,
                upk_prime,
                a_1,
                s_1: r_1 + c * alpha,
                a_2,
                s_2: r_2 + c * sinv * self.dh_sk,
                a_3,
                s_3: r_3 + c * self.dh_sk,
                a_4,
                s_4: r_4 + c * r,
                a_5,
                s_5_1: r_5_1 + c * s,
                s_5_2: r_5_2 + c * r,
                a_6,
                s_6_1: r_6_1 + c * beta,
                s_6_2: r_6_2 - c * s,
            },
        )
    }
}

pub fn verify(
    pp: &PP,
    mpk: &CentralAuthorityPK,
    sppk: &ServiceProviderPK,
    nym: &G1Projective,
    pi: &Proof,
) -> bool {
    let mut hasher = hash_context();
    hash_gx(&mut hasher, &sppk.dh_pk);
    hash_gx(&mut hasher, &mpk.enc_pk);
    hash_gx(&mut hasher, &mpk.sig_pk.pk);
    hash_gx(&mut hasher, &pi.c_1);
    hash_gx(&mut hasher, &pi.c_2);
    hash_gx(&mut hasher, &pi.upk_prime);
    hash_gx(&mut hasher, &pi.r_hat_prime_prime);
    hash_gx(&mut hasher, &pi.s_prime_prime);
    hash_gx(&mut hasher, &pi.t_prime_prime);
    hash_gx(&mut hasher, nym);
    hash_gx(&mut hasher, &pi.a_1);
    hash_gx(&mut hasher, &pi.a_2);
    hash_gx(&mut hasher, &pi.a_3);
    hash_gx(&mut hasher, &pi.a_4);
    hash_gx(&mut hasher, &pi.a_5);
    hash_gx(&mut hasher, &pi.a_6);
    let c = hash_extract_scalar(hasher);
    let minus_c = -c;

    // e(s'', r'') ^ alpha = e(y, ghat) e(g, mpk_groth)
    let b_1 = Bls12_381::multi_pairing(
        [
            pi.s_prime_prime * pi.s_1,
            pp.groth.y * minus_c,
            pp.groth.g * minus_c,
        ],
        [pi.r_hat_prime_prime, pp.groth.ghat, mpk.sig_pk.pk],
    ) == pi.a_1;
    // upk'^s = H^usk => upk' = H^(usk / s)
    let b_2 = pp.h * pi.s_2 == pi.upk_prime * c + pi.a_2;
    // nym = sppk^usk
    let b_3 = sppk.dh_pk * pi.s_3 == *nym * c + pi.a_3;
    // c_1 = K^r
    let b_4 = pp.k * pi.s_4 == pi.c_1 * c + pi.a_4;
    // c_2 = upks'^s mpk_elgamal^r
    let b_5 = pi.upk_prime * pi.s_5_1 + mpk.enc_pk * pi.s_5_2 == pi.c_2 * c + pi.a_5;
    // e(t'', r'')^\beta = e(y,mpk_groth) e(upk', ghat)^s => e(t'', r'')^\beta e(upk', ghat)^-s  = e(y,mpk_groth)
    let b_6 = Bls12_381::multi_pairing(
        [
            pi.t_prime_prime * pi.s_6_1,
            pi.upk_prime * pi.s_6_2,
            pp.groth.y * minus_c,
        ],
        [pi.r_hat_prime_prime, pp.groth.ghat, mpk.sig_pk.pk],
    ) == pi.a_6;

    b_1 && b_2 && b_3 && b_4 && b_5 && b_6
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn groth() {
        let pp = GrothPP::default();
        let (sk, pk) = GrothSK::rand(&pp);

        let msg = hash_with_domain_separation_1(b"msg", b"");
        let sig = sk.sign(&pp, &msg);
        assert!(pk.verify(&pp, &msg, &sig));
    }

    #[test]
    fn nym() {
        let pp = PP::default();

        let (msk, mpk) = CentralAuthroitySK::rand(&pp);
        let (_, sppk) = ServiceProviderSK::rand(&pp);
        let (usk, _) = msk.rand_user(&pp);

        let (nym, pi) = usk.nymgen(&pp, &sppk, &mpk);
        assert!(verify(&pp, &mpk, &sppk, &nym, &pi));
    }
}
