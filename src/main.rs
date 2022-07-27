use std::fmt::Formatter;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use cmac::{Cmac, Mac};
use ctr::Ctr64BE;
use prio::field::Field128;
use prio::flp::types::Sum;
use prio::vdaf::prg::{Prg, SeedStream};
use prio::vdaf::prio3::Prio3;
use prio::vdaf::VdafError;

use std::fmt::Debug;

#[derive(Clone, Debug)]
pub struct PrgAes128Alt(Cmac<Aes128>);
impl Prg<16> for PrgAes128Alt {
    type SeedStream = SeedStreamAes128Alt;

    fn init(seed_bytes: &[u8; 16]) -> Self {
        Self(Cmac::new_from_slice(seed_bytes).unwrap())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn into_seed_stream(self) -> SeedStreamAes128Alt {
        let key = self.0.finalize().into_bytes();
        SeedStreamAes128Alt::new(&key, &[0; 16])
    }
}

/// The key stream produced by AES128 in CTR-mode.
pub struct SeedStreamAes128Alt(Ctr64BE<Aes128>);

impl SeedStreamAes128Alt {
    pub(crate) fn new(key: &[u8], iv: &[u8]) -> Self {
        SeedStreamAes128Alt(Ctr64BE::<Aes128>::new(key.into(), iv.into()))
    }
}

impl SeedStream for SeedStreamAes128Alt {
    fn fill(&mut self, buf: &mut [u8]) {
        buf.fill(0);
        self.0.apply_keystream(buf);
    }
}

impl Debug for SeedStreamAes128Alt {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // Ctr64BE<Aes128> does not implement Debug, but [`ctr::CtrCore`][1] does, and we get that
        // with [`cipher::StreamCipherCoreWrapper::get_core`][2].
        //
        // [1]: https://docs.rs/ctr/latest/ctr/struct.CtrCore.html
        // [2]: https://docs.rs/cipher/latest/cipher/struct.StreamCipherCoreWrapper.html
        self.0.get_core().fmt(f)
    }
}

pub type Prio3Aes128SumAlt = Prio3<Sum<Field128>, PrgAes128Alt, 16>;

/// Construct an instance of Prio3Aes128Sum with the given number of aggregators and required
/// bit length. The bit length must not exceed 64.
pub fn new_prg(num_aggregators: u8, bits: u32) -> Result<Prio3Aes128SumAlt, VdafError> {
    if bits > 64 {
        return Err(VdafError::Uncategorized(format!(
            "bit length ({}) exceeds limit for aggregate type (64)",
            bits
        )));
    }

    Prio3::new(num_aggregators, Sum::new(bits as usize)?)
}

fn main() {
    let _s = new_prg(2, 16);
}

#[cfg(test)]
mod test {
    use super::*;
    use prio::{
        codec::{Encode, ParameterizedDecode},
        flp::Type,
        vdaf::{
            prg::Prg,
            prio3::{Prio3, Prio3InputShare, Prio3PrepareShare},
            Aggregator, PrepareTransition,
        },
    };
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Deserialize, Serialize)]
    struct TEncoded(#[serde(with = "hex")] Vec<u8>);

    impl AsRef<[u8]> for TEncoded {
        fn as_ref(&self) -> &[u8] {
            &self.0
        }
    }

    #[derive(Deserialize, Serialize)]
    struct TPrio3<M> {
        verify_key: TEncoded,
        prep: Vec<TPrio3Prep<M>>,
    }

    #[derive(Deserialize, Serialize)]
    struct TPrio3Prep<M> {
        measurement: M,
        #[serde(with = "hex")]
        nonce: Vec<u8>,
        input_shares: Vec<TEncoded>,
        prep_shares: Vec<Vec<TEncoded>>,
        prep_messages: Vec<TEncoded>,
        out_shares: Vec<Vec<M>>,
    }

    macro_rules! err {
        (
        $test_num:ident,
        $error:expr,
        $msg:expr
    ) => {
            panic!("test #{} failed: {} err: {}", $test_num, $msg, $error)
        };
    }

    #[test]
    fn test_vec_prio3_sum() {
        let t: TPrio3<u128> =
            serde_json::from_str(include_str!("test_vec/01/Prio3Aes128Sum.json")).unwrap();
        let prio3 = new_prg(2, 8).unwrap();
        let verify_key = t.verify_key.as_ref().try_into().unwrap();

        for (test_num, p) in t.prep.iter().enumerate() {
            check_prep_test_vec(&prio3, &verify_key, test_num, p);
        }
    }

    // TODO Generalize this method to work with any VDAF. To do so we would need to add
    // `test_vec_setup()` and `test_vec_shard()` to traits. (There may be a less invasive alternative.)
    fn check_prep_test_vec<M, T, P, const L: usize>(
        prio3: &Prio3<T, P, L>,
        verify_key: &[u8; L],
        test_num: usize,
        t: &TPrio3Prep<M>,
    ) where
        T: Type<Measurement = M>,
        P: Prg<L>,
        M: From<<T as Type>::Field> + Debug + PartialEq,
    {
        let input_shares = prio3
            .test_vec_shard(&t.measurement)
            .expect("failed to generate input shares");

        assert_eq!(2, t.input_shares.len(), "#{}", test_num);
        for (agg_id, want) in t.input_shares.iter().enumerate() {
            assert_eq!(
                input_shares[agg_id],
                Prio3InputShare::get_decoded_with_param(&(prio3, agg_id), want.as_ref())
                    .unwrap_or_else(|e| err!(test_num, e, "decode test vector (input share)")),
                "#{}",
                test_num
            );
            assert_eq!(
                input_shares[agg_id].get_encoded(),
                want.as_ref(),
                "#{}",
                test_num
            )
        }

        let mut states = Vec::new();
        let mut prep_shares = Vec::new();
        for (agg_id, input_share) in input_shares.iter().enumerate() {
            let (state, prep_share) = prio3
                .prepare_init(verify_key, agg_id, &(), &t.nonce, input_share)
                .unwrap_or_else(|e| err!(test_num, e, "prep state init"));
            states.push(state);
            prep_shares.push(prep_share);
        }

        assert_eq!(1, t.prep_shares.len(), "#{}", test_num);
        for (i, want) in t.prep_shares[0].iter().enumerate() {
            assert_eq!(
                prep_shares[i],
                Prio3PrepareShare::get_decoded_with_param(&states[i], want.as_ref())
                    .unwrap_or_else(|e| err!(test_num, e, "decode test vector (prep share)")),
                "#{}",
                test_num
            );
            assert_eq!(prep_shares[i].get_encoded(), want.as_ref(), "#{}", test_num);
        }

        let inbound = prio3
            .prepare_preprocess(prep_shares)
            .unwrap_or_else(|e| err!(test_num, e, "prep preprocess"));
        assert_eq!(t.prep_messages.len(), 1);
        assert_eq!(inbound.get_encoded(), t.prep_messages[0].as_ref());

        let mut out_shares = Vec::new();
        for state in states.iter_mut() {
            match prio3.prepare_step(state.clone(), inbound.clone()).unwrap() {
                PrepareTransition::Finish(out_share) => {
                    out_shares.push(out_share);
                }
                _ => panic!("unexpected transition"),
            }
        }

        for (got, want) in out_shares.iter().zip(t.out_shares.iter()) {
            let got: Vec<M> = got.as_ref().iter().map(|x| M::from(*x)).collect();
            assert_eq!(&got, want);
        }
    }
}
