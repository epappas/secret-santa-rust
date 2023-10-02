use curv::arithmetic::{BasicOps, Modulo, Samplable};
use curv::BigInt;
use elgamal::rfc7919_groups::SupportedGroups;
use elgamal::{ElGamalKeyPair, ElGamalPP, ElGamalPublicKey};
use rand::distributions::Uniform;
use rand::seq::SliceRandom;
use rand::Rng;

#[derive(Clone, Debug, PartialEq)]
pub struct Player {
    pub pub_key: ElGamalPublicKey,
    key_pair: ElGamalKeyPair,
}

pub trait PlayerTrait {
    fn init() -> Self;
    fn new(pp: &ElGamalPP) -> Self;
    fn get_key_pair(&self) -> &ElGamalKeyPair;
}

impl PlayerTrait for Player {
    fn init() -> Self {
        let group_id = SupportedGroups::FFDHE2048;
        let pp = ElGamalPP::generate_from_rfc7919(group_id);

        Player::new(&pp)
    }

    fn new(pp: &ElGamalPP) -> Self {
        let key_pair = ElGamalKeyPair::generate(pp);
        Player {
            pub_key: key_pair.pk.clone(),
            key_pair: key_pair,
        }
    }

    fn get_key_pair(&self) -> &ElGamalKeyPair {
        &self.key_pair
    }
}

pub struct PrivateList {
    pub private_list: Vec<BigInt>,
    pub pp: ElGamalPP,
    pub g_s: BigInt,
}

impl PrivateList {
    pub fn init(pub_keys: &[ElGamalPublicKey]) -> Self {
        assert!(!pub_keys.is_empty());

        let pp = pub_keys[0].pp.clone();
        let private_list: Vec<BigInt> = (0..pub_keys.len())
            .map(|i| {
                assert_eq!(pp, pub_keys[i].pp);
                pub_keys[i].h.clone()
            })
            .collect();

        PrivateList::new(private_list, &pp, (&pub_keys[0]).pp.g.clone())
    }

    fn new(private_list: Vec<BigInt>, pp: &ElGamalPP, g_s: BigInt) -> Self {
        PrivateList {
            private_list,
            pp: pp.clone(),
            g_s,
        }
    }

    pub fn secure_shuffle(&mut self, player: &Player) {
        let mut rng = rand::thread_rng();
        self.private_list.shuffle(&mut rng);

        let s = BigInt::sample_below(&self.g_s);
        self.g_s = BigInt::mod_pow(&self.g_s, &s, &player.pub_key.pp.p);

        for element in &mut self.private_list {
            *element = BigInt::mod_pow(&element, &s, &player.pub_key.pp.p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_player() {
        let player = Player::init();
        let key_pair = player.get_key_pair();
        assert_eq!(key_pair.pk.pp, player.pub_key.pp);
    }

    #[test]
    fn test_private_list() {
        let player = Player::init();
        let player_key_pair = player.get_key_pair();

        let private_list = PrivateList::init(&[player_key_pair.pk.clone()]);

        assert_eq!(private_list.private_list[0], player_key_pair.pk.h);
        assert_eq!(private_list.pp, player.pub_key.pp);
        assert_eq!(private_list.g_s, player.pub_key.pp.g);
    }
}
