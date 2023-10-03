use curv::arithmetic::{Modulo, Samplable};
use curv::BigInt;
use elgamal::rfc7919_groups::SupportedGroups;
use elgamal::{ElGamal, ElGamalCiphertext, ElGamalKeyPair, ElGamalPP, ElGamalPublicKey};
use rand::seq::SliceRandom;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum AppError {
    NoGifteeFound,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Player {
    pub pub_key: ElGamalPublicKey,
    key_pair: ElGamalKeyPair,
}

pub trait PlayerTrait {
    fn init() -> Self;
    fn new(pp: &ElGamalPP) -> Self;
    fn get_key_pair(&self) -> &ElGamalKeyPair;
    fn find_giftee(&self, private_list: &PrivateList) -> Result<usize, AppError>;
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

    fn find_giftee(&self, private_list: &PrivateList) -> Result<usize, AppError> {
        let matching_result: BigInt = BigInt::from(1);

        for i in 0..private_list.private_list.len() {
            let y = BigInt::sample_below(&self.key_pair.pk.pp.q);
            let c1 = BigInt::mod_pow(&private_list.g_s, &y, &self.key_pair.pk.pp.p);
            let s = BigInt::mod_pow(&self.key_pair.pk.h, &y, &self.key_pair.pk.pp.p);
            let c2 = BigInt::mod_mul(&s, &private_list.private_list[i], &self.key_pair.pk.pp.p);
            let cipher: ElGamalCiphertext = ElGamalCiphertext {
                c1,
                c2,
                pp: self.key_pair.pk.pp.clone(),
            };

            let result: BigInt = ElGamal::decrypt(&cipher, &self.key_pair.sk).unwrap();

            println!("result: {}", result);

            if result == matching_result {
                return Ok(i);
            }
        }

        Err(AppError::NoGifteeFound)
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

        let s = BigInt::sample_below(&player.pub_key.pp.g);
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

    #[test]
    fn test_secure_shuffle() {
        let player = Player::init();
        let pub_keys = vec![player.pub_key.clone()];
        let mut private_list = PrivateList::init(&pub_keys);
        let original_list = private_list.private_list.clone();

        private_list.secure_shuffle(&player);

        // Ensure the list is shuffled
        assert_ne!(original_list, private_list.private_list);

        // Ensure the length remains the same
        assert_eq!(original_list.len(), private_list.private_list.len());
    }

    #[test]
    fn test_find_giftee() {
        // Alice, Bob and Charlie
        let player_1 = Player::init();
        let player_2 = Player::init();
        let player_3 = Player::init();
        let pub_keys = vec![
            player_1.pub_key.clone(),
            player_2.pub_key.clone(),
            player_3.pub_key.clone(),
        ];

        let private_list = PrivateList::init(&pub_keys);

        match player_1.find_giftee(&private_list) {
            Ok(index) => {
                assert!(index < pub_keys.len());
            }
            Err(e) => panic!("Expected Ok, got Err: {:?}", e),
        }
    }
}
