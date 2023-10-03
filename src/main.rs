mod models;

use models::*;

fn main() {
    // Print welcome message
    println!("Welcome to the Secret Santa!");

    // Alice, Bob and Charlie
    let players = vec![Player::init(), Player::init(), Player::init()];

    let pub_keys: Vec<elgamal::ElGamalPublicKey> =
        players.iter().map(|p: &Player| p.pub_key.clone()).collect();

    println!("3 players enter teh game!");
    let mut private_list: PrivateList = PrivateList::init(&pub_keys);

    for i in 0..players.len() {
        println!("Player {} shakes!", i + 1);
        private_list.secure_shuffle(&players[i]);
    }

    for i in 0..players.len() {
        println!("Player {} finds giftee!", i + 1);
        let giftee = players[i].find_giftee(&private_list).unwrap();
        println!("Player {} giftee: {}", i + 1, giftee);
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::Converter;
    use curv::arithmetic::Modulo;
    use curv::BigInt;
    use elgamal::{rfc7919_groups::SupportedGroups, ElGamal, ElGamalKeyPair, ElGamalPP};

    #[test]
    fn test_allice_simple_encryption() {
        // choose suitable field parameter, https://tools.ietf.org/html/rfc7919
        let group_id = SupportedGroups::FFDHE2048;

        let alice_pp = ElGamalPP::generate_from_rfc7919(group_id);
        let alice_key_pair = ElGamalKeyPair::generate(&alice_pp);

        // homomorphic (pow) addition
        // note to self: we now have (g^r, g^m * h^r) instead of (g^r, m * h^r)
        // data set:
        let alice_name = String::from("Alice Smith");
        let alice_name_bytes = alice_name.clone().into_bytes();
        let alice_name_bigint = BigInt::from_bytes(&alice_name_bytes);

        let cipher = ElGamal::encrypt(&alice_name_bigint, &alice_key_pair.pk).unwrap();
        let message_tag = ElGamal::decrypt(&cipher, &alice_key_pair.sk).unwrap();

        let message_tag_bytes = message_tag.to_bytes();
        let message_tag_string = String::from_utf8(message_tag_bytes).unwrap();

        println!(
            "basic encryption: message: {}, decrypted: {}",
            alice_name, message_tag_string
        );
    }

    #[test]
    fn test_allice_complete_encryption() {
        let group_id = SupportedGroups::FFDHE2048;
        let alice_pp = ElGamalPP::generate_from_rfc7919(group_id);
        // create a public, secret keypair
        let alice_key_pair = ElGamalKeyPair::generate(&alice_pp);
        let name: [u8; 4] = [70, 71, 72, 73];
        let message = u32::from_be_bytes(name);
        let message_bn = BigInt::from(message);
        let message_in_field = message_bn.modulus(&alice_pp.q);
        let cipher = ElGamal::encrypt(&message_in_field, &alice_key_pair.pk).unwrap();
        let message_prime = ElGamal::decrypt(&cipher, &alice_key_pair.sk).unwrap();
        println!(
            "basic encryption: message: {}, decrypted: {}",
            message, message_prime
        );
    }

    #[test]
    fn test_product_encryption() {
        let group_id = SupportedGroups::FFDHE2048;

        let alice_pp = ElGamalPP::generate_from_rfc7919(group_id);
        let alice_key_pair = ElGamalKeyPair::generate(&alice_pp);

        // homomorphic multiplication
        let factor_1 = BigInt::from(3);
        let factor_2 = BigInt::from(5);

        let cipher = ElGamal::encrypt(&factor_1, &alice_key_pair.pk).unwrap();
        let constant_cipher = ElGamal::encrypt(&factor_2, &alice_key_pair.pk).unwrap();

        // homomorphic multiplication in cipher space
        let product_cipher = ElGamal::mul(&cipher, &constant_cipher).unwrap();

        // decrypt homomorphic product
        let product_tag = ElGamal::decrypt(&product_cipher, &alice_key_pair.sk).unwrap();

        assert_eq!(&factor_1 * &factor_2, product_tag);
    }
}
