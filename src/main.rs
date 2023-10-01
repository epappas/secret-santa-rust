use curv::arithmetic::Converter;
use curv::BigInt;
use elgamal::{rfc7919_groups::SupportedGroups, ElGamal, ElGamalKeyPair, ElGamalPP};

fn main() {
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
