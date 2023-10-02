use curv::arithmetic::traits::Modulo;
use curv::arithmetic::traits::Samplable;
use curv::BigInt;
use elgamal::{
    rfc7919_groups::SupportedGroups, ElGamal, ElGamalCiphertext, ElGamalKeyPair, ElGamalPP,
};

#[test]
fn test_elgamal() {
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

    let y = BigInt::sample_below(&alice_pp.q);
    let c1 = BigInt::mod_pow(&alice_key_pair.pk.pp.g, &y, &alice_key_pair.pk.pp.p);
    let s = BigInt::mod_pow(&alice_key_pair.pk.h, &y, &alice_key_pair.pk.pp.p);
    let c2 = BigInt::mod_mul(&s, &message_in_field, &alice_pp.p);
    let ct_manual = ElGamalCiphertext {
        c1,
        c2,
        pp: alice_pp.clone(),
    };
    let message_double_prime = ElGamal::decrypt(&ct_manual, &alice_key_pair.sk).unwrap();
    assert_eq!(message_bn, message_double_prime);

    let m3 = BigInt::from(3);
    let m5 = BigInt::from(5);
    let c3 = ElGamal::encrypt(&m3, &alice_key_pair.pk).unwrap();
    let c5 = ElGamal::encrypt(&m5, &alice_key_pair.pk).unwrap();
    let c15 = ElGamalCiphertext {
        c1: BigInt::mod_mul(&c3.c1, &c5.c1, &alice_key_pair.pk.pp.p),
        c2: BigInt::mod_mul(&c3.c2, &c5.c2, &alice_key_pair.pk.pp.p),
        pp: alice_pp.clone(),
    };
    assert_eq!(
        ElGamal::decrypt(&c15, &alice_key_pair.sk).unwrap(),
        BigInt::from(15)
    );
}
