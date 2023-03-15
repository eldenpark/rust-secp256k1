extern crate secp256k1;

use std::str::FromStr;

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::fmt::Write;

fn main() {
    let secp = Secp256k1::new();
    // let mut rng = rand::thread_rng();
    // // First option:
    // let (seckey, pubkey) = secp.generate_keypair(&mut rng);

    // assert_eq!(pubkey, PublicKey::from_secret_key(&secp, &seckey));

    // // Second option:
    // let seckey = SecretKey::new(&mut rng);
    // let _pubkey = PublicKey::from_secret_key(&secp, &seckey);

    let mut v = [0x00; 32];
    v[31] = 0x01;

    let secret_key = SecretKey::from_slice(&v).expect("32 bytes, within curve order");
    println!("secret_key: {:?}", secret_key);

    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    println!("public_key: {:?}", public_key);

    let str = "9817f8165b81f259d928ce2ddbfc9b02070b87ce9562a055acbbdcf97e66be79b8d410fb8fd0479c195485a648b417fda808110efcfba45d65c4a32677da3a48";
    let v = hex::decode(str);
    println!("v: {:?}", v);

    let pk_uncompressed_vec = public_key.serialize_uncompressed();
    println!("pk_uncompressed_vec: {:?}", pk_uncompressed_vec);

    let pk_uncompressed_str = hex::encode(pk_uncompressed_vec);
    println!("pk_uncompressed_str: {}", pk_uncompressed_str);

    let pk = PublicKey::from_slice(&pk_uncompressed_vec).unwrap();
    println!("pk: {:?}", pk);

    // d116ed27a37326d9679d52ddd511f0c671e2d0ff68d30fb78c1fc64eb8fe0ec2e0b260e5c453f856a3297588931aca98d4b2bd14ff1fff6d9b95ed9cd2e5cad8
    //
    let pk_1 = "0x04d116ed27a37326d9679d52ddd511f0c671e2d0ff68d30fb78c1fc64eb8fe0ec2e0b260e5c453f856a3297588931aca98d4b2bd14ff1fff6d9b95ed9cd2e5cad8";
    let pk_1 = pk_1.strip_prefix("0x").unwrap();
    println!("pk_1: {:?}", pk_1);

    let my_pk = PublicKey::from_str(pk_1).unwrap();
    println!("my_pk: {:?}", my_pk);

    // let pk_2 = "0x049817f8165b81f259d928ce2ddbfc9b02070b87ce9562a055acbbdcf97e66be79b8d410fb8fd0479c195485a648b417fda808110efcfba45d65c4a32677da3a48";
    let pk_2 = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";
    let pk_2 = pk_2.strip_prefix("0x").unwrap();
    let pk_2_slice = hex::decode(pk_2).unwrap();
    let my_pk_2 = PublicKey::from_slice(&pk_2_slice).unwrap();
    println!("my_pk_2: {:?}", my_pk_2);
}

// //
// 9817f8165b81f259d928ce2ddbfc9b02070b87ce9562a055acbbdcf97e66be79
// b8d410fb8fd0479c195485a648b417fda808110efcfba45d65c4a32677da3a48

// //
// 79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
// 483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8
