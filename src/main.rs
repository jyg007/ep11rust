mod ep11; 
mod constants; 
 
use ep11::hsm_init; 
use ep11::Mechanism; 
use ep11::Attribute; 
use ep11::generate_key_pair; 
use ep11::generate_key; 
use ep11::generate_random; 
use ep11::derive_key; 
use ep11::sign_single;
use ep11::encrypt_single;
use ep11::decrypt_single;
use ep11::unwrap_key;
use ep11::wrap_key;
use ep11::encode_oid;
use ep11::new_btc_derive_params;
use ep11::BTCDeriveParams;
use crate::constants::*; 
use crate::ep11::OIDNAMEDCURVESECP256K1;
use crate::ep11::OIDNAMEDCURVEED25519;
use libloading::Library;
use sha2::{Sha256, Digest};
use std::env;

// Assuming the necessary imports and structs are defined in the same file 
 
fn main() { 
    let target = unsafe { hsm_init("03.19", false) }.expect("HSM initialization failed"); 
 
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
   // Prepare EC parameters (OIDNamedCurveSecp256k1) 
    //let ec_parameters = encode_oid("1.3.132.0.10"); 
    let ec_parameters = encode_oid(OIDNAMEDCURVESECP256K1); 
//    println!("{:?}", ec_parameters); 
 
 
   // Create mechanism (EC key pair generation) 
   let mech = Mechanism { 
       mechanism: CKM_EC_KEY_PAIR_GEN, 
 //     mechanism: CKM_RSA_PKCS_KEY_PAIR_GEN, 
       parameter: None, // You can pass additional parameters if needed 
   }; 
 
   // Define public key template 
   let public_key_template = vec![ 
       Attribute::new(CKA_EC_PARAMS, ec_parameters), 
       Attribute::new(CKA_VERIFY, true), 
 //    Attribute::new(CKA_CLASS, CKO_PUBLIC_KEY), 
        
   ]; 
 
   // Define private key template 
   let private_key_template = vec![ 
         Attribute::new(CKA_SIGN, true), 
   //    Attribute::new(CKA_DECRYPT, true), 
 //      Attribute::new(CKA_PRIVATE, true), 
    //   Attribute::new(CKA_SENSITIVE, true), 
   ]; 
 
   // Call GenerateKeyPair function 
   let result = unsafe { 
       generate_key_pair( 
           target, 
           &mech, 
           public_key_template, 
           private_key_template, 
       ) 
   }; 
 
let (pk,sk) = match result { 
   Ok((pk, sk)) => { 
       // Successfully generated the keys 
       println!("Generated Public Key: {}", hex::encode(&pk)); 
       println!("Generated Private Key: {}", hex::encode(&sk)); 
       (pk,sk)
   }, 
   Err(error) => { 
       // There was an error 
       eprintln!("Error: {}", error); 
       return;
   } 
}; 

//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
   let mech = Mechanism { 
       mechanism: CKM_AES_KEY_GEN, 
       parameter: None, 
   }; 

   let key_template = vec![ 
       Attribute::new(CKA_VALUE_LEN,32),
       Attribute::new(CKA_UNWRAP,true),
       Attribute::new(CKA_WRAP,true),
       Attribute::new(CKA_ENCRYPT,true),
       Attribute::new(CKA_EXTRACTABLE,true),
   ];
   let result2 = unsafe { 
       generate_key( 
           target, 
           &mech, 
           key_template, 
       ) 
   }; 
   let (k,csum) = match result2 { 
   Ok((k, csum)) => { 
       // Successfully generated the keys 
       println!("Generated aes Key: {}", hex::encode(&k)); 
       println!("Generated csum: {}", hex::encode(&csum)); 
       (k,csum)
   }, 
   Err(error) => { 
       // There was an error 
       eprintln!("Error: {}", error); 
       return;
   } 
}; 
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************

    let mut hasher = Sha256::new();
    hasher.update(b"This data needs to be signed");
    let sign_data = hasher.finalize();   // This is a 32-byte array

    // Build the correct mechanism manually (your style)
    let mechanism = Mechanism {
        mechanism: CKM_ECDSA,
        parameter: None,
    };
    // sk should be Option<Vec<u8>> if following our SignSingle API
    let signature = match sign_single( target, &mechanism, Some(sk.clone()), &sign_data) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Sign error: {}", e);
            return; // or handle the error appropriately
        }
    };

    println!("Signature (hex) = {}", hex::encode(&signature)); 
    
    //let iv = vec![0u8; 16];

//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
    let iv = match generate_random( target, 16) {
        Ok(iv) => iv,
        Err(e) => {
            eprintln!("Failed to generate IV: {}", e);
            return;
        }
    };
    // 2. Build AES-CBC-PAD mechanism with the IV
    let mechanism = Mechanism {
        mechanism: CKM_AES_CBC_PAD,
        parameter: Some(iv.clone()), // pass IV as parameter
    };

    let mut data = b"this is a string that will be ciphered in rust";
    let cipher = match encrypt_single( target, &mechanism, k.clone(), data) {
        Ok(cip) => cip,
        Err(e) => {
            eprintln!("Encrypt error: {}", e);
            return; // or handle the error appropriately
        }
    };
    let mut encrypted_with_iv = iv;
    encrypted_with_iv.extend_from_slice(&cipher);

    println!("cipher (hex) = {}", hex::encode(&encrypted_with_iv)); 

//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
    let iv2 = &encrypted_with_iv[..16];
    let ciphertext2 = &encrypted_with_iv[16..];

    // Build AES-CBC-PAD mechanism with the IV
    let mechanism = Mechanism {
        mechanism: CKM_AES_CBC_PAD,
        parameter: Some(iv2.to_vec()),
    };

match decrypt_single( target, &mechanism, k.clone(), &ciphertext2) {
    Ok(plain) => println!("plain = {}", String::from_utf8_lossy(&plain)),
    Err(e) => eprintln!("Decryption error: {}", e),
}

 // Generate random IV
    let iv = match generate_random( target, 16) {
        Ok(iv) => iv,
        Err(e) => {
            eprintln!("Failed to generate IV: {}", e);
            return;
        }
    };
    println!("random (hex) = {}", hex::encode(&iv));

//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
   let mech = Mechanism { 
       mechanism: CKM_AES_KEY_GEN, 
       parameter: None, 
   }; 

   let key_template = vec![ 
       Attribute::new(CKA_VALUE_LEN,32),
       Attribute::new(CKA_UNWRAP,true),
       Attribute::new(CKA_WRAP,true),
       Attribute::new(CKA_ENCRYPT,true),
       Attribute::new(CKA_DECRYPT,true),
   ];
   let result2 = unsafe { 
       generate_key( 
           target, 
           &mech, 
           key_template, 
       ) 
   }; 
   let (ref k, ref csum) = match result2 {
        Ok((k, csum)) => (k, csum),
        Err(error) => {
            eprintln!("Error: {}", error);
            return; // This is valid because main() returns ()
        }
    };

    let iv = vec![0u8; 16];

    let mechanism = Mechanism {
        mechanism: CKM_AES_CBC_PAD,
        parameter: Some(iv.clone()), // pass IV as parameter
    };
    let seed_hex = "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542";
    let seed = hex::decode(seed_hex).expect("Invalid hex string");

    let cipher = match encrypt_single( target, &mechanism, k.clone(), &seed) {
        Ok(cip) => cip,
        Err(e) => {
            eprintln!("Encrypt error: {}", e);
            return; // or handle the error appropriately
        }
    };
   
   let key_template4 = vec![ 
       Attribute::new(CKA_UNWRAP,false),
       Attribute::new(CKA_WRAP,false),
       Attribute::new(CKA_SIGN,true),
       Attribute::new(CKA_VERIFY,true),
       Attribute::new(CKA_DERIVE,true),
       Attribute::new(CKA_IBM_USE_AS_DATA,true),
       Attribute::new(CKA_VALUE_LEN,seed.len() as u64),
       Attribute::new(CKA_CLASS,CKO_SECRET_KEY),
       Attribute::new(CKA_KEY_TYPE,CKK_GENERIC_SECRET),
   ];
    let (seedblob, csum) = match unwrap_key( target, &Mechanism { mechanism: CKM_AES_CBC_PAD, parameter: Some(iv.clone()) }, k.clone(),cipher ,key_template4) {
    Ok((uk, cs)) => (uk, cs),
    Err(e) => {
        eprintln!("Unwrap error: {}", e);
        return;
    }
   };
  
    let wrapkey = match wrap_key( target, &Mechanism { mechanism: CKM_AES_CBC_PAD, parameter: Some(iv.clone()) }, k.clone(),seedblob.clone()) {
        Ok(wk) => wk,
        Err(e) => {
            eprintln!("Wrap error: {}", e);
            return;
        }
   };

   println!("wrapkey = {}", hex::encode(&wrapkey));
   

//************************************************************************************************
//************************************************************************************************
//************************************************************************************************
//************************************************************************************************

// ASN.1 OID for secp256k1
//let ec_parameters = encode_oid("1.3.132.0.10");
    let ec_parameters = encode_oid(OIDNAMEDCURVEED25519); 

// DeriveKey attributes (equivalent to Go map)
let derive_key_template = vec![
    Attribute::new(CKA_EC_PARAMS, ec_parameters.clone()),
    Attribute::new(CKA_VERIFY, true),
    Attribute::new(CKA_DERIVE, true),
    Attribute::new(CKA_PRIVATE, true),
    Attribute::new(CKA_SENSITIVE, true),
    Attribute::new(CKA_IBM_USE_AS_DATA, true),
    Attribute::new(CKA_KEY_TYPE, CKK_ECDSA),
    Attribute::new(CKA_VALUE_LEN, 0u64),
];

let btc_params = BTCDeriveParams {
    derive_type: CK_IBM_SLIP0010_MASTERK,
    child_key_index: 0,
    chain_code: Vec::new(),
    version: XCP_BTC_VERSION,
};

let btc_params = new_btc_derive_params(&btc_params);

// Prepare mechanism
let mech = Mechanism {
    mechanism: CKM_IBM_BTC_DERIVE,
    parameter: Some(btc_params),
};
/*
let seedblob_hex = env::var("MASTERSEED")
    .expect("MASTERSEED environment variable not set");

let seedblob = hex::decode(&seedblob_hex)
    .expect("MASTERSEED is not valid hex");*/

// baseKey is your parent keyblob
let base_key_bytes: Option<&[u8]> = if seedblob.is_empty() {
    None
} else {
    Some(&seedblob)
};

match base_key_bytes {
    Some(bytes) => {
        println!("base_key_bytes = {}", hex::encode(bytes));
    }
    None => {
        println!("base_key_bytes = <none>");
    }
}

// ---- Call Rust DeriveKey ----
let (new_key_bytes, checksum) =
    match derive_key( target, &mech, base_key_bytes, derive_key_template) {
        Ok((k, c)) => (k, c),
        Err(e) => panic!("Derived Child Key request error: {}", e),
    };

println!("Derived Key  = {}", hex::encode(&new_key_bytes));
println!("Checksum     = {}", hex::encode(&checksum));

} 
 
