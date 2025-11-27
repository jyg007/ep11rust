mod ep11; 
mod constants; 
 
use ep11::hsm_init; 
use ep11::Mechanism; 
use ep11::Attribute; 
use ep11::generate_key_pair; 
use ep11::generate_key; 
use ep11::generate_random; 
use ep11::sign_single;
use ep11::encrypt_single;
use ep11::decrypt_single;
use ep11::encode_oid;
use crate::ep11::Ep11; 
use crate::constants::*; 
use libloading::Library;
use sha2::{Sha256, Digest};
// Assuming the necessary imports and structs are defined in the same file 
 
fn main() { 
   // Load the ep11 shared library 
    let lib = unsafe { 
       Library::new("libep11.so").expect("Failed to load libep11") 
    }; 
 
   // Call the HsmInit function (from previous code) 
    let target = unsafe { hsm_init("03.19", false, &lib) }.expect("HSM initialization failed"); 
 
   // Prepare EC parameters (OIDNamedCurveSecp256k1) 
    let ec_parameters = encode_oid("1.3.132.0.10"); 
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
       generate_key_pair(&lib, 
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
       generate_key(&lib, 
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

    let mut hasher = Sha256::new();
    hasher.update(b"This data needs to be signed");
    let sign_data = hasher.finalize();   // This is a 32-byte array

    // Build the correct mechanism manually (your style)
    let mechanism = Mechanism {
        mechanism: CKM_ECDSA,
        parameter: None,
    };
    // sk should be Option<Vec<u8>> if following our SignSingle API
    let signature = match sign_single(&lib, target, &mechanism, Some(sk.clone()), &sign_data) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("Sign error: {}", e);
            return; // or handle the error appropriately
        }
    };

    println!("Signature (hex) = {}", hex::encode(&signature)); 
    
    //let iv = vec![0u8; 16];

    let iv = match generate_random(&lib, target, 16) {
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
    let cipher = match encrypt_single(&lib, target, &mechanism, k.clone(), data) {
        Ok(cip) => cip,
        Err(e) => {
            eprintln!("Encrypt error: {}", e);
            return; // or handle the error appropriately
        }
    };
    let mut encrypted_with_iv = iv;
    encrypted_with_iv.extend_from_slice(&cipher);

    println!("cipher (hex) = {}", hex::encode(&encrypted_with_iv)); 

    let iv2 = &encrypted_with_iv[..16];
    let ciphertext2 = &encrypted_with_iv[16..];

    // Build AES-CBC-PAD mechanism with the IV
    let mechanism = Mechanism {
        mechanism: CKM_AES_CBC_PAD,
        parameter: Some(iv2.to_vec()),
    };

match decrypt_single(&lib, target, &mechanism, k.clone(), &ciphertext2) {
    Ok(plain) => println!("plain = {}", String::from_utf8_lossy(&plain)),
    Err(e) => eprintln!("Decryption error: {}", e),
}

 // Generate random IV
    let iv = match generate_random(&lib, target, 16) {
        Ok(iv) => iv,
        Err(e) => {
            eprintln!("Failed to generate IV: {}", e);
            return;
        }
    };
    println!("random (hex) = {}", hex::encode(&iv));
} 
 
