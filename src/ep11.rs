extern crate libc;
use libc::{calloc, free};
use std::ffi::CString;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int, c_uint, c_ulong};
use std::ptr;
use std::time::SystemTime;
use libloading::{Library, Symbol};
use std::sync::Mutex;
use std::slice;
use std::mem;



pub const XCP_OK: u32 = 0;
pub const CKR_OK: u64 = 0;
pub const XCP_MOD_VERSION: u32 = 2;
pub const XCP_MFL_VIRTUAL: u64 = 0x10;
pub const XCP_MFL_PROBE: u64 = 0x40;
pub const XCP_MFL_MODULE: u64 = 0x02;
pub const XCP_TGT_INIT: u64 = 0xFFFFFFFFFFFFFFFF;
pub const XCP_KEYCSUM_BYTES: usize = 32;
pub const XCP_ADMCTR_BYTES: usize = 16;
pub const XCP_SERIALNR_CHARS: usize = 8;
pub const MAX_FNAME_CHARS: usize = 256;

pub struct Ep11 {
    pub m_GenerateKeyPair: Symbol<'static, unsafe extern "C" fn(
        target: u64,
        mechanism: *const CK_MECHANISM,
        pPublicKeyTemplate: *const CK_ATTRIBUTE,
        ulPublicKeyAttributeCount: u64,
        pPrivateKeyTemplate: *const CK_ATTRIBUTE,
        ulPrivateKeyAttributeCount: u64,
        phPublicKey: *mut u64,
        phPrivateKey: *mut u64,
    ) -> u64>,
    // Add more as needed
}
/*
impl Ep11 {
    pub unsafe fn new(lib: &libloading::Library) -> Ep11 {
        Ep11 {
            m_GenerateKeyPair: lib.get(b"m_GenerateKeyPair\0").unwrap(),
            // Initialize other fields as necessary
        }
    }
}
*/
#[repr(C)]
#[derive(Debug)]
pub struct CK_MECHANISM {
    pub mechanism: c_ulong,       // CK_MECHANISM_TYPE
    pub pParameter: *mut c_void,  // CK_VOID_PTR
    pub ulParameterLen: c_ulong,  // CK_ULONG
}

#[repr(C)]
#[derive(Debug)]
pub struct CK_ATTRIBUTE {
    pub type_: c_ulong,           // CK_ATTRIBUTE_TYPE
    pub pValue: *mut c_void,      // CK_VOID_PTR
    pub ulValueLen: c_ulong,      // CK_ULONG
}

#[repr(C)]
pub struct XCP_ModuleSocket {
    pub host: [c_char; MAX_FNAME_CHARS + 1],
    pub port: u32,
}

#[repr(C)]
pub struct XCP_DomainPerf {
    pub lastperf: [u32; 256],
}

#[repr(C)]
pub struct XCP_Module {
    pub version: u32,
    pub flags: u64,
    pub domains: u32,
    pub domainmask: [u8; 32],
    pub socket: XCP_ModuleSocket,
    pub module_nr: u32,
    pub mhandle: *mut c_void,
    pub perf: XCP_DomainPerf,
    pub api: u32,
}

pub fn xcptgtmask_set_dom(mask: &mut [u8; 32], domain: usize) {
    let byte_index = domain / 8;
    let bit = 1 << (7 - (domain % 8));
    mask[byte_index] |= bit;
}

pub type Ep11MInit = unsafe extern "C" fn() -> c_int;
pub type Ep11AddModule = unsafe extern "C" fn(*mut XCP_Module, *mut u64) -> u32;



static LOGIN_BLOB: Mutex<Option<Vec<u8>>> = Mutex::new(None);
static LOGIN_BLOB_LEN: Mutex<u64> = Mutex::new(0);

// Constants for OIDs
const OIDNAMEDCURVESECP256K1: &str = "1.3.132.0.10";
const OIDNAMEDCURVEED25519: &str = "1.3.101.112";


// SetLoginBlob function to set global blob and its length
pub fn set_login_blob(id_bytes: &[u8]) {
    let mut login_blob = LOGIN_BLOB.lock().unwrap(); // lock to ensure safe access
    let mut login_blob_len = LOGIN_BLOB_LEN.lock().unwrap(); // lock to safely modify length
    *login_blob = Some(id_bytes.to_vec());
    *login_blob_len = id_bytes.len() as u64;
}

// Function to get a pointer to the login blob (for use with C API)
pub fn get_login_blob_ptr() -> *mut u8 {
    let login_blob = LOGIN_BLOB.lock().unwrap();
    match &*login_blob {
        Some(blob) => blob.as_ptr() as *mut u8, // return a pointer to the login blob data
        None => ptr::null_mut(),
    }
}

// Function to get the length of the login blob
pub fn get_login_blob_len() -> u64 {
    let login_blob_len = LOGIN_BLOB_LEN.lock().unwrap();
    *login_blob_len // Return the length of the login blob
}


// Helper function to convert error codes to strings
fn to_error(code: u64) -> String {
    format!("Error code: {:#X}", code)
}

#[derive(Debug)]
pub struct Attribute {
    pub r#type: u64,
    pub Value: Vec<u8>,
}

impl Attribute {
    pub fn new<T: IntoAttributeValue>(attr_type: u64, value: T) -> Self {
        Self {
            r#type: attr_type,
            Value: value.into_bytes(),
        }
    }
}

pub trait IntoAttributeValue {
    fn into_bytes(self) -> Vec<u8>;
}

impl IntoAttributeValue for bool {
    fn into_bytes(self) -> Vec<u8> {
        vec![if self { 1 } else { 0 }]
    }
}

impl IntoAttributeValue for u64 {
    fn into_bytes(self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for u32 {
    fn into_bytes(self) -> Vec<u8> {
        (self as u64).to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for u16 {
    fn into_bytes(self) -> Vec<u8> {
        (self as u64).to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for u8 {
    fn into_bytes(self) -> Vec<u8> {
        (self as u64).to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for i64 {
    fn into_bytes(self) -> Vec<u8> {
        (self as u64).to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for i32 {
    fn into_bytes(self) -> Vec<u8> {
        (self as u64).to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for i16 {
    fn into_bytes(self) -> Vec<u8> {
        (self as u64).to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for i8 {
    fn into_bytes(self) -> Vec<u8> {
        (self as u64).to_be_bytes().to_vec()
    }
}

impl IntoAttributeValue for String {
    fn into_bytes(self) -> Vec<u8> {
        self.into_bytes()
    }
}

impl<'a> IntoAttributeValue for &'a str {
    fn into_bytes(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }
}

impl IntoAttributeValue for Vec<u8> {
    fn into_bytes(self) -> Vec<u8> {
        self
    }
}

impl<'a> IntoAttributeValue for &'a [u8] {
    fn into_bytes(self) -> Vec<u8> {
        self.to_vec()
    }
}

impl IntoAttributeValue for SystemTime {
    fn into_bytes(self) -> Vec<u8> {
        // Placeholder: format like YYYYMMDD as ASCII bytes (needs actual date conversion)
        b"20250101".to_vec()
    }
}


pub struct Allocation {
    pub ptr: *mut c_void,
    pub len: usize,
}

pub struct Arena {
    allocations: Vec<*mut c_void>,
}

impl Arena {
    pub fn new() -> Self {
        Arena {
            allocations: Vec::new(),
        }
    }

    pub fn allocate(&mut self, data: &[u8]) -> Allocation {
        unsafe {
            let size = data.len();
            let mem = libc::calloc(size, 1);

            if mem.is_null() {
                panic!("Arena allocation failed");
            }

            ptr::copy_nonoverlapping(data.as_ptr(), mem as *mut u8, size);
            self.allocations.push(mem);

            Allocation {
                ptr: mem,
                len: size,
            }
        }
    }
}

impl Drop for Arena {
    fn drop(&mut self) {
        for &ptr in &self.allocations {
            unsafe {
                libc::free(ptr);
            }
        }
    }
}

// Mechanism struct
pub struct Mechanism {
    pub mechanism: u64,
    pub parameter: Option<Vec<u8>>, // Optional parameter, equivalent to the Python version
}

impl Mechanism {
    fn new(mechanism: u64, parameter: Option<Vec<u8>>) -> Self {
        Mechanism {
            mechanism,
            parameter,
        }
    }
}


pub struct AttributeContext {
    pub attrs: Vec<Attribute>,
    pub buffers: Vec<Vec<u8>>,
}

impl AttributeContext {
    pub fn new(attributes: Vec<Attribute>) -> Self {
        let mut buffers = Vec::with_capacity(attributes.len());

        for attr in &attributes {
            buffers.push(attr.Value.clone()); // keep cloned buffer for lifetime
        }

        Self {
            attrs: attributes,
            buffers,
        }
    }

    pub fn as_ck_attributes(&self) -> Vec<CK_ATTRIBUTE> {
        self.attrs
            .iter()
            .zip(self.buffers.iter())
            .map(|(attr, buf)| CK_ATTRIBUTE {
                type_: attr.r#type,
                pValue: buf.as_ptr() as *mut std::ffi::c_void,
                ulValueLen: buf.len() as u64,
            })
            .collect()
    }

    pub fn as_mut_ptr(&mut self) -> *mut CK_ATTRIBUTE {
        let mut ck_attributes = self.as_ck_attributes();

        let ptr = ck_attributes.as_mut_ptr();
        std::mem::forget(ck_attributes); // Prevent deallocation
        ptr
    }

    pub fn print_ck_attributes(&self) {
let ck_attributes = self.as_ck_attributes();
for attr in ck_attributes {
println!("Type: {}", attr.type_);
println!("Length: {}", attr.ulValueLen);
let value_bytes = unsafe { std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize) };
println!("Value: {:?}", value_bytes);
}
}

    pub fn len(&self) -> usize {
        self.attrs.len()
    }
}
// Function to generate key pair
pub fn generate_key_pair(lib: &Library,target: u64, mechanism: &Mechanism, pk_attributes: Vec<Attribute>, sk_attributes: Vec<Attribute>) -> Result<(Vec<u8>, Vec<u8>), String> {

    let mut arena = Arena::new();

    // Convert attributes
//    let pk_ck_attrs = convert_attributes_to_ck(pk_attributes );
//    let sk_ck_attrs = convert_attributes_to_ck(sk_attributes);
    let mut pub_ctx = AttributeContext::new(pk_attributes);
    let mut sk_ctx = AttributeContext::new(sk_attributes);
    
    // Create mechanism
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    if let Some(param) = &mechanism.parameter {
        let buf_ptr = arena.allocate(param);
        mech_struct.pParameter = buf_ptr.ptr ;
        mech_struct.ulParameterLen = param.len() as u64;
    }

    // Buffers to store the keys
    let mut sk_key = vec![0u8; 9000]; // Adjust size as needed
    let mut pk_key = vec![0u8; 9000]; // Adjust size as needed
    let mut pk_key_len: u64 = pk_key.len() as u64;
    let mut sk_key_len: u64 = sk_key.len() as u64;

    let rc = unsafe {
        let m_generate_keypair: Symbol<
                unsafe extern "C" fn(
        *mut CK_MECHANISM,
        *mut CK_ATTRIBUTE,
        u64,
        *mut CK_ATTRIBUTE,
        u64,
        *mut u8,
        u64,
        *mut u8,
        *mut u64,
        *mut u8,
        *mut u64,
        u64,
    ) -> u64
        > = lib.get(b"m_GenerateKeyPair\0").map_err(|e| e.to_string())?;
        let login_blob_ptr = get_login_blob_ptr();
        let login_blob_len = get_login_blob_len();
      unsafe {
       let rc: u64 = m_generate_keypair(
            &mut mech_struct,
            pub_ctx.as_mut_ptr() as *mut CK_ATTRIBUTE,
            pub_ctx.len() as u64,
            sk_ctx.as_mut_ptr() as *mut CK_ATTRIBUTE,
            sk_ctx.len() as u64,
            login_blob_ptr,
            login_blob_len,
            sk_key.as_mut_ptr() as *mut u8,
            &mut sk_key_len,
            pk_key.as_mut_ptr() as *mut u8,
            &mut pk_key_len,
            target,
        );
    if rc != CKR_OK {
        return Err(to_error(rc));
    }
      }
    };
    pk_key.truncate(pk_key_len as usize);
    sk_key.truncate(sk_key_len as usize);

    Ok((pk_key, sk_key))
}
pub fn decrypt_single(
    lib: &Library,
    target: u64,
    mechanism: &Mechanism,
    k: Vec<u8>,
    cipher: &[u8],
) -> Result<Vec<u8>, String> {
    let mut arena = Arena::new();

    // Create mechanism
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    if let Some(param) = &mechanism.parameter {
        let buf_ptr = arena.allocate(param);
        mech_struct.pParameter = buf_ptr.ptr ;
        mech_struct.ulParameterLen = param.len() as u64;
    }

    // Prepare key and cipher buffers
    let key_ptr = k.as_ptr() as *mut u8;
    let key_len = k.len() as u64;

    let cipher_ptr = cipher.as_ptr() as *mut u8;
    let cipher_len = cipher.len() as u64;

    // Allocate buffer for plaintext
    let mut plain = vec![0u8; cipher.len() + 9000];
    let mut plain_len = plain.len() as u64;
    let plain_ptr = plain.as_mut_ptr();

    // Load the C function
    let m_decrypt_single: Symbol<
        unsafe extern "C" fn(
            *mut u8, u64,
            *mut CK_MECHANISM,
            *mut u8, u64,
            *mut u8, *mut u64,
            u64
        ) -> u64
    > = unsafe { lib.get(b"m_DecryptSingle\0") }
    .map_err(|e| e.to_string())?;

    // Call the C function
    let rv = unsafe {
        m_decrypt_single(
            key_ptr,
            key_len,
            &mut mech_struct,
            cipher_ptr,
            cipher_len,
            plain_ptr,
            &mut plain_len,
            target,
        )
    };

    if rv != CKR_OK {
        return Err(to_error(rv));
    }

    // Truncate plaintext to actual length
    plain.truncate(plain_len as usize);

    Ok(plain)
}

pub fn encrypt_single(
    lib: &Library,
    target: u64,
    mechanism: &Mechanism,
    k: Vec<u8>,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let mut arena = Arena::new();

    // Create mechanism
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    if let Some(param) = &mechanism.parameter {
        let buf_ptr = arena.allocate(param);
        mech_struct.pParameter = buf_ptr.ptr ;
        mech_struct.ulParameterLen = param.len() as u64;
    }

    // Prepare key and data buffers
    let key_ptr = k.as_ptr() as *mut u8;
    let key_len = k.len() as u64;

    let (data_ptr, data_len) = if data.is_empty() {
        (std::ptr::null_mut(), 0)
    } else {
        (data.as_ptr() as *mut u8, data.len() as u64)
    };

    let mut cipher = vec![0u8; data.len() + 9000];
    let mut cipher_len = cipher.len() as u64;
    let cipher_ptr = cipher.as_mut_ptr();

    // Load the C function
    let m_encrypt_single: Symbol<
        unsafe extern "C" fn(
            *mut u8, u64,
            *mut CK_MECHANISM,
            *mut u8, u64,
            *mut u8, *mut u64,
            u64
        ) -> u64
    > =   unsafe { lib.get(b"m_EncryptSingle\0") }
    .map_err(|e| e.to_string())?;

    // Call the C function
    let rc = unsafe {
        m_encrypt_single(
            key_ptr,
            key_len,
            &mut mech_struct,
            data_ptr,
            data_len,
            cipher_ptr,
            &mut cipher_len,
            target,
        )
    };

    if rc != CKR_OK {
        return Err(to_error(rc));
    }

    // Truncate to actual length
    cipher.truncate(cipher_len as usize);

    Ok(cipher)
}

// Function to generate key 
pub fn generate_key(lib: &Library,target: u64, mechanism: &Mechanism, k_attributes: Vec<Attribute>) -> Result<(Vec<u8>,Vec<u8>), String> {

    let mut arena = Arena::new();

    // Convert attributes
    let mut k_ctx = AttributeContext::new(k_attributes);
    
    // Create mechanism
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    if let Some(param) = &mechanism.parameter {
        let buf_ptr = arena.allocate(param);
        mech_struct.pParameter = buf_ptr.ptr ;
        mech_struct.ulParameterLen = param.len() as u64;
    }

    // Buffers to store the keys
    let mut k_key = vec![0u8; 9000]; // Adjust size as needed
    let mut k_key_len: u64 = k_key.len() as u64;
    let mut csum = vec![0u8; 9000]; // Adjust size as needed
    let mut csum_len: u64 = csum.len() as u64;

    let rc = unsafe {
        let m_generate_key: Symbol<
                unsafe extern "C" fn(
        *mut CK_MECHANISM,
        *mut CK_ATTRIBUTE,
        u64,
        *mut u8,
        u64,
        *mut u8,
        *mut u64,
        *mut u8,
        *mut u64,
        u64,
    ) -> u64
        > = lib.get(b"m_GenerateKey\0").map_err(|e| e.to_string())?;
        let login_blob_ptr = get_login_blob_ptr();
        let login_blob_len = get_login_blob_len();
      unsafe {
       let rc: u64 = m_generate_key(
            &mut mech_struct,
            k_ctx.as_mut_ptr() as *mut CK_ATTRIBUTE,
            k_ctx.len() as u64,
            login_blob_ptr,
            login_blob_len,
            k_key.as_mut_ptr() as *mut u8,
            &mut k_key_len,
            csum.as_mut_ptr() as *mut u8,
            &mut csum_len,
            target,
        );
    if rc != CKR_OK {
        return Err(to_error(rc));
    }
      }
    };
    k_key.truncate(k_key_len as usize);
    csum.truncate(csum_len as usize);

    Ok((k_key,csum))
}

pub fn sign_single(
    lib: &Library,
    target: u64,
    mechanism: &Mechanism,
    sk: Option<Vec<u8>>,
    data: &[u8],
) -> Result<Vec<u8>, String> {
    let mut arena = Arena::new();

    // ---- Build CK_MECHANISM ----
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    if let Some(param) = &mechanism.parameter {
        let buf = arena.allocate(param);
        mech_struct.pParameter = buf.ptr;
        mech_struct.ulParameterLen = param.len() as u64;
    }

    // ---- Private key blob ----
    let (sk_ptr, sk_len) = match &sk {
        Some(blob) if !blob.is_empty() => (
            blob.as_ptr() as *mut u8,
            blob.len() as u64
        ),
        _ => (std::ptr::null_mut(), 0),
    };
    
    // ---- Data to sign ----
    let (data_ptr, data_len) = if data.is_empty() {
        (std::ptr::null_mut(), 0)
    } else {
        (data.as_ptr() as *mut u8, data.len() as u64)
    };

    // ---- Output signature buffer ----
    let mut sig = vec![0u8; 9000];     // adjust to MAX_BLOB_SIZE
    let sig_ptr = sig.as_mut_ptr();
    let mut sig_len: u64 = sig.len() as u64;

    // ---- Load the EP11 symbol ----
    let m_sign_single: Symbol<
        unsafe extern "C" fn(
            *mut u8,        // private key
            u64,            // private key len
            *mut CK_MECHANISM,
            *mut u8,        // data
            u64,            // data len
            *mut u8,        // output sig
            *mut u64,       // output sig len
            u64             // target
        ) -> u64
    > = unsafe { lib.get(b"m_SignSingle\0") }
        .map_err(|e| format!("Cannot load m_SignSingle: {}", e))?;

    // ---- Call EP11 ----
    let rc = unsafe {
        m_sign_single(
            sk_ptr,
            sk_len,
            &mut mech_struct,
            data_ptr,
            data_len,
            sig_ptr,
            &mut sig_len,
            target,
        )
    };

    if rc != CKR_OK {
        return Err(to_error(rc));
    }

    sig.resize(sig_len as usize, 0);
    Ok(sig)
}


pub fn hsm_init(input: &str, single: bool, lib: &Library) -> Result<u64, String> {
    unsafe {
        let m_init: Symbol<unsafe extern "C" fn() -> c_int> =
            lib.get(b"m_init").map_err(|e| e.to_string())?;
        let m_add_module: Symbol<unsafe extern "C" fn(*mut XCP_Module, *mut u64) -> u64> =
            lib.get(b"m_add_module").map_err(|e| e.to_string())?;

        if m_init() != XCP_OK as i32 {
            return Err("EP11 init error".into());
        }

        let mut target = XCP_TGT_INIT;
        let mut module = XCP_Module {
            version: XCP_MOD_VERSION,
            flags: 0,
            domains: 0,
            domainmask: [0; 32],
            socket: XCP_ModuleSocket {
                host: [0; MAX_FNAME_CHARS + 1],
                port: 0,
            },
            module_nr: 0,
            mhandle: ptr::null_mut(),
            perf: XCP_DomainPerf { lastperf: [0; 256] },
            api: 0,
        };

        for pair in input.trim().split_whitespace() {
            let parts: Vec<&str> = pair.split('.').collect();
            if parts.len() != 2 {
                eprintln!("Invalid format: {}", pair);
                continue;
            }

            let adapter: u32 = match parts[0].parse() {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid adapter number in: {}", pair);
                    continue;
                }
            };

            let domain: usize = match parts[1].parse() {
                Ok(val) => val,
                Err(_) => {
                    eprintln!("Invalid domain number in: {}", pair);
                    continue;
                }
            };

            println!("Initializing adapter {:02} and domain {}", adapter, domain);
            module.module_nr = adapter;
            module.domainmask = [0; 32];
            xcptgtmask_set_dom(&mut module.domainmask, domain);

            module.flags |= if single {
                XCP_MFL_PROBE | XCP_MFL_MODULE
            } else {
                XCP_MFL_VIRTUAL | XCP_MFL_PROBE | XCP_MFL_MODULE
            };

            let rc = m_add_module(&mut module, &mut target);
            if rc != CKR_OK {
                return Err(format!("Error from m_add_module: {:#X}", rc));
            }
        }

        Ok(target)
    }
}

pub fn encode_oid(oid_str: &str) -> Vec<u8> {
    // Split OID string into numbers
    let numbers: Vec<u32> = oid_str
        .split('.')
        .map(|s| s.parse::<u32>().expect("Invalid OID number"))
        .collect();

    if numbers.len() < 2 {
        panic!("OID must have at least two components");
    }

    let mut der: Vec<u8> = Vec::new();

    // Tag for OBJECT IDENTIFIER
    der.push(0x06);

    // Encode first two numbers into one byte: 40*X + Y
    let first_byte = 40 * numbers[0] + numbers[1];
    let mut value_bytes: Vec<u8> = vec![first_byte as u8];

    // Encode the remaining numbers in base-128 with continuation bit
    for &n in &numbers[2..] {
        let mut stack = Vec::new();
        let mut val = n;
        loop {
            stack.push((val & 0x7F) as u8);
            val >>= 7;
            if val == 0 {
                break;
            }
        }
        while let Some(byte) = stack.pop() {
            // Set the high bit for all but the last byte
            if stack.is_empty() {
                value_bytes.push(byte);
            } else {
                value_bytes.push(byte | 0x80);
            }
        }
    }
    // Length byte
    der.push(value_bytes.len() as u8);

    // Append value bytes
    der.extend(value_bytes);

    der
}


