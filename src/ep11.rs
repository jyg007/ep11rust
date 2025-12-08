extern crate libc;
use std::ffi::c_void;
use std::os::raw::{c_char, c_int,  c_ulong};
use std::ptr;
use std::time::SystemTime;
use libloading::{Library, Symbol};
use std::sync::Mutex;
use std::sync::OnceLock;

static LIB: OnceLock<Library> = OnceLock::new();

// Static cached function pointer
static M_SIGN_SINGLE: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64, *mut CK_MECHANISM, *mut u8, u64, *mut u8, *mut u64, u64
) -> u64>> = OnceLock::new();



fn init_sign_single() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64, *mut CK_MECHANISM, *mut u8, u64, *mut u8, *mut u64, u64
) -> u64> {
    M_SIGN_SINGLE.get_or_init(|| {
        let lib = init_lib();
        unsafe { lib.get(b"m_SignSingle\0").expect("Cannot load m_SignSingle") }
    })
}

static M_GENERATE_KEYPAIR: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut CK_MECHANISM, *mut CK_ATTRIBUTE, u64,
    *mut CK_ATTRIBUTE, u64,
    *mut u8, u64,
    *mut u8, *mut u64,
    *mut u8, *mut u64,
    u64
) -> u64>> = OnceLock::new();

fn init_generate_keypair() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut CK_MECHANISM, *mut CK_ATTRIBUTE, u64,
    *mut CK_ATTRIBUTE, u64,
    *mut u8, u64,
    *mut u8, *mut u64,
    *mut u8, *mut u64,
    u64
) -> u64> {
    M_GENERATE_KEYPAIR.get_or_init(|| {
        let lib = init_lib(); // your function to initialize/load lib
        unsafe { lib.get(b"m_GenerateKeyPair\0").expect("Cannot load m_GenerateKeyPair") }
    })
}

static M_GENERATE_KEY: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut CK_MECHANISM, *mut CK_ATTRIBUTE, u64,
    *mut u8, u64,
    *mut u8, *mut u64,
    *mut u8, *mut u64,
    u64
) -> u64>> = OnceLock::new();

fn init_generate_key() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut CK_MECHANISM, *mut CK_ATTRIBUTE, u64,
    *mut u8, u64,
    *mut u8, *mut u64,
    *mut u8, *mut u64,
    u64
) -> u64> {
    M_GENERATE_KEY.get_or_init(|| {
        let lib = init_lib(); // your function that returns &'static Library
        unsafe { lib.get(b"m_GenerateKey\0").expect("Cannot load m_GenerateKey") }
    })
}

static M_ENCRYPT_SINGLE: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64,
    *mut CK_MECHANISM,
    *mut u8, u64,
    *mut u8, *mut u64,
    u64
) -> u64>> = OnceLock::new();

fn init_encrypt_single() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64,
    *mut CK_MECHANISM,
    *mut u8, u64,
    *mut u8, *mut u64,
    u64
) -> u64> {
    M_ENCRYPT_SINGLE.get_or_init(|| {
        let lib = init_lib(); // function returning &'static Library
        unsafe { lib.get(b"m_EncryptSingle\0").expect("Cannot load m_EncryptSingle") }
    })
}

static M_DECRYPT_SINGLE: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64,
    *mut CK_MECHANISM,
    *mut u8, u64,
    *mut u8, *mut u64,
    u64
) -> u64>> = OnceLock::new();

fn init_decrypt_single() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64,
    *mut CK_MECHANISM,
    *mut u8, u64,
    *mut u8, *mut u64,
    u64
) -> u64> {
    M_DECRYPT_SINGLE.get_or_init(|| {
        let lib = init_lib(); // your function returning &'static Library
        unsafe { lib.get(b"m_DecryptSingle\0").expect("Cannot load m_DecryptSingle") }
    })
}

static M_DERIVE_KEY: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut CK_MECHANISM,
    *mut CK_ATTRIBUTE,
    u64,
    *mut u8,
    u64,
    *mut u8,
    u64,
    *mut u8,
    u64,
    *mut u8,
    *mut u64,
    *mut u8,
    *mut u64,
    u64
) -> u64>> = OnceLock::new();

fn init_derive_key() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut CK_MECHANISM,
    *mut CK_ATTRIBUTE,
    u64,
    *mut u8,
    u64,
    *mut u8,
    u64,
    *mut u8,
    u64,
    *mut u8,
    *mut u64,
    *mut u8,
    *mut u64,
    u64
) -> u64> {
    M_DERIVE_KEY.get_or_init(|| {
        let lib = init_lib(); // returns &'static Library
        unsafe { lib.get(b"m_DeriveKey\0").expect("Cannot load m_DeriveKey") }
    })
}

static M_UNWRAP_KEY: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64,          // wrapped key
    *mut u8, u64,          // KEK
    *mut u8, u64,          // MAC key
    *mut u8, u64,          // Login blob
    *mut CK_MECHANISM,     // mechanism
    *mut CK_ATTRIBUTE, u64,// template
    *mut u8, *mut u64,     // unwrapped key
    *mut u8, *mut u64,     // checksum
    u64,                   // target
) -> u64>> = OnceLock::new();

fn init_unwrap_key() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64, *mut u8, u64, *mut u8, u64, *mut u8, u64,
    *mut CK_MECHANISM, *mut CK_ATTRIBUTE, u64,
    *mut u8, *mut u64, *mut u8, *mut u64,
    u64
) -> u64> {
    M_UNWRAP_KEY.get_or_init(|| {
        let lib = init_lib(); // returns &'static Library
        unsafe { lib.get(b"m_UnwrapKey\0").expect("Cannot load m_UnwrapKey") }
    })
}

// Static cached function pointer for m_WrapKey
static M_WRAP_KEY: OnceLock<Symbol<'static, unsafe extern "C" fn(
    key: *const u8,
    key_len: u64,
    kek: *const u8,
    kek_len: u64,
    mac_key: *const u8,
    mac_key_len: u64,
    mech: *const CK_MECHANISM,
    wrapped: *mut u8,
    wrapped_len: *mut u64,
    target: u64,
) -> u64>> = OnceLock::new();

fn init_wrap_key() -> &'static Symbol<'static, unsafe extern "C" fn(
    key: *const u8,
    key_len: u64,
    kek: *const u8,
    kek_len: u64,
    mac_key: *const u8,
    mac_key_len: u64,
    mech: *const CK_MECHANISM,
    wrapped: *mut u8,
    wrapped_len: *mut u64,
    target: u64,
) -> u64> {
    M_WRAP_KEY.get_or_init(|| {
        let lib = init_lib(); // returns &'static Library
        unsafe { lib.get(b"m_WrapKey\0").expect("Cannot load m_WrapKey") }
    })
}

static M_GENERATE_RANDOM: OnceLock<Symbol<'static, unsafe extern "C" fn(*mut u8, u64, u64) -> u64>> = OnceLock::new();

fn init_generate_random() -> &'static Symbol<'static, unsafe extern "C" fn(*mut u8, u64, u64) -> u64> {
    M_GENERATE_RANDOM.get_or_init(|| {
        let lib = init_lib(); // Returns &'static Library
        unsafe { lib.get(b"m_GenerateRandom\0").expect("Cannot load m_GenerateRandom") }
    })
}

static M_VERIFY_SINGLE: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64, *mut CK_MECHANISM, *mut u8, u64, *mut u8, u64, u64
) -> u64>> = OnceLock::new();

fn init_verify_single() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8, u64, *mut CK_MECHANISM, *mut u8, u64, *mut u8, u64, u64
) -> u64> {
    M_VERIFY_SINGLE.get_or_init(|| {
        let lib = init_lib(); // your global library loader function
        unsafe { lib.get(b"m_VerifySingle\0").expect("Cannot load m_VerifySingle") }
    })
}

pub const MAX_BLOB_SIZE: usize = 9000;

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
pub const OIDNAMEDCURVESECP256K1: &str = "1.3.132.0.10";
pub const OIDNAMEDCURVEED25519: &str = "1.3.101.112";

fn init_lib() -> &'static Library {
    LIB.get_or_init(|| {
        unsafe { Library::new("libep11.so").expect("Failed to load libep11") }
    })
}

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
println!("Type: {:X}", attr.type_);
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
pub fn generate_key_pair(target: u64, mechanism: &Mechanism, pk_attributes: Vec<Attribute>, sk_attributes: Vec<Attribute>) -> Result<(Vec<u8>, Vec<u8>), String> {
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
    let mut sk_key = vec![0u8; MAX_BLOB_SIZE]; // Adjust size as needed
    let mut pk_key = vec![0u8; MAX_BLOB_SIZE]; // Adjust size as needed
    let mut pk_key_len: u64 = pk_key.len() as u64;
    let mut sk_key_len: u64 = sk_key.len() as u64;

      let m_generate_keypair=init_generate_keypair();
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
 //     }
    };
    pk_key.truncate(pk_key_len as usize);
    sk_key.truncate(sk_key_len as usize);

    Ok((pk_key, sk_key))
}


//************************************************************************************************
//************************************************************************************************
pub fn wrap_key(
    target: u64,
    mechanism: &Mechanism,
    kek: Vec<u8>,
    key: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let m_wrap_key=init_wrap_key();
        // Convert Mechanism → CK_MECHANISM
        let mut arena = Arena::new();

        let mut mech_struct = CK_MECHANISM {
            mechanism: mechanism.mechanism,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        };

        if let Some(param) = &mechanism.parameter {
            let buf_ptr = arena.allocate(param);
            mech_struct.pParameter = buf_ptr.ptr;
            mech_struct.ulParameterLen = param.len() as u64;
        }
        // Output buffer
        let mut wrapped = vec![0u8; MAX_BLOB_SIZE];
        let mut wrapped_len = wrapped.len() as u64;

        // Input pointers
        let key_ptr = if key.is_empty() { std::ptr::null() } else { key.as_ptr() };
        let kek_ptr = if kek.is_empty() { std::ptr::null() } else { kek.as_ptr() };

        // No MAC key used
        let mac_key_ptr: *const u8 = std::ptr::null();
        let mac_key_len: u64 = 0;

    unsafe {
        // Call EP11 m_WrapKey
        let rc = (m_wrap_key)(
            key_ptr,
            key.len() as u64,
            kek_ptr,
            kek.len() as u64,
            mac_key_ptr,
            mac_key_len,
            &mut mech_struct,
            wrapped.as_mut_ptr(),
            &mut wrapped_len,
            target,
        );

        if rc != CKR_OK {
            return Err(format!("m_WrapKey failed: {:#X}", rc));
        }
        

        wrapped.truncate(wrapped_len as usize);
        Ok(wrapped)
    }
}

//************************************************************************************************
//************************************************************************************************
pub fn unwrap_key(
    target: u64,
    mechanism: &Mechanism,
    kek: Vec<u8>,
    wrapped_key: Vec<u8>,
    template: Vec<Attribute>,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut attr_arena = Arena::new();
    let mut t_ctx = AttributeContext::new(template);
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: ptr::null_mut(),
        ulParameterLen: 0,
    };

    if let Some(param) = &mechanism.parameter {
        let buf_ptr = attr_arena.allocate(param);
        mech_struct.pParameter = buf_ptr.ptr;
        mech_struct.ulParameterLen = param.len() as u64;
    }

    // Buffers for unwrapped key and checksum
    let mut unwrapped_key = vec![0u8; MAX_BLOB_SIZE];
    let mut csum = vec![0u8; MAX_BLOB_SIZE];
    let mut unwrapped_len = unwrapped_key.len() as u64;
    let mut csum_len = csum.len() as u64;

    let mac_key_ptr: *mut u8 = ptr::null_mut();
    let mac_key_len: u64 = 0;

    //t_ctx.print_ck_attributes();
    let rv = unsafe {
        let m_unwrap_key=init_unwrap_key();
        m_unwrap_key(
            wrapped_key.as_ptr() as *mut u8,
            wrapped_key.len() as u64,
            kek.as_ptr() as *mut u8,
            kek.len() as u64,
            mac_key_ptr,
            mac_key_len,
            get_login_blob_ptr(),
            get_login_blob_len(),
            &mut mech_struct,
            t_ctx.as_mut_ptr() as *mut CK_ATTRIBUTE,
            t_ctx.len() as u64,
            unwrapped_key.as_mut_ptr(),
            &mut unwrapped_len,
            csum.as_mut_ptr(),
            &mut csum_len,
            target,
        )
    };

    if rv != CKR_OK {
        return Err(to_error(rv));
    }

    unwrapped_key.truncate(unwrapped_len as usize);
    csum.truncate(csum_len as usize);

    Ok((unwrapped_key, csum))
}

//************************************************************************************************
//************************************************************************************************
pub fn decrypt_single(
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
    let mut plain = vec![0u8; cipher.len() + MAX_BLOB_SIZE];
    let mut plain_len = plain.len() as u64;
    let plain_ptr = plain.as_mut_ptr();

    let m_decrypt_single=init_decrypt_single();
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

//************************************************************************************************
//************************************************************************************************
pub fn encrypt_single(
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

    let mut cipher = vec![0u8; data.len() + MAX_BLOB_SIZE];
    let mut cipher_len = cipher.len() as u64;
    let cipher_ptr = cipher.as_mut_ptr();

    let m_encrypt_single=init_encrypt_single();
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
//************************************************************************************************
//************************************************************************************************
pub fn generate_key(target: u64, mechanism: &Mechanism, k_attributes: Vec<Attribute>) -> Result<(Vec<u8>,Vec<u8>), String> {
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
    let mut k_key = vec![0u8; MAX_BLOB_SIZE]; // Adjust size as needed
    let mut k_key_len: u64 = k_key.len() as u64;
    let mut csum = vec![0u8; MAX_BLOB_SIZE]; // Adjust size as needed
    let mut csum_len: u64 = csum.len() as u64;

       let m_generate_key = init_generate_key();
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
    };
    k_key.truncate(k_key_len as usize);
    csum.truncate(csum_len as usize);

    Ok((k_key,csum))
}

//************************************************************************************************
//************************************************************************************************
pub fn sign_single(
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
    let mut sig = vec![0u8; MAX_BLOB_SIZE];     // adjust to MAX_BLOB_SIZE
    let sig_ptr = sig.as_mut_ptr();
    let mut sig_len: u64 = sig.len() as u64;

    let m_sign_single = init_sign_single();

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


//************************************************************************************************
//************************************************************************************************
pub fn hsm_init(input: &str) -> Result<u64, String> {
    unsafe {
        let lib = init_lib();
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

            let mut module_flags = XCP_MFL_PROBE | XCP_MFL_MODULE;

            if input.split_whitespace().count() > 1 {
                module_flags |= XCP_MFL_VIRTUAL;
            }

            module.flags = module_flags;

            let rc = m_add_module(&mut module, &mut target);
            if rc != CKR_OK {
                    println!( "Error from m_add_module: {:#X} | module={:02} | domain={:04}", rc, adapter, domain);
            }
        }
        // Handle EP11LOGIN env variable
        if let Ok(hex_string) = std::env::var("EP11LOGIN") {
            if !hex_string.is_empty() {
                match hex::decode(&hex_string) {
                    Ok(blob) => {
                        // Call your set_login_blob function
                        set_login_blob(&blob);
                        println!("Login blob set from environment variable.");
                    }
                    Err(e) => eprintln!("Failed to decode EP11LOGIN: {}", e),
                }
            }
        }

        Ok(target)
    }
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BTCDeriveParams {
    pub derive_type: u64,
    pub child_key_index: u64,
    pub chain_code: Vec<u8>,
    pub version: u64,
}

#[repr(C)]
pub struct CK_IBM_BTC_DERIVE_PARAMS {
    pub _type: u64,
    pub childKeyIndex: u64,
    pub pChainCode: *const u8,
    pub ulChainCodeLen: u64,
    pub version: u64,
}
pub fn new_btc_derive_params(p: &BTCDeriveParams) -> Vec<u8> {
    let (ptr, len) = if p.chain_code.is_empty() {
        (std::ptr::null(), 0u64)
    } else {
        (p.chain_code.as_ptr(), p.chain_code.len() as u64)
    };

    let params = CK_IBM_BTC_DERIVE_PARAMS {
        _type: p.derive_type,
        childKeyIndex: p.child_key_index,
        pChainCode: ptr,
        ulChainCodeLen: len,
        version: p.version,
    };

    // SAFETY: the struct is POD, we can copy it as bytes
    let size = std::mem::size_of::<CK_IBM_BTC_DERIVE_PARAMS>();
    let mut out = vec![0u8; size];

    unsafe {
        std::ptr::copy_nonoverlapping(
            &params as *const _ as *const u8,
            out.as_mut_ptr(),
            size,
        );
    }

    out
}


//************************************************************************************************
//************************************************************************************************
pub fn derive_key( target: u64, mechanism: &Mechanism, base_key: Option<&[u8]>, attrs: Vec<Attribute>) -> Result<(Vec<u8>, Vec<u8>), String> {
    unsafe {
    let m_derive_key=init_derive_key();
    let mut arena = Arena::new();

    // ---- Build CK_MECHANISM ----
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    // Convert attributes
    let mut k_attr = AttributeContext::new(attrs);
    
    if let Some(param) = &mechanism.parameter {
        let buf_ptr = arena.allocate(param);
        mech_struct.pParameter = buf_ptr.ptr ;
        mech_struct.ulParameterLen = param.len() as u64;
    }

        // Base key pointer
        let (base_key_ptr, base_key_len) = match base_key {
            Some(bk) if !bk.is_empty() => (bk.as_ptr() as *mut u8, bk.len() as u64),
            _ => (std::ptr::null_mut(), 0),
        };

        // Output buffers
//        const MAX_BLOB_SIZE: usize = 4096;
        let mut new_key = vec![0u8; MAX_BLOB_SIZE];
        let mut csum = vec![0u8; MAX_BLOB_SIZE];

        let mut new_key_len = new_key.len() as u64;
        let mut csum_len = csum.len() as u64;

        // Empty data buffer 
        let data_ptr = std::ptr::null_mut();
        let data_len = 0u64;

        // Login blob
        let login_ptr = get_login_blob_ptr();
        let login_len = get_login_blob_len();

        // Call m_DeriveKey
        let rv = m_derive_key(
            &mut mech_struct,
            k_attr.as_mut_ptr() as *mut CK_ATTRIBUTE,
            k_attr.len() as u64,
            base_key_ptr,
            base_key_len,
            data_ptr,
            data_len,
            login_ptr,
            login_len,
            new_key.as_mut_ptr(),
            &mut new_key_len,
            csum.as_mut_ptr(),
            &mut csum_len,
            target,
        );

        if rv != CKR_OK {
            return Err(format!("m_DeriveKey failed: {:#X}", rv));
        }

        new_key.truncate(new_key_len as usize);
        csum.truncate(csum_len as usize);

        Ok((new_key, csum))
    }
}

//************************************************************************************************
//************************************************************************************************
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

//************************************************************************************************
//************************************************************************************************
pub fn generate_random(
    target: u64,
    length: usize,
) -> Result<Vec<u8>, String> {
    let mut random_data = vec![0u8; length];

    // Load the C function (unsafe)
    let m_generate_random=init_generate_random();
    // Call the function
    let rc = unsafe {
        m_generate_random(random_data.as_mut_ptr(), length as u64, target)
    };

    if rc != CKR_OK {
        return Err(to_error(rc));
    }

    Ok(random_data)
}

//************************************************************************************************
//************************************************************************************************
pub fn verify_single(
    target: u64,
    mechanism: &Mechanism,
    public_key: Vec<u8>,
    data: &[u8],
    sig: &[u8],
) -> Result<(), String> {
    // Allocate mechanism arena
    let mut mech_arena = Arena::new();
    let mut mech_struct = CK_MECHANISM {
        mechanism: mechanism.mechanism,
        pParameter: std::ptr::null_mut(),
        ulParameterLen: 0,
    };

    // If mechanism has parameters, allocate them in the arena
    if let Some(param) = &mechanism.parameter {
        let buf_ptr = mech_arena.allocate(param);
        mech_struct.pParameter = buf_ptr.ptr;
        mech_struct.ulParameterLen = param.len() as u64;
    }

    // Convert keys/data/signature to raw pointers
    let pk_ptr = public_key.as_ptr() as *mut u8;
    let pk_len = public_key.len() as u64;
    let data_ptr = data.as_ptr() as *mut u8;
    let data_len = data.len() as u64;
    let sig_ptr = sig.as_ptr() as *mut u8;
    let sig_len = sig.len() as u64;

    // Call the C function
    let rc = unsafe {
        let m_verify_single = init_verify_single(); // your OnceLock cached pointer
        m_verify_single(pk_ptr, pk_len, &mut mech_struct, data_ptr, data_len, sig_ptr, sig_len, target)
    };

    if rc == CKR_OK {
        Ok(())
    } else {
        Err(format!("m_VerifySingle failed: {:#X}", rc))
    }
}
