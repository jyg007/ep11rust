
use std::ffi::c_void;
use std::os::raw::{c_char, c_int,  c_ulong};
use std::ptr;
use std::time::SystemTime;
use libloading::{Library, Symbol};
use std::sync::Mutex;
use std::sync::OnceLock;
use std::convert::TryInto;
// AES
use aes::Aes256;
use cipher::{ BlockEncrypt,generic_array::GenericArray,KeyInit};

// SHA-256
use sha2::{Sha256, Digest};
// Hex
use hex;

use openssl::error::ErrorStack;
use openssl::pkey::{PKey, Private, Public};
use openssl::derive::Deriver;
use openssl::ec::EcKey;
use openssl::ec::EcGroup;
use openssl::nid::Nid;
use openssl_sys::*;
use byteorder::{BigEndian, ByteOrder};

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


static M_GET_XCP_INFO: OnceLock<Symbol<'static, unsafe extern "C" fn(
    CK_VOID_PTR,
    *mut CK_ULONG,
    CK_ULONG,
    CK_ULONG,
    u64
) -> CK_ULONG>> = OnceLock::new();

fn init_get_xcp_info() -> &'static Symbol<'static, unsafe extern "C" fn(
    CK_VOID_PTR,
    *mut CK_ULONG,
    CK_ULONG,
    CK_ULONG,
    u64
) -> CK_ULONG> {
    M_GET_XCP_INFO.get_or_init(|| {
        let lib = init_lib();
        unsafe { lib.get(b"m_get_xcp_info\0").expect("Cannot load m_get_xcp_info") }
    })
}

static M_ADMIN: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8,
    *mut CK_ULONG,
    *mut u8,
    *mut CK_ULONG,
    *mut u8,
    CK_ULONG,
    *mut u8,
    CK_ULONG,
    u64
) -> CK_ULONG>> = OnceLock::new();

fn init_m_admin() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8,
    *mut CK_ULONG,
    *mut u8,
    *mut CK_ULONG,
    *mut u8,
    CK_ULONG,
    *mut u8,
    CK_ULONG,
    u64
) -> CK_ULONG> {
    M_ADMIN.get_or_init(|| {
        let lib = init_lib();
        unsafe { lib.get(b"m_admin\0").expect("Cannot load m_admin") }
    })
}

static XCPA_CMDBLOCK: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8,
    CK_ULONG,
    CK_ULONG,
    *mut XCPadmresp_T,
    *mut u8,
    *mut u8,
    CK_ULONG
) -> i32>> = OnceLock::new();

fn init_xcpa_cmdblock() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8,
    CK_ULONG,
    CK_ULONG,
    *mut XCPadmresp_T,
    *mut u8,
    *mut u8,
    CK_ULONG
) -> i32> {
    XCPA_CMDBLOCK.get_or_init(|| {
        let lib = init_lib();
        unsafe { lib.get(b"xcpa_cmdblock\0").expect("Cannot load xcpa_cmdblock") }
    })
}

static XCPA_INTERNAL_RV: OnceLock<Symbol<'static, unsafe extern "C" fn(
    *mut u8,
    CK_ULONG,
    *mut XCPadmresp_T,
    *mut CK_ULONG
) -> i32>> = OnceLock::new();

fn init_xcpa_internal_rv() -> &'static Symbol<'static, unsafe extern "C" fn(
    *mut u8,
    CK_ULONG,
    *mut XCPadmresp_T,
    *mut CK_ULONG
) -> i32> {
    XCPA_INTERNAL_RV.get_or_init(|| {
        let lib = init_lib();
        unsafe { lib.get(b"xcpa_internal_rv\0").expect("Cannot load xcpa_internal_rv") }
    })
}

static M_LOGIN_EXTENDED: OnceLock<libloading::Symbol<'static, unsafe extern "C" fn(
    *const u8, u64, *const u8, usize, *const u8, usize, *mut u8, *mut u64, u64
) -> u64>> = OnceLock::new();

fn init_m_login_extended() -> &'static libloading::Symbol<'static, unsafe extern "C" fn(
    *const u8, u64, *const u8, usize, *const u8, usize, *mut u8, *mut u64, u64
) -> u64> {
    M_LOGIN_EXTENDED.get_or_init(|| {
        let lib = init_lib();
        unsafe { lib.get(b"m_LoginExtended\0").expect("Cannot load m_LoginExtended")}
    })
}

static M_LOGOUT_EXTENDED: OnceLock<libloading::Symbol<'static, unsafe extern "C" fn(
    *const u8, u64, *const u8, usize, *const u8, usize,  u64
) -> u64>> = OnceLock::new();

fn init_m_logout_extended() -> &'static libloading::Symbol<'static, unsafe extern "C" fn(
    *const u8, u64, *const u8, usize, *const u8, usize,  u64
) -> u64> {
    M_LOGOUT_EXTENDED.get_or_init(|| {
        let lib = init_lib();
        unsafe { lib.get(b"m_LogoutExtended\0").expect("Cannot load m_LogoutExtended")}
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
pub type CK_ULONG = u64;
pub type CK_VOID_PTR = *mut c_void;
pub const CK_IBM_XCPQ_DOMAIN: u64= 3;
pub const XCP_ADM_REENCRYPT: u64= 25;

pub const CKR_FUNCTION_FAILED: u64 = 0x00000006;
// --- Constants ---
pub const XCP_WK_BYTES: usize = 32;
pub const XCP_SESSION_TCTR_BYTES: usize = 16;
pub const XCP_PINBLOB_V1_BYTES: usize = 56;
pub const EP11_PINBLOB_MARKER_OFS: usize = 4;
pub const EP11_PINBLOB_V1_MARKER: u8 = 0xab;
pub const FNID_LOGINEXTENDED: u32 = 43;
pub const FNID_LOGOUTEXTENDED: u32 = 44;

pub const  XCP_CERTHASH_BYTES: usize = 32;
pub const XCP_LOGIN_IMPR_MAX_SIZE: usize = 3 + (2 + XCP_CERTHASH_BYTES) + 3 + 158 + 2 + XCP_SESSION_TCTR_BYTES;
pub const CK_IBM_XCPQ_LOGIN_IMPORTER:  u64 = 15; 
pub const XCP_LOGIN_ALG_F2021: u64 = 2;

const OID_IBM_MISC_EP11_SESSION_INFO: &[u8] = &[
    0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01,
    0x02, 0x82, 0x0b, 0x87, 0x67, 0x04, 0x01,
];

// --- Nonce structure ---
#[repr(C)]
pub struct Nonce {
    slot_id: u32,
    purpose: [u8; 12],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct CK_IBM_DOMAIN_INFO {
    pub domain: CK_ULONG,
    pub wk: [u8; XCP_KEYCSUM_BYTES],
    pub nextwk: [u8; XCP_KEYCSUM_BYTES],
    pub flags: CK_ULONG,
    pub mode: [u8; 8],
}

#[repr(C)]
#[derive(Debug)]
pub struct XCPadmresp_T {
    pub fn_: u32,          // `fn` is a Rust keyword
    pub domain: u32,
    pub domainInst: u32,

    pub module: [u8; XCP_SERIALNR_CHARS * 2],
    pub modNr: [u8; XCP_SERIALNR_CHARS],
    pub modInst: [u8; XCP_SERIALNR_CHARS],

    pub tctr: [u8; XCP_ADMCTR_BYTES],

    pub rv: CK_ULONG,      // CK_RV
    pub reason: u32,

    pub payload: *const u8,
    pub pllen: CK_ULONG,      // size_t
}

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
pub fn reencipher(target: u64, key: Vec<u8>) -> Result<Vec<u8>, String> {

    // -----------------------------
    // Get domain info
    // -----------------------------
    let mut domain_info: CK_IBM_DOMAIN_INFO = unsafe { std::mem::zeroed() };
    let mut domain_info_len =
        std::mem::size_of::<CK_IBM_DOMAIN_INFO>() as CK_ULONG;

    let rc = unsafe {
        init_get_xcp_info()(
            &mut domain_info as *mut _ as CK_VOID_PTR,
            &mut domain_info_len,
            CK_IBM_XCPQ_DOMAIN,
            0,
            target,
        )
    };

    if rc != CKR_OK {
        return Err(to_error(rc));
    }

    // -----------------------------
    // Prepare admin structures
    // -----------------------------
    let mut rb: XCPadmresp_T = unsafe { std::mem::zeroed() };
    let mut lrb: XCPadmresp_T = unsafe { std::mem::zeroed() };

    rb.domain  = domain_info.domain as u32;
    lrb.domain = domain_info.domain as u32;

    let mut req = vec![0u8; MAX_BLOB_SIZE];
    let mut resp = vec![0u8; MAX_BLOB_SIZE];
    let mut resp_len = resp.len() as CK_ULONG;

    // -----------------------------
    // Build request
    // -----------------------------
    let req_len = unsafe {
        init_xcpa_cmdblock()(
            req.as_mut_ptr(),
            MAX_BLOB_SIZE as CK_ULONG,
            XCP_ADM_REENCRYPT,
            &mut rb,
            std::ptr::null_mut(),
            key.as_ptr() as *mut u8,
            key.len() as CK_ULONG,
        )
    };

    if req_len < 0 {
        return Err(to_error(CKR_FUNCTION_FAILED));
    }

    // -----------------------------
    // Call m_admin
    // -----------------------------
    let mut zero: CK_ULONG = 0;

    let rc = unsafe {
        init_m_admin()(
            resp.as_mut_ptr(),
            &mut resp_len,
            std::ptr::null_mut(),
            &mut zero,
            req.as_mut_ptr(),
            req_len as CK_ULONG,
            std::ptr::null_mut(),
            0,
            target,
        )
    };

    if rc != CKR_OK || resp_len == 0 {
        return Err(to_error(rc));
    }

    // -----------------------------
    // Parse response
    // -----------------------------
    let mut inner_rc: CK_ULONG = CKR_OK;

    let rv = unsafe {
        init_xcpa_internal_rv()(
            resp.as_mut_ptr(),
            resp_len,
            &mut lrb,
            &mut inner_rc,
        )
    };

    if rv < 0 {
        return Err(to_error(CKR_FUNCTION_FAILED));
    }

    if key.len() as CK_ULONG != lrb.pllen {
        return Err(to_error(CKR_FUNCTION_FAILED));
    }

    // -----------------------------
    // Extract new blob
    // -----------------------------
    let new_key = unsafe {
        std::slice::from_raw_parts(
            lrb.payload as *const u8,
            lrb.pllen as usize,
        ).to_vec()
    };

    Ok(new_key)
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

        let mut success_count = 0usize;

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
            } else {
                success_count += 1;
            }
        }

        // Only fail if ALL modules failed ░
        if success_count == 0 {
            return Err("All modules failed to initialize".into());
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



//************************************************************************************************
//************************************************************************************************
fn ber_decode_sequence(input: &[u8]) -> Result<(&[u8], usize), String> {
    if input.len() < 2 {
        return Err("input too short".to_string());
    }

    if input[0] != 0x30 {
        return Err("not a SEQUENCE".to_string());
    }

    let length: usize;
    let header_len: usize;

    if input[1] & 0x80 == 0 {
        // short form
        length = (input[1] & 0x7F) as usize;
        header_len = 2;
    } else {
        // long form
        let length_octets = (input[1] & 0x7F) as usize;
        match length_octets {
            1 => {
                if input.len() < 3 {
                    return Err("input too short for 1-length octet".to_string());
                }
                length = input[2] as usize;
                header_len = 3;
            }
            2 => {
                if input.len() < 4 {
                    return Err("input too short for 2-length octets".to_string());
                }
                length = ((input[2] as usize) << 8) | (input[3] as usize);
                header_len = 4;
            }
            3 => {
                if input.len() < 5 {
                    return Err("input too short for 3-length octets".to_string());
                }
                length = ((input[2] as usize) << 16) | ((input[3] as usize) << 8) | (input[4] as usize);
                header_len = 5;
            }
            _ => return Err("length octets > 3 not supported".to_string()),
        }
    }

    if header_len + length > input.len() {
        return Err("sequence length mismatch".to_string());
    }

    let data = &input[header_len..header_len + length];
    let field_len = header_len + length;

    Ok((data, field_len))
}

fn ber_decode_octet_string(input: &[u8]) -> Result<(&[u8], usize), String> {
    if input.len() < 2 {
        return Err("input too short".to_string());
    }

    if input[0] != 0x04 {
        return Err("not an OCTET STRING".to_string());
    }

    let length: usize;
    let header_len: usize;

    if input[1] & 0x80 == 0 {
        // short form
        length = (input[1] & 0x7F) as usize;
        header_len = 2;
    } else {
        // long form
        let length_octets = (input[1] & 0x7F) as usize;
        match length_octets {
            1 => {
                if input.len() < 3 {
                    return Err("input too short for 1-length octet".to_string());
                }
                length = input[2] as usize;
                header_len = 3;
            }
            2 => {
                if input.len() < 4 {
                    return Err("input too short for 2-length octets".to_string());
                }
                length = ((input[2] as usize) << 8) | (input[3] as usize);
                header_len = 4;
            }
            3 => {
                if input.len() < 5 {
                    return Err("input too short for 3-length octets".to_string());
                }
                length = ((input[2] as usize) << 16)
                    | ((input[3] as usize) << 8)
                    | (input[4] as usize);
                header_len = 5;
            }
            _ => return Err("length octets > 3 not supported".to_string()),
        }
    }

    if header_len + length > input.len() {
        return Err("octet string length mismatch".to_string());
    }

    let data = &input[header_len..header_len + length];
    let field_len = header_len + length;

    Ok((data, field_len))
}

/// Encode a byte slice as a BER OCTET STRING
fn ber_encode_octet_string(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.push(0x04); // tag for OCTET STRING

    // Encode length
    if data.len() < 0x80 {
        out.push(data.len() as u8);
    } else if data.len() < 0x100 {
        out.push(0x81);
        out.push(data.len() as u8);
    } else if data.len() < 0x10000 {
        out.push(0x82);
        out.push(((data.len() >> 8) & 0xFF) as u8);
        out.push((data.len() & 0xFF) as u8);
    } else {
        return Err("Data too long for BER encoding".into());
    }

    out.extend_from_slice(data);
    Ok(out)
}

/// Encode a byte slice as a BER SEQUENCE
fn ber_encode_sequence(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.push(0x30); // tag for SEQUENCE

    // Encode length
    if data.len() < 0x80 {
        out.push(data.len() as u8);
    } else if data.len() < 0x100 {
        out.push(0x81);
        out.push(data.len() as u8);
    } else if data.len() < 0x10000 {
        out.push(0x82);
        out.push(((data.len() >> 8) & 0xFF) as u8);
        out.push((data.len() & 0xFF) as u8);
    } else {
        return Err("Data too long for BER encoding".into());
    }

    out.extend_from_slice(data);
    Ok(out)
}


fn create_login_recipient(
    ski: &[u8; XCP_CERTHASH_BYTES],
    ec_privkey: &PKey<Private>,
) -> Result<Vec<u8>, String> {
    // 1. Serialize SPKI (public key info) in DER format
    let spki = ec_privkey
        .public_key_to_der()
        .map_err(|e| format!("Failed to serialize SPKI: {:?}", e))?;

    // 2. Version = 1 (v1)
    let version = 1u32.to_be_bytes();

    // 3. Encode each component as OCTET STRING
    let v1_os = ber_encode_octet_string(&version)?;
    let ski_os = ber_encode_octet_string(ski)?;
    let spki_os = ber_encode_octet_string(&spki)?;

    // 4. Concatenate all OCTET STRINGs
    let mut data = Vec::new();
    data.extend_from_slice(&v1_os);
    data.extend_from_slice(&ski_os);
    data.extend_from_slice(&spki_os);

    // 5. Wrap in SEQUENCE
    let recipient = ber_encode_sequence(&data)?;

    Ok(recipient)
}


fn create_login_extended_info(
    ski: &[u8; XCP_CERTHASH_BYTES],
    ec_privkey: &PKey<Private>,
) -> Result<Vec<u8>, String> {
    
    // Encode algorithm (big-endian u32)
    // 1. Create a 4-byte array
    let mut alg_bytes = [0u8; 4];

    // 2. Encode algorithm as big-endian u32
    let alg_value: u32 =  XCP_LOGIN_ALG_F2021 as u32; // replace with your enum/constant
    BigEndian::write_u32(&mut alg_bytes, alg_value);

    // Encode parent session ID (all zeros if none)
    let parent_id = [0u8; XCP_WK_BYTES];
    let parent_os = ber_encode_octet_string(&parent_id)?;

    // 1. Create recipient info
    let recipient = create_login_recipient(ski, ec_privkey)?;

    // 4. Optional fields: attributes and context (empty)
    let attr_bytes = &[];
    let ctx_bytes = &[];

    // 5. Encode all fields as OCTET STRINGs
    let vers_os = ber_encode_octet_string(&OID_IBM_MISC_EP11_SESSION_INFO)?;
    let alg_os = ber_encode_octet_string(&alg_bytes)?;
    let recipient_os = ber_encode_octet_string(&recipient)?;
    let attr_os = ber_encode_octet_string(attr_bytes)?;
    let ctx_os = ber_encode_octet_string(ctx_bytes)?;

    // 6. Concatenate all
    let mut data = Vec::new();
    data.extend_from_slice(&vers_os);
    data.extend_from_slice(&alg_os);
    data.extend_from_slice(&parent_os);
    data.extend_from_slice(&recipient_os);
    data.extend_from_slice(&attr_os);
    data.extend_from_slice(&ctx_os);

    // 7. Wrap in SEQUENCE
    let extended_info = ber_encode_sequence(&data)?;

    Ok(extended_info)
}


fn get_login_importer_key(
    target: u64,
) -> Result<([u8; 32], [u8; XCP_ADMCTR_BYTES], PKey<openssl::pkey::Public>), String> {

    let mut res = vec![0u8; XCP_LOGIN_IMPR_MAX_SIZE];
    let mut res_len : u64 = res.len() as CK_ULONG;

    let rc = unsafe {
        init_get_xcp_info()(
            res.as_mut_ptr() as *mut std::ffi::c_void,
            &mut res_len,
            CK_IBM_XCPQ_LOGIN_IMPORTER,
            XCP_LOGIN_ALG_F2021,
            target
        )
    };

    if rc != CKR_OK {
        return Err(format!("m_get_xcp_info failed: 0x{:x}", rc));
    }
    let res = &res[..res_len as usize];

    /*
     * xcpRsp ::= SEQUENCE
     *   SKI OCTET STRING
     *   SPKI OCTET STRING
     *   tcounter OCTET STRING
     */

    // ---- SEQUENCE ----
    let (mut data, _) =
        ber_decode_sequence(res).map_err(|e| format!("ber_decode_sequence: {}", e))?;

    // ---- SKI ----
    let (ski_bytes, field_len) =
        ber_decode_octet_string(data).map_err(|e| format!("SKI decode: {}", e))?;

    if ski_bytes.len() != XCP_CERTHASH_BYTES {
        return Err(format!(
            "SKI length mismatch {} != {}",
            ski_bytes.len(),
            XCP_CERTHASH_BYTES
        ));
    }

    let ski: [u8; XCP_CERTHASH_BYTES] = ski_bytes
        .try_into()
        .map_err(|_| format!("SKI length mismatch {}", ski_bytes.len()))?;

    data = &data[field_len..];

    // ---- SPKI ----
    let (spki_bytes, field_len) =
        ber_decode_octet_string(data).map_err(|e| format!("SPKI decode: {}", e))?;

    data = &data[field_len..];

    // ---- TCOUNTER ----
    let (cnt_bytes, _) =
        ber_decode_octet_string(data).map_err(|e| format!("COUNTER decode: {}", e))?;

    if cnt_bytes.len() > XCP_ADMCTR_BYTES {
        return Err("tcounter too large".into());
    }

    // left-pad like C memset + memcpy
    let mut tcounter = [0u8; XCP_ADMCTR_BYTES];
    let offset = XCP_ADMCTR_BYTES - cnt_bytes.len();
    tcounter[offset..].copy_from_slice(cnt_bytes);


    // ----- Parse SPKI into EVP_PKEY -----
    let ec_pubkey = PKey::public_key_from_der(spki_bytes)
        .map_err(|e: ErrorStack| format!("d2i_PUBKEY failed: {:?}", e))?;

    Ok((ski, tcounter, ec_pubkey))
}



// --- Increment TCounter (big-endian) ---
fn increment_tcounter(tcounter: &mut [u8]) {
    for i in (0..tcounter.len()).rev() {
        tcounter[i] = tcounter[i].wrapping_add(1);
        if tcounter[i] != 0 { break; }
    }
}

// --- SHA-256 based PIN blob key derivation ---
fn derive_pinblob_key(pinblob: &[u8], pin: &[u8]) -> Result<Vec<u8>, String> {
    if pinblob.len() != 48 { return Err("pinblob length invalid".into()); }
    let mut hasher = Sha256::new();
    hasher.update(&1u32.to_be_bytes());
    hasher.update(&3u32.to_be_bytes());
    hasher.update(pin);
    hasher.update(&[0u8]);
    hasher.update(&pinblob[XCP_WK_BYTES..XCP_WK_BYTES+16]);
    Ok(hasher.finalize().to_vec())
}

/// Create padded PIN in BER format
fn create_padded_pin(pin: &[u8], tcounter: &[u8], func_id: u32) -> Result<Vec<u8>, String> {
    // 1. Encode each field as OCTET STRING
    let version_os = ber_encode_octet_string(&1u32.to_be_bytes())?;
    let func_id_os = ber_encode_octet_string(&func_id.to_be_bytes())?;
    let tcounter_os = ber_encode_octet_string(tcounter)?;
    let pin_os = ber_encode_octet_string(pin)?;

    // 2. Concatenate all fields
    let mut data = Vec::new();
    data.extend_from_slice(&version_os);
    data.extend_from_slice(&func_id_os);
    data.extend_from_slice(&tcounter_os);
    data.extend_from_slice(&pin_os);

    // 3. Wrap concatenated data in a SEQUENCE
    let seq = ber_encode_sequence(&data)?;

    Ok(seq)
}


// Derive ECDH shared secret
pub fn ecdh_derive(
    privkey: &PKey<Private>,
    pubkey: &PKey<Public>,
) -> Result<Vec<u8>, String> {
    // Create a deriver
    let mut deriver = Deriver::new(privkey)
        .map_err(|e| format!("Deriver::new failed: {:?}", e))?;

    // Set peer public key
    deriver
        .set_peer(pubkey)
        .map_err(|e| format!("set_peer failed: {:?}", e))?;

    // Derive shared secret
    let secret = deriver
        .derive_to_vec()
        .map_err(|e| format!("derive_to_vec failed: {:?}", e))?;

    Ok(secret)
}

/// AES 256-bit key size
const AES_KEY_SIZE_256: usize = 32;

fn ec_x_from_pkey(privkey: &PKey<Private>) -> Result<Vec<u8>, String> {
    unsafe {
        // 1. Trait-less extraction of the internal EVP_PKEY pointer
        let pkey_ptr = *(privkey as *const _ as *const *mut EVP_PKEY);

        // 2. Get the EC_KEY handle
        let ec_key = EVP_PKEY_get1_EC_KEY(pkey_ptr);
        if ec_key.is_null() {
            return Err("Not an EC key".into());
        }

        let group = EC_KEY_get0_group(ec_key);
        let pub_point = EC_KEY_get0_public_key(ec_key);
        let degree = EC_GROUP_get_degree(group);
        let prime_len = (degree + 7) / 8;

        // 3. Extract the X coordinate as a BIGNUM
        let bn_x = BN_new();
        if bn_x.is_null() {
            EC_KEY_free(ec_key);
            return Err("BN_new failed".into());
        }

        // We pass null for Y since we only need X
        if EC_POINT_get_affine_coordinates_GFp(group, pub_point, bn_x, std::ptr::null_mut(), std::ptr::null_mut()) != 1 {
            BN_free(bn_x);
            EC_KEY_free(ec_key);
            return Err("Failed to get affine coordinates".into());
        }

        // 4. Convert BIGNUM to padded byte vector
        let mut x_coord = vec![0u8; prime_len as usize];
        if BN_bn2binpad(bn_x, x_coord.as_mut_ptr(), prime_len as i32) != prime_len as i32 {
            BN_free(bn_x);
            EC_KEY_free(ec_key);
            return Err("BN_bn2binpad failed".into());
        }

        // 5. Cleanup
        BN_free(bn_x);
        EC_KEY_free(ec_key);

        Ok(x_coord)
    }
}


/// SP800-56C KDF SHA-256
pub fn kdf_sp800_56c_sha256(
    ec_privkey: &PKey<openssl::pkey::Private>,
    secret: &[u8],
) -> Result<[u8; AES_KEY_SIZE_256], String> {
    let x_bytes = ec_x_from_pkey(ec_privkey)?;

    let mut hasher = Sha256::new();

    // Big-endian 32-bit value 1
    let be32_1 = 1u32.to_be_bytes();

    // SHA256( BE32(1) || BE32(1) || secret || x_bytes )
    hasher.update(&be32_1);
    hasher.update(&be32_1);
    hasher.update(secret);
    hasher.update(&x_bytes);

    let hash = hasher.finalize();


    if hash.len() != AES_KEY_SIZE_256 {
        return Err(format!("Unexpected SHA256 output length: {}", hash.len()));
    }

    let mut key = [0u8; AES_KEY_SIZE_256];
    key.copy_from_slice(&hash);
    Ok(key)
}

// Generate an EC P-521 session key
fn generate_ec_session_key_p521() -> Result<PKey<openssl::pkey::Private>, String> {
    // Create EC group for P-521
    let group = EcGroup::from_curve_name(Nid::SECP521R1)
        .map_err(|e| format!("Failed to create EC group: {:?}", e))?;

    // Generate EC private key
    let ec_key = EcKey::generate(&group)
        .map_err(|e| format!("Failed to generate EC key: {:?}", e))?;

    // Wrap EC key in PKey<Private>
    let pkey = PKey::from_ec_key(ec_key)
        .map_err(|e| format!("Failed to wrap EC key: {:?}", e))?;

    Ok(pkey)
}


/// Rust port of your Go aes256KWPEncrypt (RFC5649)
pub fn aes_256_kwp_encrypt2( plaintext: &[u8],key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("AES-256 key must be 32 bytes".into());
    }

    let cipher = Aes256::new(GenericArray::from_slice(key));

    let n = plaintext.len();

    // RFC5649 zero padding to multiple of 8
    let mut pad_len = 8 - (n % 8);
    if pad_len == 8 {
        pad_len = 0;
    }

    let mut padded = vec![0u8; n + pad_len];
    padded[..n].copy_from_slice(plaintext);

    // AIV = A65959A6 + 32-bit big endian length
    let mut a = vec![0xA6, 0x59, 0x59, 0xA6, 0, 0, 0, n as u8];

    let rcount = padded.len() / 8;

    let mut r: Vec<[u8; 8]> = padded
        .chunks_exact(8)
        .map(|c| {
            let mut b = [0u8; 8];
            b.copy_from_slice(c);
            b
        })
        .collect();

    // 6 * n rounds
    for j in 0..6 {
        for i in 0..rcount {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&a);
            b[8..].copy_from_slice(&r[i]);

            cipher.encrypt_block(GenericArray::from_mut_slice(&mut b));

            let t = (rcount * j + i + 1) as u64;

            for k in 0..8 {
                a[k] = b[k] ^ ((t >> (56 - 8 * k)) as u8);
            }

            r[i].copy_from_slice(&b[8..]);
        }
    }

    // Output A || R[0] || R[1]...
    let mut out = Vec::with_capacity(8 + rcount * 8);
    out.extend_from_slice(&a);

    for block in r {
        out.extend_from_slice(&block);
    }

    Ok(out)
}

/// AES-256 Key Wrap with Padding (RFC 5649) using OpenSSL FFI
pub fn aes_256_kwp_encrypt(plaintext: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    if key.len() != 32 {
        return Err("AES key must be 32 bytes".into());
    }

    unsafe {
        let ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err("EVP_CIPHER_CTX_new failed".into());
        }

        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

        let cipher = EVP_aes_256_wrap_pad();
        if cipher.is_null() {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_aes_256_wrap_pad not available".into());
        }

        if EVP_EncryptInit_ex(ctx, cipher, std::ptr::null_mut(), key.as_ptr(), std::ptr::null()) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_EncryptInit_ex failed".into());
        }

        fn encrypt_len(n: usize) -> usize {
            let mut l = n;
            if n % 8 != 0 {
                l += 8 - (n % 8);
            }
            l + 8
        }

        let total_len = encrypt_len(plaintext.len());
        let mut out = vec![0u8; total_len];

        let mut outlen: c_int = total_len as c_int;

        if EVP_EncryptUpdate(
            ctx,
            out.as_mut_ptr(),
            &mut outlen,
            plaintext.as_ptr(),
            plaintext.len() as c_int,
        ) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_EncryptUpdate failed".into());
        }

        let mut outlen2: c_int = (total_len as c_int) - outlen;

        if EVP_EncryptFinal_ex(
            ctx,
            out.as_mut_ptr().add(outlen as usize),
            &mut outlen2,
        ) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_EncryptFinal_ex failed".into());
        }

        let final_len = (outlen + outlen2) as usize;
        out.truncate(final_len);

        EVP_CIPHER_CTX_free(ctx);
        Ok(out)
    }
}

pub fn aes_256_kwp_decrypt( ciphertext: &[u8],key: &[u8; 32]) -> Result<Vec<u8>, String> {
    unsafe {
        let  ctx = EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err("EVP_CIPHER_CTX_new failed".into());
        }

        let cipher = EVP_aes_256_wrap_pad();
        if cipher.is_null() {
            return Err("EVP_aes_256_wrap_pad not available in OpenSSL".into());
        }

        if EVP_DecryptInit_ex(ctx, cipher, ptr::null_mut(), key.as_ptr(), ptr::null()) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_DecryptInit_ex failed".into());
        }

        let mut out = vec![0u8; ciphertext.len()];
        let mut outlen: c_int = 0;

        if EVP_DecryptUpdate(
            ctx,
            out.as_mut_ptr(),
            &mut outlen,
            ciphertext.as_ptr(),
            ciphertext.len() as c_int,
        ) != 1
        {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_DecryptUpdate failed".into());
        }

        let mut outlen2: c_int = 0;
        if EVP_DecryptFinal_ex(ctx, out.as_mut_ptr().add(outlen as usize), &mut outlen2) != 1 {
            EVP_CIPHER_CTX_free(ctx);
            return Err("EVP_DecryptFinal_ex failed".into());
        }

        outlen += outlen2;
        out.truncate(outlen as usize);

        EVP_CIPHER_CTX_free(ctx);
        Ok(out)
    }
}


// --- Main doLoginExtended equivalent ---
fn do_login_extended(target: u64, pin: &[u8], fnid: u32) -> Result<Vec<u8>, String> {
        let mut nonce = Nonce { slot_id: 4, purpose: [0u8; 12] };
        nonce.purpose[..12].copy_from_slice(b"FIPS-session");
        let nonce_ptr = &nonce as *const Nonce as *const u8;
        let nonce_len = std::mem::size_of::<Nonce>();

        let local_priv = generate_ec_session_key_p521()?;

        let (peer_ski, mut tcounter, peer_pub) = get_login_importer_key(target)
            .map_err(|e| format!("Failed to get login importer key: {}", e))?;

      // 3. ECDH shared secret derivation
        let shared_secret = ecdh_derive(&local_priv, &peer_pub)?;
        // 4. KDF SP800-56c → AES-256 key
        let shared_key: [u8; 32]= kdf_sp800_56c_sha256(&local_priv, &shared_secret)?
                    .try_into()
                    .map_err(|_| "KDF output is not 32 bytes")?;

      // 5. Optional: create extended info
        let extended_info = create_login_extended_info(&peer_ski, &local_priv)?;

        // 6. Increment TCounter
        increment_tcounter(&mut tcounter);

        // 7. Create padded PIN
        let padded_pin = create_padded_pin(pin, &tcounter,fnid )?;

        // 8. AES-KWP encrypt padded PIN
        let enc_padded_pin = aes_256_kwp_encrypt(&padded_pin, &shared_key)?;

        // 9. Call HSM function (stub here, replace with actual m_LoginExtended)
        let mut enc_pinblob = vec![0u8; XCP_PINBLOB_V1_BYTES]; // allocate output buffer
        let mut enc_pinblob_len = enc_pinblob.len() as u64;

match fnid {
    FNID_LOGINEXTENDED => {
        let rc = unsafe {
            init_m_login_extended()(
                enc_padded_pin.as_ptr(),
                enc_padded_pin.len().try_into().unwrap(),
                nonce_ptr,
                nonce_len,
                extended_info.as_ptr(),
                extended_info.len(),
                enc_pinblob.as_mut_ptr(),
                &mut enc_pinblob_len as *mut u64,
                target,
            )
        };
    
        if rc != CKR_OK {
            return Err(format!("HSM LoginExtended failed: 0x{:X}", rc));
        }

     }
    FNID_LOGOUTEXTENDED => {
        let rc = unsafe {
            init_m_logout_extended()(
                enc_padded_pin.as_ptr(),
                enc_padded_pin.len().try_into().unwrap(),
                nonce_ptr,
                nonce_len,
                extended_info.as_ptr(),
                extended_info.len(),
                target,
            )
        };
    
        if rc != CKR_OK {
            return Err(format!("HSM LoginExtended failed: 0x{:X}", rc));
        }
        return Ok(vec![])
     }
     _ => {
        return Err(format!("Unsupported FNID: {}", fnid));
    }
}

        enc_pinblob.truncate(enc_pinblob_len as usize);

        let clear_pinblob = aes_256_kwp_decrypt(&enc_pinblob, &shared_key).map_err(|e| format!("Failed to decrypt pin blob: {}", e))?;
  
        // 10. Derive PIN blob key
        let pinblob_key = derive_pinblob_key(&clear_pinblob, pin)?;

        // 11. Encrypt pinblob (wrap first 32 bytes)
        let enc_pinblob = aes_256_kwp_encrypt(&clear_pinblob, &pinblob_key)?;

    Ok(enc_pinblob)
}

// --- EP11Login wrapper ---
pub fn ep11_login(target: u64, pin: &[u8]) -> Result<Vec<u8>, String> {
    do_login_extended(target, pin, FNID_LOGINEXTENDED)
}

// Perform an EP11 logout using the extended login function
pub fn ep11_logout(pin: &[u8], target: u64) -> Result<(), String> {
    // Call do_login_extended with the logout function ID
    do_login_extended(target, pin, FNID_LOGOUTEXTENDED).map(|_| ())
}
