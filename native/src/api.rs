// This is the entry point of your Rust library.
// When adding new code to your project, note that only items used
// here will be transformed to their Dart equivalents.

use flutter_rust_bridge::{StreamSink};
// use flutter_rust_bridge::support::lazy_static;

// use aes_gcm::{
//     aead::{stream::{self, Encryptor, EncryptorBE32, NonceSize, Nonce, StreamBE32}, generic_array::{GenericArray, ArrayLength}, consts::{U120, U2, U32, U256, U7, U160, B1, B0}},
//     Aes256Gcm, KeyInit, AesGcm, aes::{cipher::typenum::{UInt, UTerm}, Aes256}
// };

use chacha20poly1305::{
    aead::{stream::{EncryptorBE32}, Aead},
    XChaCha20Poly1305, KeyInit,
};

// A plain enum without any fields. This is similar to Dart- or C-style enums.
// flutter_rust_bridge is capable of generating code for enums with fields
// (@freezed classes in Dart and tagged unions in C).
pub enum Platform {
    Unknown,
    Android,
    Ios,
    Windows,
    Unix,
    MacIntel,
    MacApple,
    Wasm,
}

// A function definition in Rust. Similar to Dart, the return type must always be named
// and is never inferred.
pub fn platform() -> Platform {
    // This is a macro, a special expression that expands into code. In Rust, all macros
    // end with an exclamation mark and can be invoked with all kinds of brackets (parentheses,
    // brackets and curly braces). However, certain conventions exist, for example the
    // vector macro is almost always invoked as vec![..].
    //
    // The cfg!() macro returns a boolean value based on the current compiler configuration.
    // When attached to expressions (#[cfg(..)] form), they show or hide the expression at compile time.
    // Here, however, they evaluate to runtime values, which may or may not be optimized out
    // by the compiler. A variety of configurations are demonstrated here which cover most of
    // the modern oeprating systems. Try running the Flutter application on different machines
    // and see if it matches your expected OS.
    //
    // Furthermore, in Rust, the last expression in a function is the return value and does
    // not have the trailing semicolon. This entire if-else chain forms a single expression.
    if cfg!(windows) {
        Platform::Windows
    } else if cfg!(target_os = "android") {
        Platform::Android
    } else if cfg!(target_os = "ios") {
        Platform::Ios
    } else if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
        Platform::MacApple
    } else if cfg!(target_os = "macos") {
        Platform::MacIntel
    } else if cfg!(target_family = "wasm") {
        Platform::Wasm
    } else if cfg!(unix) {
        Platform::Unix
    } else {
        Platform::Unknown
    }
}

// The convention for Rust identifiers is the snake_case,
// and they are automatically converted to camelCase on the Dart side.
pub fn rust_release_mode() -> bool {
    cfg!(not(debug_assertions))
}

struct EncryptionState {
    // key: Vec<u8>,
    // iv: Vec<u8>,
    chunk_size: u32,
    // buffer: Vec<u8>,
    // aead: AesGcm<Aes256Gcm, U12>,
    stream_encryptor: EncryptorBE32<XChaCha20Poly1305>,
    sink_stream: StreamSink<Vec<u8>>,
}

static mut ENCRYPTION_STATE : Option<EncryptionState> = None;

const KEY_LENGTH: usize = 32;
const IV_LENGTH: usize = 19; // 5 bytes are taken by the counter

pub fn create_stream(key: Vec<u8>, iv: Vec<u8>, chunk_size: u32, sink_stream: StreamSink<Vec<u8>>) -> () {
    let key_slice: &[u8; KEY_LENGTH] = key[0..KEY_LENGTH].try_into().unwrap();
    let iv_slice: &[u8; IV_LENGTH] = iv[0..IV_LENGTH].try_into().unwrap();
    
    let aead = XChaCha20Poly1305::new(key_slice.into());
    // let nonce = GenericArray::from_slice(iv_slice);
    let stream_encryptor = EncryptorBE32::from_aead(aead, iv_slice.try_into().unwrap());

    unsafe {
        ENCRYPTION_STATE = Some(EncryptionState {
            // key,
            // iv,
            chunk_size,
            // buffer: vec![0; chunk_size as usize],
            // aead,
            stream_encryptor,
            sink_stream,
        });
    }

    ()
}

pub fn process_data(data: Vec<u8>) -> () {
    let data_len = data.len() as u32;

    unsafe {
        match &mut ENCRYPTION_STATE {
            Some(es) => {
                if data_len == 0 {
                    es.sink_stream.close();
                } else if data_len == es.chunk_size {
                    let encrypted_buffer = es.stream_encryptor
                        .encrypt_next(data.as_slice()).unwrap();
                    es.sink_stream.add(encrypted_buffer);
                } else {
                    // let encrypted_buffer = es.stream_encryptor
                    //     .encrypt_last(es.buffer.as_slice())
                    //     .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;
                    // es.sink_stream.add(encrypted_buffer);
                }
            }
            None => {
                panic!("Stream not initialized");
            }
        }
    }

    ()
}

pub fn process_data_loop(times: u32) -> () {
    unsafe {
        match &mut ENCRYPTION_STATE {
            Some(es) => {
                let data = vec![0; es.chunk_size as usize];
                let data_slice = data.as_slice();
                for _ in 0..times {
                    let encrypted_buffer = es.stream_encryptor
                        .encrypt_next(data_slice).unwrap();
                    es.sink_stream.add(encrypted_buffer);
                }
            }
            None => {
                panic!("Stream not initialized");
            }
        }
    }

    ()
}


#[cfg(test)]
mod tests {
    use super::*;
    use flutter_rust_bridge::{rust2dart::Rust2Dart};

    #[test]
    fn test_create_process() {
        unsafe { assert!(ENCRYPTION_STATE.is_none()); }
        
        let x_res = create_stream(vec![0; KEY_LENGTH], vec![0; IV_LENGTH], 1024 * 1024, StreamSink::new(Rust2Dart::new(12)));
        unsafe { assert!(ENCRYPTION_STATE.is_some()); }
        assert_eq!(x_res, ());

        let y_res = process_data(vec![1,2,3]);
        assert_eq!(y_res, ());
    }
}
