// This is the entry point of your Rust library.
// When adding new code to your project, note that only items used
// here will be transformed to their Dart equivalents.

use flutter_rust_bridge::StreamSink;

use aes_gcm::{
    aead::stream::{self, Encryptor, EncryptorBE32, NonceSize, Nonce},
    Aes256Gcm, KeyInit, AesGcm
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
    buffer: Vec<u8>,
    // aead: AesGcm<Aes256Gcm, U12>,
    encryption_stream: EncryptorBE32<Aes256Gcm>,
    sink_stream: StreamSink<Vec<u8>>,
}

static mut ENCRYPTION_STATE : Option<EncryptionState> = None;

pub fn create_stream(key: Vec<u8>, iv: Vec<u8>, chunk_size: u32, sink_stream: StreamSink<Vec<u8>>) -> anyhow::Result<()> {
    let aead = Aes256Gcm::new_from_slice(&key).unwrap();
    
    let iv_slice = iv.as_slice();
    let encryption_stream = stream::EncryptorBE32::from_aead(aead, iv_slice.into());

    unsafe {
        ENCRYPTION_STATE = Some(EncryptionState {
            // key,
            // iv,
            chunk_size,
            buffer: vec![0; 8],
            // aead,
            encryption_stream,
            sink_stream,
        });
    }

    Ok(())
}

pub fn process_data(data: Vec<u8>) -> anyhow::Result<()> {
    unsafe {
        match ENCRYPTION_STATE.as_mut() {
            Some(es) => {
                if data.len() as u32 == es.chunk_size {
                    let encrypted_buffer = es.encryption_stream
                        .encrypt_next(es.buffer.as_slice())
                        .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;
                    es.sink_stream.add(encrypted_buffer);
                } else {
                    // let encrypted_buffer = es.encryption_stream
                    //     .encrypt_last(es.buffer.as_slice())
                    //     .map_err(|err| anyhow::anyhow!("Encrypting large file: {}", err))?;
                    // es.sink_stream.add(encrypted_buffer);
                    es.sink_stream.close();
                }
                Ok(())
            }
            None => {
                Err(anyhow::anyhow!("Stream not initialized"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flutter_rust_bridge::{rust2dart::Rust2Dart};

    #[test]
    fn test_create_process() {
        unsafe { assert!(ENCRYPTION_STATE.is_none()); }
        
        let x_res = create_stream(vec![0; 32], vec![0; 7], 1024, StreamSink::new(Rust2Dart::new(12)));
        unsafe { assert!(ENCRYPTION_STATE.is_some()); }
        assert!(x_res.is_ok());

        let y_res = process_data(vec![1,2,3]);
        assert!(y_res.is_ok());
    }
}
