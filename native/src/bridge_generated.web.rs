use super::*;
// Section: wire functions

#[wasm_bindgen]
pub fn wire_platform(port_: MessagePort) {
    wire_platform_impl(port_)
}

#[wasm_bindgen]
pub fn wire_rust_release_mode(port_: MessagePort) {
    wire_rust_release_mode_impl(port_)
}

#[wasm_bindgen]
pub fn wire_create_stream(port_: MessagePort, key: Box<[u8]>, iv: Box<[u8]>, chunk_size: u32) {
    wire_create_stream_impl(port_, key, iv, chunk_size)
}

#[wasm_bindgen]
pub fn wire_process_data(port_: MessagePort, data: Box<[u8]>) {
    wire_process_data_impl(port_, data)
}

#[wasm_bindgen]
pub fn wire_process_data_loop(port_: MessagePort, times: u32) {
    wire_process_data_loop_impl(port_, times)
}

// Section: allocate functions

// Section: related functions

// Section: impl Wire2Api

impl Wire2Api<Vec<u8>> for Box<[u8]> {
    fn wire2api(self) -> Vec<u8> {
        self.into_vec()
    }
}
// Section: impl Wire2Api for JsValue

impl Wire2Api<u32> for JsValue {
    fn wire2api(self) -> u32 {
        self.unchecked_into_f64() as _
    }
}
impl Wire2Api<u8> for JsValue {
    fn wire2api(self) -> u8 {
        self.unchecked_into_f64() as _
    }
}
impl Wire2Api<Vec<u8>> for JsValue {
    fn wire2api(self) -> Vec<u8> {
        self.unchecked_into::<js_sys::Uint8Array>().to_vec().into()
    }
}
