use async_trait::async_trait;
use atrium_oauth_client::store::state::{InternalStateData, StateStore};
use atrium_oauth_client::store::SimpleStore;
use serde::Serialize;
use serde_wasm_bindgen::Serializer;
use thiserror::Error;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[wasm_bindgen(typescript_custom_section)]
const STORE: &'static str = r#"
interface Store {
  get(key: string): Promise<unknown | null>;
  set(key: string, value: unknown): Promise<void>;
  del(key: string): Promise<void>;
}
"#;

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "Store")]
    pub type Store;

    #[wasm_bindgen(method, catch)]
    pub async fn get(this: &Store, key: String) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(method, catch)]
    pub async fn set(this: &Store, key: String, value: JsValue) -> Result<(), JsValue>;
    #[wasm_bindgen(method, catch)]
    pub async fn del(this: &Store, key: String) -> Result<(), JsValue>;
}

#[derive(Error, Debug)]
pub enum WasmStateStoreError {
    #[error("js error: {0:?}")]
    Js(Option<String>),
}

pub struct WasmStateStore {
    store: Store,
}

impl WasmStateStore {
    pub fn new(store: Store) -> Self {
        Self { store }
    }
}

#[async_trait(?Send)]
impl SimpleStore<String, InternalStateData> for WasmStateStore {
    type Error = WasmStateStoreError;

    async fn get(&self, key: &String) -> Result<Option<InternalStateData>, Self::Error> {
        let result = self
            .store
            .get(key.clone())
            .await
            .map_err(|e| WasmStateStoreError::Js(e.as_string()))?;
        serde_wasm_bindgen::from_value::<Option<InternalStateData>>(result)
            .map_err(|e| WasmStateStoreError::Js(Some(e.to_string())))
    }
    async fn set(&self, key: String, value: InternalStateData) -> Result<(), Self::Error> {
        self.store
            .set(
                key.clone(),
                value
                    .serialize(&Serializer::json_compatible())
                    .map_err(|e| WasmStateStoreError::Js(Some(e.to_string())))?,
            )
            .await
            .map_err(|e| WasmStateStoreError::Js(e.as_string()))?;
        Ok(())
    }
    async fn del(&self, key: &String) -> Result<(), Self::Error> {
        self.store
            .del(key.clone())
            .await
            .map_err(|e| WasmStateStoreError::Js(e.as_string()))?;
        Ok(())
    }
    async fn clear(&self) -> Result<(), Self::Error> {
        unimplemented!()
    }
}

impl StateStore for WasmStateStore {}
