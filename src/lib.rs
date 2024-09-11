mod store;

use self::store::{Store, WasmStateStore};
use atrium_oauth_client::identity::handle::{
    DohDnsTxtResolver, DohDnsTxtResolverConfig, HandleResolverImpl,
};
use atrium_oauth_client::identity::HandleResolverConfig;
use atrium_oauth_client::{
    AtprotoClientMetadata, DefaultHttpClient, OAuthClient, OAuthClientConfig, OAuthResolverConfig,
};
use elliptic_curve::pkcs8::DecodePrivateKey;
use elliptic_curve::SecretKey;
use jose_jwk::{Class, Jwk, Key, Parameters};
use serde::{Deserialize, Serialize};
use serde_wasm_bindgen::Serializer;
use std::sync::Arc;
use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

#[derive(Serialize, Deserialize)]
struct WasmOAuthClientConfig {
    metadata: AtprotoClientMetadata,
    keys: Option<Vec<String>>,
    doh_service_url: String,
}

#[wasm_bindgen]
pub struct WasmOAuthClient {
    inner: OAuthClient<WasmStateStore>,
}

#[wasm_bindgen]
impl WasmOAuthClient {
    #[wasm_bindgen(constructor)]
    pub fn new(config_obj: JsValue, store: Store) -> Result<WasmOAuthClient, JsValue> {
        let config = serde_wasm_bindgen::from_value::<WasmOAuthClientConfig>(config_obj)?;
        let keys = if let Some(keys) = config.keys {
            let mut jwks = Vec::with_capacity(keys.len());
            for (i, s) in keys.into_iter().enumerate() {
                let Ok(secret_key) = SecretKey::<p256::NistP256>::from_pkcs8_pem(&s) else {
                    return Err(JsValue::from_str("failed to parse secret key"));
                };
                jwks.push(Jwk {
                    key: Key::from(&secret_key.into()),
                    prm: Parameters {
                        kid: Some(format!("key-{i:02}")),
                        cls: Some(Class::Signing),
                        ..Default::default()
                    },
                });
            }
            Some(jwks)
        } else {
            None
        };
        let client = OAuthClient::new(OAuthClientConfig {
            client_metadata: config.metadata,
            keys,
            resolver: OAuthResolverConfig {
                did: Default::default(),
                handle: HandleResolverConfig {
                    r#impl: HandleResolverImpl::Atproto(Arc::new(
                        DohDnsTxtResolver::new(DohDnsTxtResolverConfig {
                            service_url: config.doh_service_url,
                            http_client: Arc::new(DefaultHttpClient::default()),
                        })
                        .map_err(|e| JsValue::from_str(&e.to_string()))?,
                    )),
                },
            },
            state_store: WasmStateStore::new(store),
        })
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(Self { inner: client })
    }
    pub fn client_metadata(&self) -> Result<JsValue, JsValue> {
        Self::to_json(&self.inner.client_metadata)
    }
    pub fn jwks(&self) -> Result<JsValue, JsValue> {
        Self::to_json(&self.inner.jwks())
    }
    pub async fn authorize(&self, input: String) -> Result<String, JsValue> {
        self.inner
            .authorize(input, Default::default())
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))
    }
    pub async fn callback(&self, params: JsValue) -> Result<JsValue, JsValue> {
        Self::to_json(
            &self
                .inner
                .callback(serde_wasm_bindgen::from_value(params)?)
                .await
                .map_err(|e| JsValue::from_str(&e.to_string()))?,
        )
    }
    fn to_json<T>(value: &T) -> Result<JsValue, JsValue>
    where
        T: Serialize + ?Sized,
    {
        Ok(value.serialize(&Serializer::json_compatible())?)
    }
}
