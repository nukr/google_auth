use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::fs::OpenOptions;
use tokio::prelude::*;

#[derive(Deserialize, Serialize, Debug)]
pub struct DefaultCredentials {
    path: PathBuf,
    json: Option<Vec<u8>>,
    token: Option<Token>,
}

impl DefaultCredentials {
    pub fn new() -> Result<Self> {
        if let Ok(gadc) = std::env::var("GOOGLE_APPLICATION_DEFAULT_CREDENTIAL") {
            let path = PathBuf::from(gadc);
            return Ok(DefaultCredentials {
                path,
                json: None,
                token: None,
            });
        }
        let home_path = std::env::var("HOME")?;
        let config_path = ".config/gcloud/application_default_credentials.json";
        let path = std::path::Path::new(&home_path).join(&config_path);
        Ok(DefaultCredentials {
            path,
            json: None,
            token: None,
        })
    }
    pub async fn token(&mut self) -> Result<&Option<Token>> {
        let mut file = match OpenOptions::new().read(true).open(&self.path).await {
            Ok(file) => file,
            Err(err) => return Err(anyhow!("open file error {}", err)),
        };
        let mut buf = vec![];
        file.read_to_end(&mut buf).await?;
        let credentials_type: CredentialsType = serde_json::from_slice(&buf)?;
        let token = match credentials_type {
            CredentialsType::authorized_user(cred) => get_token_from_adc(cred).await?,
            CredentialsType::service_account(cred) => get_token_from_service_account(cred).await?,
        };
        self.json = Some(buf);
        self.token = Some(token);
        Ok(&self.token)
    }
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(untagged)]
enum CredentialsType {
    #[allow(non_camel_case_types)]
    authorized_user(ApplicationDefaultCredentials),
    #[allow(non_camel_case_types)]
    service_account(ServiceAccountCredentials),
}

#[derive(Deserialize, Serialize, Debug)]
struct ApplicationDefaultCredentials {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    r#type: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct Token {
    access_token: String,
    expires_in: i64,
    scope: Option<String>,
    token_type: String,
    id_token: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
struct ServiceAccountCredentials {
    r#type: String,
    project_id: String,
    private_key_id: String,
    private_key: String,
    client_email: String,
    client_id: String,
    auth_uri: String,
    token_uri: String,
    auth_provider_x509_cert_url: String,
    client_x509_cert_url: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    exp: u64,
    iat: u64,
}

async fn get_token_from_service_account(
    service_account: ServiceAccountCredentials,
) -> Result<Token> {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = Claims {
        iss: service_account.client_email,
        scope: String::from("https://www.googleapis.com/auth/devstorage.read_only"),
        aud: service_account.token_uri.clone(),
        iat: ts,
        exp: ts + 3600,
    };
    let header = Header {
        typ: Some("JWT".to_owned()),
        alg: Algorithm::RS256,
        cty: None,
        jku: None,
        kid: None,
        x5u: None,
        x5t: None,
    };
    let key = EncodingKey::from_rsa_pem(service_account.private_key.as_ref()).unwrap();
    let jwt = encode(&header, &claims, &key)?;
    let mut form: HashMap<&str, &str> = HashMap::new();
    form.insert("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer");
    form.insert("assertion", &jwt);
    let client = reqwest::Client::new();
    let resp = client
        .post(&service_account.token_uri)
        .form(&form)
        .send()
        .await?;
    Ok(resp.json::<Token>().await?)
}

async fn get_token_from_adc(credentials: ApplicationDefaultCredentials) -> Result<Token> {
    let client = reqwest::Client::new();
    let mut form: HashMap<String, String> = HashMap::new();
    form.insert(String::from("client_id"), credentials.client_id);
    form.insert(String::from("client_secret"), credentials.client_secret);
    form.insert(String::from("refresh_token"), credentials.refresh_token);
    form.insert(String::from("grant_type"), String::from("refresh_token"));
    let resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&form)
        .send()
        .await?;
    let resp_string = resp.text().await?;
    Ok(serde_json::from_str(&resp_string)?)
}
