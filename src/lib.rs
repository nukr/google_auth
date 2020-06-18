use anyhow::{anyhow, Result};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Read;

#[derive(Deserialize, Serialize, Debug)]
struct Credentials {
    client_id: String,
    client_secret: String,
    refresh_token: String,
    r#type: String,
}

#[derive(Deserialize, Serialize, Debug)]
struct Token {
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

fn get_access_token_from_service_account(service_account: ServiceAccountCredentials) -> String {
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
    let jwt = encode(&header, &claims, &key);
    let mut form: HashMap<String, String> = HashMap::new();
    form.insert(
        String::from("grant_type"),
        String::from("urn:ietf:params:oauth:grant-type:jwt-bearer"),
    );
    form.insert(String::from("assertion"), jwt.unwrap().to_string());
    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(&service_account.token_uri)
        .form(&form)
        .send()
        .unwrap();
    let resp_text = resp.text().unwrap();
    let token: Token = serde_json::from_str(&resp_text).unwrap();
    token.access_token
}

fn find_application_default_credentials() -> Credentials {
    let home_path = std::env::var("HOME").unwrap();
    let config_path = ".config/gcloud/application_default_credentials.json";
    let path = std::path::Path::new(&home_path).join(&config_path);
    let mut file = OpenOptions::new()
        .read(true)
        .write(false)
        .open(path)
        .unwrap();
    let mut buf = String::new();
    file.read_to_string(&mut buf).unwrap();
    serde_json::from_str(&buf).unwrap()
}

fn get_access_token(credentials: Credentials) -> Token {
    let client = reqwest::blocking::Client::new();
    let mut form: HashMap<String, String> = HashMap::new();
    form.insert(String::from("client_id"), credentials.client_id);
    form.insert(String::from("client_secret"), credentials.client_secret);
    form.insert(String::from("refresh_token"), credentials.refresh_token);
    form.insert(String::from("grant_type"), String::from("refresh_token"));
    let mut resp = client
        .post("https://oauth2.googleapis.com/token")
        .form(&form)
        .send()
        .unwrap();
    let mut resp_string = String::new();
    resp.read_to_string(&mut resp_string).unwrap();
    serde_json::from_str(&resp_string).unwrap()
}

pub fn find_access_token() -> Result<String> {
    if let Ok(gadc) = std::env::var("GOOGLE_APPLICATION_DEFAULT_CREDENTIAL") {
        let mut file = match OpenOptions::new().read(true).open(gadc) {
            Ok(file) => file,
            Err(err) => return Err(anyhow!("open file error {}", err)),
        };
        let mut buf = String::new();
        if let Err(err) = file.read_to_string(&mut buf) {
            return Err(anyhow!("read_to_string error {}", err));
        };
        let cred: ServiceAccountCredentials = match serde_json::from_str(&buf) {
            Ok(cred) => cred,
            Err(err) => return Err(anyhow!("parse json error {}", err)),
        };
        let access_token = get_access_token_from_service_account(cred);
        return Ok(access_token);
    };
    let credentials = find_application_default_credentials();
    let token = get_access_token(credentials);
    Ok(token.access_token)
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
