use std::fs;
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use chrono::Utc;
use reqwest::blocking::Client;
use hex::encode;

type HmacSha256 = Hmac<Sha256>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let access_key = "mr0PbSHDSWykTX9lTC5R";
    let secret_key = "UphVPZAGy9wkd4IrFNuImiWMSe7M7SSwKtzDwaqG";
    let region = "us-east-1";
    let service = "s3";
    let bucket = "devapp";
    let object_key = "sample-rs.png";
    let endpoint = "http://localhost:9999";

    let payload = fs::read("sample.png")?;
    let payload_hash = sha256_hex(&payload);
    
    let now = Utc::now();
    let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let date_stamp = now.format("%Y%m%d").to_string();

    let canonical_uri = format!("/{}/{}", bucket, object_key);
    let host = "localhost:9999";
    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, payload_hash, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    // FIX: extra \n between headers and signed_headers
    let canonical_request = format!(
        "PUT\n{}\n\n{}\
        \n{}\n{}",
        canonical_uri,
        canonical_headers,
        signed_headers,
        payload_hash
    );

    let credential_scope = format!("{}/{}/{}/aws4_request", date_stamp, region, service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        credential_scope,
        sha256_hex(canonical_request.as_bytes())
    );

    let signing_key = get_signature_key(secret_key, &date_stamp, region, service);
    let signature = hmac_sha256_hex(&signing_key, &string_to_sign);

    let authorization_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        access_key, credential_scope, signed_headers, signature
    );

    // Send the request
    let client = Client::new();
    let url = format!("{}{}", endpoint, canonical_uri);
    let res = client.put(&url)
        .header("Authorization", authorization_header)
        .header("x-amz-date", amz_date)
        .header("x-amz-content-sha256", payload_hash)
        .body(payload)
        .send()?;

    println!("Status: {}", res.status());
    println!("Response: {}", res.text()?);

    Ok(())
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    encode(hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

fn hmac_sha256_hex(key: &[u8], data: &str) -> String {
    encode(hmac_sha256(key, data))
}

fn get_signature_key(key: &str, date: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", key).as_bytes(), date);
    let k_region = hmac_sha256(&k_date, region);
    let k_service = hmac_sha256(&k_region, service);
    hmac_sha256(&k_service, "aws4_request")
}
