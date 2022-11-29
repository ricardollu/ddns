use chrono::Utc;
use hmacsha1::hmac_sha1;
use rand::{distributions::Uniform, prelude::Distribution};
use serde::Deserialize;
use std::env;
use std::time::Duration;
use std::{error::Error, thread};
use url::form_urlencoded::byte_serialize;

fn main() {
    println!("version {}", env!("CARGO_PKG_VERSION"));
    loop {
        // get ip
        let ip = match get_ip() {
            Ok(ip) => ip,
            Err(e) => {
                println!("oops! err: {:#?}", e);
                thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        // update record
        if let Err(e) = set_ip(ip) {
            println!("oops! err: {:#?}", e);
        }

        // sleep
        thread::sleep(Duration::from_secs(5))
    }
}

fn get_ip() -> Result<String, Box<dyn Error>> {
    let res = reqwest::blocking::get("https://ipv4.icanhazip.com")?.text()?;
    Ok(res)
}

#[derive(Deserialize, Debug)]
#[serde(rename_all(deserialize = "PascalCase"))]
struct AliyunUpdateDomainRecordResult {
    // request_id: String,
    code: Option<String>,
}

fn set_ip(ip: String) -> Result<(), Box<dyn Error>> {
    let timestamp = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let signature_nonce: String = Uniform::new(0, 10)
        .sample_iter(rand::thread_rng())
        .take(15)
        .map(|i| i.to_string())
        .collect();
    let get_env = |k: &'static str| -> String { env::var(k).unwrap_or_else(|_| String::from("")) };
    let access_key_id = get_env("ACCESS_KEY_ID");
    let access_key_secret = get_env("ACCESS_KEY_SECRET");
    let rr = get_env("RR");
    let record_id = get_env("RECORD_ID");

    let mut params = vec![
        ("Action", "UpdateDomainRecord"),
        ("RR", &rr),
        ("RecordId", &record_id),
        ("Type", "A"),
        ("Value", &ip),
        ("Version", "2015-01-09"),
        ("Format", "json"),
        ("AccessKeyId", &access_key_id),
        ("SignatureMethod", "HMAC-SHA1"),
        ("Timestamp", &timestamp),
        ("SignatureVersion", "1.0"),
        ("SignatureNonce", &signature_nonce),
    ];
    params.sort_by(|a, b| a.0.cmp(b.0));

    let a: Vec<_> = params
        .iter()
        .map(|item| format!("{}={}", url_encode(item.0), url_encode(item.1)))
        .collect();
    let a = format!("GET&%2F&{}", url_encode(&a.join("&")));

    let a = hmac_sha1((format!("{}&", access_key_secret)).as_bytes(), a.as_bytes());
    let sign = base64::encode(a);

    params.push(("Signature", &sign));

    let b = params.iter().fold(String::new(), |v, item| {
        format!(
            "{}&{}={}",
            v,
            byte_serialize(item.0.as_bytes()).collect::<String>(),
            byte_serialize(item.1.as_bytes()).collect::<String>()
        )
    });

    let res: AliyunUpdateDomainRecordResult =
        reqwest::blocking::get(format!("https://alidns.aliyuncs.com?{}", &b[1..]))?.json()?;

    match res.code {
        Some(error_code) => {
            if error_code != "DomainRecordDuplicate" {
                println!("aliyun error: {}", error_code)
            }
        }
        None => println!("update success! new ip: {}", ip),
    }
    Ok(())
}

fn url_encode(text: &str) -> String {
    let encoded_text: String = byte_serialize(text.as_bytes()).collect();
    encoded_text
        .replace('+', "%20")
        .replace('*', "%2A")
        .replace("%7E", "~")
}
