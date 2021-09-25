use std::convert::TryInto;

use serde_json::json;
use sha2::Digest;
use worker::*;

mod utils;

const ONE_YEAR_IN_SECONDS: u64 = 60 * 60 * 24 * 365;
const ID_HASH_SALT: &str = include_str!("../../ID_HASH_SALT");
const RECAPTCHA_SECRET: &str = include_str!("../../RECAPTCHA_SECRET");

trait Cors {
    fn cors(self, req: &Request) -> Result<Response>;
}

impl Cors for Response {
    fn cors(self, req: &Request) -> Result<Response> {
        static ALLOWED_ORIGINS: &[&str] = &["http://localhost:3000", "https://pc.cro.sh"];

        let mut cors_header = Headers::new();
        if let Some(origin) = req.headers().get("Origin")? {
            if ALLOWED_ORIGINS.iter().find(|&&x| x == origin).is_some() {
                cors_header.append("Access-Control-Allow-Origin", &origin)?;
            }
        }

        Ok(self.with_headers(cors_header))
    }
}

fn log_request(req: &Request) {
    console_log!(
        "{} - [{}], located at: {:?}, within: {}",
        Date::now().to_string(),
        req.path(),
        req.cf().coordinates().unwrap_or_default(),
        req.cf().region().unwrap_or_else(|| "unknown region".into())
    );
}

/// Returns SHA256 hashed hex string(with salt).
fn sha256_salted_hash(x: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(ID_HASH_SALT.as_bytes());
    hasher.update(x);
    let hashed_key = hasher.finalize();
    let upper = u128::from_be_bytes(hashed_key[..16].try_into().unwrap());
    let lower = u128::from_be_bytes(hashed_key[16..].try_into().unwrap());
    format!("{:x}{:x}", upper, lower)
}

async fn validate_recaptcha(token: String) -> Result<bool> {
    let mut init = RequestInit::new();
    init.method = Method::Post;

    let mut resp = Fetch::Request(Request::new_with_init(
        &format!(
            "https://www.google.com/recaptcha/api/siteverify?secret={}&response={}",
            RECAPTCHA_SECRET, token
        ),
        &init,
    )?)
    .send()
    .await?;

    let json: serde_json::Value = resp.json().await?;
    console_log!("{:?}", json);
    json["success"]
        .as_bool()
        .ok_or_else(|| Error::RustError("Type assertion failed".to_owned()))
}

async fn v1_put(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if let Some(key) = ctx.param("key") {
        let token = req
            .headers()
            .get("X-RECAPTCHA-TOKEN")?
            .ok_or_else(|| Error::RustError("No reCAPTCHA token".to_owned()))?;

        if !validate_recaptcha(token).await? {
            return Ok(Response::ok("recaptcha_fail")?.cors(&req)?.with_status(417));
        }

        let body = req.bytes().await?;
        let body = base64::encode(body);
        if body.as_bytes().len() > (400 << 10) {
            return Ok(
                Response::ok(format!("file_size_too_big, got: {}", body.as_bytes().len()))?
                    .cors(&req)?
                    .with_status(413),
            );
        }

        let kv = ctx.kv("pc")?;
        let hashed_key = sha256_salted_hash(key.as_bytes());
        kv.put(&hashed_key, body)?
            .expiration_ttl(ONE_YEAR_IN_SECONDS)
            .metadata(json!({"version": "1"}))?
            .execute()
            .await?;

        Response::ok("ok")?.cors(&req)
    } else {
        Response::error("Bad Request", 400)?.cors(&req)
    }
}

async fn v1_get(mut req: Request, ctx: RouteContext<()>) -> worker::Result<Response> {
    if let Some(key) = ctx.param("key") {
        let token = req
            .headers()
            .get("X-RECAPTCHA-TOKEN")?
            .ok_or_else(|| Error::RustError("No reCAPTCHA token".to_owned()))?;

        if !validate_recaptcha(token).await? {
            return Ok(Response::ok("recaptcha_fail")?.cors(&req)?.with_status(403));
        }

        let kv = ctx.kv("pc")?;
        let hashed_key = sha256_salted_hash(key.as_bytes());
        let value = kv.get(&hashed_key).await?;

        Response::ok("")?.cors(&req)
    } else {
        Response::error("Bad Request", 400)?.cors(&req)
    }
}

async fn v1_preflight(req: Request, _ctx: RouteContext<()>) -> worker::Result<Response> {
    let mut resp = Response::ok("")?.cors(&req)?;
    resp.headers_mut()
        .append("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")?;
    resp.headers_mut()
        .append("Access-Control-Allow-Headers", "X-RECAPTCHA-TOKEN")?;

    Ok(resp)
}

#[event(fetch)]
pub async fn main(req: Request, env: Env) -> Result<Response> {
    main_inner(req, env).await
}

pub async fn main_inner(req: Request, env: Env) -> Result<Response> {
    log_request(&req);

    // Optionally, get more helpful error messages written to the console in the case of a panic.
    utils::set_panic_hook();

    // Optionally, use the Router to handle matching endpoints, use ":name" placeholders, or "*name"
    // catch-alls to match on specific patterns. The Router takes some data with its `new` method
    // that can be shared throughout all routes. If you don't need any shared data, use `()`.
    let router = Router::new();

    // Add as many routes as your Worker needs! Each route will get a `Request` for handling HTTP
    // functionality and a `RouteContext` which you can use to  and get route parameters and
    // Enviornment bindings like KV Stores, Durable Objects, Secrets, and Variables.
    router
        .put_async("/api/:key", v1_put)
        .options_async("/api/:key", v1_preflight)
        .run(req, env)
        .await
}
