use std::convert::TryFrom;

use iron::typemap;
use iron::prelude::*;
use iron::middleware::BeforeMiddleware;
use iron::headers::{Authorization, Bearer, Basic};

use jwt::{self, Header, Registered};
use crypto::sha2::Sha256;
use time::get_time;

use error::{ErrorKind, Result};
use error::ErrorKind::{TokenFailure, PasswordFailure, MalformedRequest};

const SECRET: &'static [u8] = include_bytes!("./secret.key");
const TOKEN_LIFESPAN: u64 = 600;

type Token = jwt::Token<Header, Registered>;
struct AuthToken;
impl typemap::Key for AuthToken {
    type Value = Token;
}

pub struct Authenticate;
impl BeforeMiddleware for Authenticate {
    fn before(&self, req: &mut Request) -> IronResult<()> {
        if req.url.path[0] == "login" {
            Auth::<Basic>::load(req)
        } else {
            Auth::<Bearer>::load(req)
        }.map_err(|e| From::from(e))

    }
}

pub trait Auth<T> where T: ::iron::headers::Scheme {
    type AuthReturn;
    fn load(&mut self) -> Result<()>;
    fn auth(&self) -> Result<Self::AuthReturn>;
}

impl<'a, 'b> Auth<Bearer> for Request<'a, 'b> {
    type AuthReturn = ();
    fn load(&mut self) -> Result<()> {
        self.headers
            .get::<Authorization<Bearer>>()
            .ok_or(TokenFailure("Missing authentication tokens".to_owned()).into())
            .map(|header| &header.0.token)
            .and_then(|tok_str| {
                Token::parse(tok_str).map_err(|_| {
                    MalformedRequest(format!("Could not parse JWT: \"{}\"", tok_str)).into()
                })
            })
            .map(|tok| {
                self.extensions.insert::<AuthToken>(tok);
            })
    }
    fn auth(&self) -> Result<Self::AuthReturn> {
        self.extensions
            .get::<AuthToken>()
            .ok_or("No AuthToken found in request".into())
            .and_then(|token| {
                let time = get_time().sec as u64;
                let exp = token.claims.exp.unwrap();
                if !token.verify(SECRET, Sha256::new()) {
                    Err(TokenFailure(format!("Token verification failed")).into())
                } else if time > exp {
                    Err(TokenFailure(format!("Token expired {} second(s) ago", time - exp)).into())
                } else {
                    Ok(())
                }
            })
    }
}

impl<'a, 'b> Auth<Basic> for Request<'a, 'b> {
    type AuthReturn = String;
    fn load(&mut self) -> Result<()> {
        Ok(())
    }
    fn auth(&self) -> Result<Self::AuthReturn> {
        self.headers
            .get::<Authorization<Basic>>()
            .ok_or(PasswordFailure("Client did not provide Basic header".to_owned()).into())
            .map(|auth| &auth.0)
            .and_then(|b| Login::try_from(b.clone()))
            .and_then(|l| l.get_token())
    }
}

pub struct Login {
    username: String,
    password: String,
}

impl Login {
    pub fn get_token(&self) -> Result<String> {
        try!(self.check_password());
        let header = Header::default();
        let time = get_time().sec as u64;
        let claims = Registered {
            sub: Some(self.username.to_owned()),
            iss: Some("serve_backend".to_owned()),
            iat: Some(time),
            exp: Some(time + TOKEN_LIFESPAN),
            ..Default::default()
        };
        let token = Token::new(header, claims);
        token.signed(SECRET, Sha256::new()).map_err(|_| "Failure signing token".into())
    }
    #[inline(always)]
    fn check_password(&self) -> Result<()> {
        if self.password == "secret" {
            Ok(())
        } else {
            Err(ErrorKind::PasswordFailure("Incorrect password".to_owned()).into())
        }
    }
}

impl TryFrom<Basic> for Login {
    type Err = ::error::Error;
    fn try_from(b: Basic) -> Result<Self> {
        b.password
         .as_ref()
         .ok_or(ErrorKind::MalformedRequest("Password not supplied by client".to_owned()).into())
         .map(|pass| {
             Login {
                 username: b.username.clone(),
                 password: pass.clone(),
             }
         })
    }
}
