#![recursion_limit = "1024"]
#![feature(try_from)]

#[macro_use]
extern crate bson;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate iron;
#[macro_use]
extern crate log;
#[macro_use]
extern crate router;
extern crate crypto;
extern crate env_logger;
extern crate jwt;
extern crate mongodb;
extern crate rustc_serialize;
extern crate time;

#[macro_use]mod user;
mod auth;
mod error;

use std::io::Read;
use std::default::Default;

use bson::oid::ObjectId;

use iron::prelude::*;
use iron::status;
use iron::headers::{ContentType, Location, Bearer, Basic};
use router::Router;
use rustc_serialize::{json, Decodable};

use auth::{Authenticate, Auth};
use error::{Error, ChainErr, Result, LogError, IgnoreClientError};
use user::User;


fn main() {
    env_logger::init().unwrap();
    let router = router! {
        post "/users" => |req: &mut Request| {
            try!(Auth::<Bearer>::auth(req));
            let user: User = try!(decode_body(req));
            try!(validate_user!(user; first, last));

            let uid = try!(user.add_to_db());
            info!("User created: {:?}", user);

            let mut resp = Response::with(status::Created);
            resp.headers.set(Location(format!("/users/{}", uid)));
            Ok(resp)
        },
        post "/users/*" => |req: &mut Request| {
            try!(Auth::<Bearer>::auth(req));
            Ok(Response::with(status::Conflict))
        },
        post "/login" => |req: &mut Request| {
            let token = try!(Auth::<Basic>::auth(req));
            Ok(Response::with((status::Ok, token)))
        },
        get "/users/:id" => |req: &mut Request | {
            try!(Auth::<Bearer>::auth(req));
            let id_str = req.extensions.get::<Router>().unwrap().find("id").unwrap();
            let id = try!(ObjectId::with_string(id_str).map_err(|e| Error::from(e)));
            let user = User { _id: Some(id), ..Default::default()};
            let ret = try!(user.find_one());

            Ok(match ret {
                Some(user) => {
                    let mut resp = Response::with((status::Ok, user));
                    resp.headers.set(ContentType::json());
                    resp
                }
                None => Response::with(status::NotFound)
            })

        },
        get "/users" => |req: &mut Request| {
            try!(Auth::<Bearer>::auth(req));
            let mut resp = Response::with((status::Ok, try!(User::default().find())));
            resp.headers.set(ContentType::json());
            Ok(resp)
        }
    };
    let mut chain = Chain::new(router);
    chain.link_before(Authenticate);
    chain.link_after(IgnoreClientError);
    chain.link_after(LogError);
    Iron::new(chain)
        .https("localhost:3000",
               From::from("./ssl/ssl.crt"),
               From::from("./ssl/ssl.key"))
        .unwrap();
}

fn decode_body<T: Decodable>(req: &mut Request) -> Result<T> {
    let mut buf = String::new();
    try!(req.body.read_to_string(&mut buf).map_err(|_| Error::from("Failed to read request")));
    json::decode(&buf).map_err(|e| Error::from(e))
}
