use bson::oid;
use bson::Bson;
use mongodb::{Client, ThreadedClient};
use mongodb::db::ThreadedDatabase;
use mongodb::coll::Collection;
use mongodb::error::Result as MongoResult;
use rustc_serialize::json;

use error::Result;

#[derive(Default, Debug, RustcEncodable, RustcDecodable)]
pub struct User {
    pub first: Option<String>,
    pub last: Option<String>,
    pub _id: Option<oid::ObjectId>,
}

macro_rules! insert_user {
    ($doc:ident; $user:expr; $($field:ident),+) => {{
        $(
            if let Some(ref field) = $user.$field {
                $doc.insert(stringify!($field), field.clone());
            }
         )+
    }};
}

macro_rules! validate_user {
    ($user:expr; $($field:ident),+) => {{
        let mut res: ::error::Result<()> = Ok(());
        let mut _first = true;
        $(
            if $user.$field.is_none() {
                let err = ::error::ErrorKind::MalformedRequest(
                    format!("missing required JSON object: {}", stringify!($field)));
                if _first {
                    res = Err(err.into());
                    _first = false;
                } else {
                    res = res.chain_err(|| err);
                }
            }
         )+
        res
    }};
}

impl User {
    pub fn add_to_db(&self) -> Result<oid::ObjectId> {
        let coll = try!(get_collection());
        let id = try!(oid::ObjectId::new());
        let mut doc = doc! { "_id" => (id.clone()) };
        insert_user!(doc; self; first, last);
        try!(coll.insert_one(doc, None));
        Ok(id)
    }
    pub fn find(&self) -> Result<String> {
        let coll = try!(get_collection());
        let mut doc = doc!();
        insert_user!(doc; self; first, last, _id);
        let res: Result<Vec<_>> = try!(coll.find(Some(doc), None))
                                      .map(|res| {
                                          res.map(|d| Bson::Document(d).to_json())
                                             .map_err(|e| From::from(e))
                                      })
                                      .collect();

        json::encode(&try!(res))
            .map(|j| j.to_string())
            .map_err(|e| From::from(e))
    }
    pub fn find_one(&self) -> Result<Option<String>> {
        let coll = try!(get_collection());
        let mut doc = doc!();
        insert_user!(doc; self; first, last, _id);
        Ok(try!(coll.find_one(Some(doc), None)).map(|d| Bson::Document(d).to_json().to_string()))
    }
}

const DB_LOC: &'static str = "localhost";
const DB_PORT: u16 = 27017;
const DB_NAME: &'static str = "users";
const COLL_NAME: &'static str = "rust-users";


fn get_collection() -> MongoResult<Collection> {
    Ok(try!(Client::connect(DB_LOC, DB_PORT)).db(DB_NAME).collection(COLL_NAME))
}
