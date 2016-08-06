use mongodb::error::Error as MongoError;
use rustc_serialize::json::{EncoderError, DecoderError};
use bson::oid::Error as OidError;
use iron::status;
use iron::middleware::AfterMiddleware;
use iron::prelude::*;

error_chain! {
    links {}
    foreign_links {
        MongoError, DatabaseError,
        "Database error";
        OidError, ObjectIdError,
        "Error generating ObjectId";
        DecoderError, JsonDecodeError,
        "Error decoding JSON data";
        EncoderError, JsonEncodeError,
        "Error encoding JSON data";

        
    }
    errors {
        TokenFailure(reason: String) {
            description("Token authentication failed")
            display("Could not authenticate client token: {}", reason) 
        }
        PasswordFailure(reason: String) {
            description("Password authentication failed")
            display("Password authentication failed: {}", reason)
        }
        MalformedRequest (msg: String) {
            description("Malformed request")
            display("Malformed request: {}", msg)
        }
    }

}

impl Error {
    /// Maps ErrorKind to HTTP status code
    pub fn get_status(&self) -> status::Status {
        use self::ErrorKind::*;
        match self.kind() {
            &DatabaseError |
            &ObjectIdError |
            &Msg(_) => status::InternalServerError,
            &MalformedRequest(_) |
            &JsonEncodeError |
            &JsonDecodeError => status::BadRequest,
            &TokenFailure(_) |
            &PasswordFailure(_) => status::Unauthorized,
        }
    }
    pub fn get_response(&self) -> Response {
        use self::ErrorKind::*;
        let status = self.get_status();
        let mut response = Response::with(status);
        match self.kind() {
            &TokenFailure(_) => {
                response.headers.set_raw("WWW-Authentication",
                                         vec![b"Token".to_vec(), b"realm=\"Serve-Backend".to_vec()])
            }
            &PasswordFailure(_) => {
                response.headers.set_raw("WWW-Authentication",
                                         vec![b"Basic".to_vec(), b"realm=\"Serve-Backend".to_vec()])
            }
            _ => {}
        }
        response
    }
}

impl From<Error> for IronError {
    fn from(e: Error) -> Self {
        IronError {
            response: e.get_response(),
            error: Box::new(e),
        }
    }
}


/// Log Error Chain after handling Request
pub struct LogError;
impl AfterMiddleware for LogError {
    fn catch(&self, _: &mut Request, err: IronError) -> IronResult<Response> {
        if let Some(e) = err.error.downcast::<Error>() {
            error!("{}", e);
            for e in e.iter().skip(1) {
                info!("caused by: {}", e);
            }
            trace!("{:?}", e.backtrace());
        }
        Err(err)
    }
}

/// Ensure that logs don't get cluttered up with errors that are the client's fault
pub struct IgnoreClientError;
impl AfterMiddleware for IgnoreClientError {
    fn catch(&self, _: &mut Request, err: IronError) -> IronResult<Response> {
        if let Some(s) = err.response.status {
            if !s.is_server_error() {
                return Ok(err.response);
            }
            debug!("{}", err);
        }
        Err(err)
    }
}
