use std::{hash::Hasher, collections::HashMap, sync::{RwLock, Arc}, ops::Add};
use chrono::{prelude::*, Duration};
use seahash::SeaHasher;
//abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789)(*&^%$#@!~
pub const CHARSET: &str = r"PQb7@&sU9WK*!GwHZxn1eJ#V(2kfF8AC3viuLzomOTD4NR^hyjdtS$rYMIcBq0gl~a%6)p5EX";
//0123456789
pub const NUMSET: &str = r"8132967540";
pub const NUM_CHARACTERS: usize = 4096;
pub const LICENSE_TIMEOUT_DAYS: i64 = 1;
pub const SALT: &str = r"rA9";

//TODO: Implement version salt as the client will tell the server which version it is running
//TODO: Implement auto-updater like discord and a few other services I use

pub fn generate_key(length: usize) -> String {
    let chars: Vec<char> = CHARSET.chars().collect();
    let mut key = String::with_capacity(length);
    unsafe {
        for _ in 0..length {
            key.push(
                *chars.get_unchecked(fastrand::usize(0..chars.len()))
            );
        }
    }
    key
}

pub fn hash_string(input: &str) -> String {
    let mut hasher = SeaHasher::new();
    hasher.write(input.as_bytes());
    hasher.finish().to_string()
}

pub fn hash_user(hashed_username: &str, hashed_password: &str, server_side_key: &str, issue_date: &DateTime<Utc>) -> String {
    hash_string(&format!("{}.{}.{}.{}", hashed_username, server_side_key, issue_date.to_string(), hashed_password))
}

/* pub enum ValidationStrenth {
    One = 1,
    Two = 2,
    Three = 3,
} */

pub fn validate_license(current_licenses: Arc<RwLock<HashMap<String, DateTime<Utc>>>>, current_users: Arc<RwLock<HashMap<String, User>>>, username: &str, password: &str) -> bool {
    let hashed_username = hash_string(username);
    let hashed_password = hash_string(password);
    
    //exits early if credentials don't exist/match
    match current_users.read().unwrap().get(&hashed_username) {
        Some(saved_user) => {
            if saved_user.hashed_password != hashed_password {
                return false;
            }
            let hash = hash_user(&hashed_username, &hashed_password, &saved_user.server_side_key, &saved_user.issue_date);
            if current_licenses.read().unwrap().contains_key(&hash) {
                //doesn't take into account expiration date yet
                return true;
            }
        },
        None => return false,
    }
    false
}

//returns false if credentials were invalid
pub fn generate_license(current_licenses: Arc<RwLock<HashMap<String, DateTime<Utc>>>>, current_users: Arc<RwLock<HashMap<String, User>>>, maybe_user: &User) -> bool {
    //exits early if credentials don't exist/match
    match current_users.read().unwrap().get(&maybe_user.hashed_username) {
        Some(saved_user) => {
            if saved_user.hashed_password != maybe_user.hashed_password {
                return false;
            }
            //definitely a user now, logical change
            let authenticated_user = maybe_user;

            //client_accessible_key is Hash|Client

            let hash = hash_user(&authenticated_user.hashed_username, &authenticated_user.hashed_password, &saved_user.server_side_key, &saved_user.issue_date);

            //Private|Expiration, a running application should always ask for a license before it's current one actually runs out                                            
            let expiry_date: DateTime<Utc> = saved_user.issue_date.add(Duration::days(LICENSE_TIMEOUT_DAYS));

            //add new license to HashMap
            {
                current_licenses.write().unwrap().insert(hash, expiry_date);
            }

            return true;
        },
        None => return false,
    }
}

pub struct License {
    _hash: String,
    _expiry_date: DateTime<Utc>,
}

#[derive(Hash)]
pub struct User {
    pub hashed_username: String,
    pub hashed_password: String,
    //Hash|Private
    pub server_side_key: String,
    //Hash|Private
    pub issue_date: DateTime<Utc>,
    //pub token: Option<String>,
}

impl User {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            hashed_username: hash_string(username),
            hashed_password: hash_string(password),
            server_side_key: generate_key(NUM_CHARACTERS),
            issue_date: Utc::now(),
            //token: generate_key(NUM_CHARACTERS),
        }
    }
}

pub fn create_user(current_users: Arc<RwLock<HashMap<String, User>>>, username: &str, password: &str) {
    let user: User = User::new(username, password);
    current_users.write().unwrap().insert(user.hashed_username.clone(), user);
}

pub fn validate_user(current_users: Arc<RwLock<HashMap<String, User>>>, username: &str, password: &str) -> bool {
    match current_users.read().unwrap().get(&hash_string(&username)) {
        Some(saved_user) => {
            if saved_user.hashed_password != hash_string(&password) {
                return false;
            }
        },
        None => {
            return false;
        },
    }
    true
}

fn main() {
    let current_licenses: Arc<RwLock<HashMap<String, DateTime<Utc>>>> = Arc::new(RwLock::new(HashMap::new()));
    let current_users: Arc<RwLock<HashMap<String, User>>> = Arc::new(RwLock::new(HashMap::new()));

    create_user(current_users.clone(), "me", "Password123");

    assert!(generate_license(current_licenses.clone(), current_users.clone(), &User::new("me", "Password123")));
    assert!(!generate_license(current_licenses.clone(), current_users.clone(), &User::new("me", "Password1234")));
    assert!(!generate_license(current_licenses.clone(), current_users.clone(), &User::new("you", "Password123")));

    assert!(validate_user(current_users.clone(), "me", "Password123"));

    assert!(validate_license(current_licenses.clone(), current_users.clone(), "me", "Password123"));
    assert!(!validate_license(current_licenses.clone(), current_users.clone(), "me", "Password1234"));



    //the server-side key plus the received client_accessible_key, username and password
    //this must be vetted as this will be received from the outside world.
    //the usernames will be pseudo-random generated from a short alpha-numeric character set much like PIA
    //these would be emailed or displayed on screen, an email will only be required for payment details, as per legal requirements and evidence of records and allowing the user to recover things.
    
    
    /* for i in 0..100000 {
        print!("\r{}", (i + 1) * 10000);
        io::stdout().flush().unwrap();
        for _ in 0..10000 {
            generate_thing("fuck".to_string());
        }
    } */
    //start async listener for hash and email, returns Ok() or None
    //may as well use a websocket

    //generate new reversable cryptographic hash of email plus private key
    //store the time and date of generation down to the nano second UTC
    //add it to a database for persistence and the HashMap for active use.

    //keep every single license that has ever been activated in a database with a counter


}
