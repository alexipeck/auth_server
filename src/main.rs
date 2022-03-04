use std::{collections::HashMap, sync::{RwLock, Arc}, ops::Add, net::TcpListener, thread, io::{Read, Write}};
use chrono::{prelude::*, Duration};
use crypto_hash::{Algorithm, hex_digest};
use serde::{Deserialize, Serialize};
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
    hex_digest(Algorithm::SHA512, input.as_bytes())
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

/* async fn handle_web_connection(
    peer_map: Arc<Mutex<PeerMap>>,
    raw_stream: TcpStream,
    addr: SocketAddr,
    tasks: Arc<Mutex<VecDeque<Task>>>,
    file_manager: Arc<Mutex<FileManager>>,
    worker_manager_transcode_queue: Arc<Mutex<VecDeque<Encode>>>,
    worker_manager: Arc<Mutex<WorkerManager>>,
    server_config: Arc<RwLock<ServerConfig>>,
) {
    println!("Incoming TCP connection from: {}", addr);

    let ws_stream = tokio_tungstenite::accept_async(raw_stream)
        .await
        .unwrap_or_else(|err| {
            println!(
                "Error during the websocket handshake occurred. Err: {}",
                err
            );
            panic!();
        });
        println!("WebSocket connection established: {}", addr);

    // Insert the write part of this peer to the peer map.
    let (tx, rx) = unbounded();
    peer_map.lock().unwrap().insert(addr, (None, tx.clone()));
    let (outgoing, incoming) = ws_stream.split();

    let broadcast_incoming = incoming.try_for_each(|msg| {
        if msg.is_text() {
            let message = msg
                .to_text()
                .unwrap()
                .strip_suffix("\r\n")
                .or_else(|| msg.to_text().unwrap().strip_suffix('\n'))
                .unwrap_or_else(|| msg.to_text().unwrap());
            /* //Shitty way of separating json and text, starting a message with '{' will make it shit itself
            if message.starts_with('{') {
                let raw_message_source: Result<MessageSource, Error> = serde_json::from_str(message);
                match raw_message_source {
                    Ok(message_source) => match message_source {
                        MessageSource::WebUI(webui_message) => {
                            match webui_message.clone() {
                                WebUIMessage::Request(request_type) => {
                                    let request_type: RequestType = request_type;
                                    match request_type {
                                        RequestType::AllFileVersions => {
                                            request_all_file_versions(tx.clone(), file_manager.clone());
                                        }
                                        RequestType::AllShows => {
                                            request_all_shows(tx.clone(), file_manager.clone());
                                        },
                                    };
                                }
                                WebUIMessage::Encode(generic_uid, id) => {
                                    encode_file(file_manager.clone(), worker_manager_transcode_queue.clone(), &EncodeProfile::H264_TV_1080p, generic_uid, id);
                                },
                                _ => {
                                    println!("Server received a message it doesn't know how to handle");
                                }
                            }
                            
                            println!("{:?}", webui_message);

                            
                        },
                        MessageSource::Worker(worker_message) => {
                            match worker_message {
                                WorkerMessage::Initialise(_) => {
                                    initialise(
                                        worker_message,
                                        worker_manager.clone(),
                                        addr,
                                        tx.clone(),
                                        peer_map.clone(),
                                    );
                                }
                                WorkerMessage::EncodeGeneric(_, _, _, _) => {
                                    encode_generic(
                                        worker_message,
                                        file_manager.clone(),
                                        worker_manager_transcode_queue.clone(),
                                        server_config.clone(),
                                    );
                                }
                                WorkerMessage::EncodeStarted(_, _) => {
                                    encode_started(worker_message);
                                }
                                WorkerMessage::EncodeFinished(_, _, _) => {
                                    encode_finished(worker_message);
                                }
                                WorkerMessage::MoveStarted(_, _, _, _) => {
                                    move_started(worker_message);
                                }
                                WorkerMessage::MoveFinished(_, _, _) => {
                                    move_finished(worker_message, worker_manager.clone(), file_manager.clone());
                                }
                                _ => {
                                    println!("Server received a message it doesn't know how to handle, ignoring");
                                }
                            }
                        },
                    },
                    Err(err) => {
                        println!(
                            "Failed converting json string to MessageSource, error output: {}",
                            err
                        );
                        panic!();
                    }
                }
            } else {
                match message {
                    //Tasks
                    "hash" => hash_files(tasks.clone()),
                    "import" => import_files(tasks.clone()),
                    "process" => process_files(tasks.clone()),
                    "generate_profiles" => generate_profiles(tasks.clone()),
                    "bulk" => {
                        //TODO: Implement a way of making one task wait for another before it can run
                        //    : this will require tasks to be logged in the DB and knowledge of the uid for the await
                        //    : this is a scheduler/task thing
                        import_files(tasks.clone());
                        process_files(tasks.clone());
                        hash_files(tasks.clone());
                        generate_profiles(tasks.clone());
                    }
                    "test" => {
                        crate::ws_functions::test(tx.clone());
                    }

                    //Debug tasks
                    "output_tracked_paths" => output_tracked_paths(file_manager.clone()),
                    "output_file_versions" => output_all_file_versions(file_manager.clone()),
                    "display_workers" => print_all_worker_models(),
                    "encode_all" => encode_all_files(
                        file_manager.clone(),
                        worker_manager_transcode_queue.clone(),
                        &EncodeProfile::H265,
                    ),
                    "encode_all_4k" => encode_all_files(
                        file_manager.clone(),
                        worker_manager_transcode_queue.clone(),
                        &EncodeProfile::H265_TV_4K,
                    ),
                    "run_completeness_check" => run_completeness_check(file_manager.clone()),
                    "kill_all_workers" => {
                        //TODO: Make this force close all workers, used for constant resetting of the dev/test environment
                    },

                    _ => println!("{} is not a valid input", message),
                }
            }
        } else if msg.is_binary() {
            //Currently nothing using binary messages
        } */
        

        future::ok(())
    }
    });
} */

pub fn format_http_response(text_message: &str) -> String {
    format!("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n{}", text_message)
}

#[derive(Serialize, Deserialize, Clone, Debug, Hash)]
pub struct Credentials {
    username: String,
    password: String,
    salt: String,
}

impl Credentials {
    pub fn from_raw(raw: String) -> Option<Self> {
        let raw_credentials: Result<Credentials, serde_json::Error> = serde_json::from_str(&raw);
        match raw_credentials {
            Ok(credentials) => Some(credentials),
            Err(err) => {
                println!("{}", err);
                return None
            },
        }
    }
}

pub fn parse_usable_text_from_raw_text(raw_text: String) -> String {
    let mut text = raw_text.split('\n').into_iter().skip(5).collect::<String>();
    text = text.strip_suffix("\r\n")
        .or_else(|| text.strip_suffix('\n'))
        .unwrap_or_else(|| &text).to_string();
    text = format!("{}}}", text.split('}').collect::<Vec<&str>>()[0].to_string());
    text
}

fn main() {
    //NOTE: Shouldn't use seahash, I need a fast cryptographic hashing algorithm thingo
    let current_licenses: Arc<RwLock<HashMap<String, DateTime<Utc>>>> = Arc::new(RwLock::new(HashMap::new()));
    let current_users: Arc<RwLock<HashMap<String, User>>> = Arc::new(RwLock::new(HashMap::new()));

    create_user(current_users.clone(), "me", "Password123");

    assert!( generate_license(current_licenses.clone(), current_users.clone(), &User::new("me",  "Password123")));
    assert!(!generate_license(current_licenses.clone(), current_users.clone(), &User::new("me",  "Password1234")));
    assert!(!generate_license(current_licenses.clone(), current_users.clone(), &User::new("you", "Password123")));

    assert!( validate_user(current_users.clone(), "me",  "Password123"));
    assert!(!validate_user(current_users.clone(), "me",  "Password1234"));
    assert!(!validate_user(current_users.clone(), "you", "Password123"));

    assert!( validate_license(current_licenses.clone(), current_users.clone(), "me",  "Password123"));
    assert!(!validate_license(current_licenses.clone(), current_users.clone(), "me",  "Password1234"));
    assert!(!validate_license(current_licenses.clone(), current_users.clone(), "you", "Password123"));


    //use the username and password to generate the key the server actually uses to start, the server will just use that key to start
    //and when the key isn't valid anymore because of the time expiry (probably just authenticated on the auth server for now)
    //it will ask the auth server for a new key with their current email and password, atm I just intend to use a daily license
    //eventually, I want long term, server condition invalidated keys, such as too many active uses of a key



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

    let listener = TcpListener::bind("127.0.0.1:35469").unwrap();
    println!("Listening for connections on port {}", 35469);

    for stream in listener.incoming() {
        match stream {
            Ok(mut stream) => {
                thread::spawn(move || {
                    let mut buf = [0u8; 4096];
                    match stream.read(&mut buf) {
                        Ok(_) => {
                            println!("Received request.");
                            let raw_text = String::from_utf8_lossy(&buf).to_string();
                            let text = parse_usable_text_from_raw_text(raw_text.to_owned());
                            let credentials = Credentials::from_raw(text);
                            match credentials {
                                Some(credentials) => {
                                    println!("{:?}", credentials);
                                    //TODO: Return the hash of the nearest half minute, using as many characters that is needed down to the nano second, even if it's only to second precision/half minute precisions
                                    let now = Utc::now();
                                    let time_closest_minute = format!("{}-{:02}-{:02} {:02}:{:02}:00.000000000 UTC", now.year(), now.month(), now.day(), now.hour(), {if now.second() < 30 { now.minute() } else { now.minute() + 1 }});
                                    let hash_time_closest_minute = hash_string(&time_closest_minute);//not sure if I actually need this to he hashed
                                    let authenticated_response = hash_string(&format!("{}{}{}{}", credentials.salt, credentials.username, hash_time_closest_minute, credentials.password));
                                    if let Err(err) = stream.write(format_http_response(&authenticated_response).as_bytes()) {
                                        println!("Failed sending response: {}", err);
                                    }
                                },
                                None => {
                                    //TODO: Log event, but ultimately ignore
                                },
                            }
                        },
                        Err(e) => println!("Unable to read stream: {}", e),
                    }
                });
            }
            Err(e) => {
                println!("Unable to connect: {}", e);
            }
        }
    }
}