use std::{sync::Arc, fs, path::Path };
use alloy::{ providers::Provider} ;
use tokio::{ net::UnixListener, task::JoinHandle};

use crate::{
    auth::store::SessionStore, config::Config, eth::node::SzProvider, keys::store::KeyStore,
};

pub mod stream;
pub mod binary;
pub mod json;
pub mod cmds;

pub async fn start_listener(
    sesh: Arc<SessionStore>, keys: Arc<KeyStore>, 
    provider: SzProvider<impl Provider + Clone + 'static>, 
    config: &Config,
) -> JoinHandle<()> {

    let path = Path::new(&config.unix.path);
    if path.exists() {
        fs::remove_file(path).expect("Failed to remove existing socket file");
    }
    let listener = UnixListener::bind(path).expect("Failed to bind socket.");
    tokio::task::spawn(async move {
        while let Ok((raw_stream, _addr)) = listener.accept().await {
            let t_s = sesh.clone();
            let t_k = keys.clone();
            let t_p = provider.clone();
            tokio::task::spawn(async move {
                let mut stream = stream::FramedStream::new(raw_stream);
                loop {
                    // Step 1: Read byte code prefix
                    let res = stream.load_message().await;
                    if res.is_err() {
                        println!("Error reading message: {:?}", res);
                        break; // socket closed or error
                    } else {
                        if stream.is_binary() {
                            // Step 4: Dispatch Command, and catch error
                            if let Err(e) = binary::bin_dispatcher(&t_s, &t_k, &t_p, &mut stream).await {
                                let _ = stream.write_error(e);
                            }
                            if stream.flush_buffer(false).await.is_err() {
                                let _ = stream.shutdown().await;
                                break
                            }
                        } else {
                            if let Err(e) = json::json_dispatcher(&t_s, &t_k, &t_p, &mut stream).await {
                                let _ = stream.write_error(e);
                            }
                            if stream.flush_buffer(true).await.is_err() {
                                let _ = stream.shutdown().await;
                                break
                            }
                        }

                    }
                }
            });
        }
    })
}

