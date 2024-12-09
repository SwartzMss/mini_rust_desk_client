use crate::client::{*,Data,MediaSender,Client,MediaData,start_video_audio_threads};
use crossbeam_queue::ArrayQueue;
use std::sync::{Arc,RwLock,Mutex};
use std::collections::HashMap;
use mini_rust_desk_common::{
    message_proto::{permission_info::Permission, *},
    protobuf::Message as _,
    rendezvous_proto::ConnType,
    tokio::{ self, sync::mpsc},
    log,Stream,allow_err
};
use std::ffi::c_void;
use crate::sciter_session::SciterHandler;
pub struct Remote{
    video_queue_map: Arc<RwLock<HashMap<usize, ArrayQueue<VideoFrame>>>>,
    video_sender: MediaSender,
    receiver: mpsc::UnboundedReceiver<Data>,
    sender: mpsc::UnboundedSender<Data>,
}



#[tokio::main(flavor = "current_thread")]
pub async fn start_work(rendezvous_server:&str,  id:&str,key:&str,token:&str) {
    let (sender, mut receiver) = mpsc::unbounded_channel::<Data>();
    let frame_count_map: Arc<RwLock<HashMap<usize, usize>>> = Default::default();
    let frame_count_map_cl = frame_count_map.clone();
    let sciter_handler = Arc::new(Mutex::new(SciterHandler::default()));
    let sciter_handler_cl = Arc::clone(&sciter_handler);
    let (video_sender, video_queue_map, decode_fps) =
        start_video_audio_threads(
            move |display: usize,
                  data: &mut scrap::ImageRgb,
                  _texture: *mut c_void,
                  pixelbuffer: bool| {
                log::info!("video_callback has been called");
                let mut write_lock = frame_count_map_cl.write().unwrap();
                let count = write_lock.get(&display).unwrap_or(&0) + 1;
                write_lock.insert(display, count);
                drop(write_lock);
                let mut handler = sciter_handler_cl.lock().unwrap();
                Client::on_rgba(&handler, display, data);
            },
        );
    let mut remote = Remote::new(
        video_queue_map,
        video_sender,
        receiver,
        sender,
    );
    let mut handler = sciter_handler.lock().unwrap();
    remote.io_loop(&rendezvous_server,&handler, &id,&key, &token).await;    
}


impl Remote {
    pub fn new(
        video_queue: Arc<RwLock<HashMap<usize, ArrayQueue<VideoFrame>>>>,
        video_sender: MediaSender,
        receiver: mpsc::UnboundedReceiver<Data>,
        sender: mpsc::UnboundedSender<Data>,
    ) -> Self {
        Self {
            video_queue_map: video_queue,
            video_sender,
            receiver,
            sender,
        }
    }
    fn contains_key_frame(vf: &VideoFrame) -> bool {
        use video_frame::Union::*;
        match &vf.union {
            Some(vf) => match vf {
                Vp8s(f) | Vp9s(f) | Av1s(f) | H264s(f) | H265s(f) => f.frames.iter().any(|e| e.key),
                _ => false,
            },
            None => false,
        }
    }

    async fn handle_msg_from_peer(&mut self, data: &[u8], peer: &mut Stream,sciterHandler: &SciterHandler) -> bool {
        if let Ok(msg_in) = Message::parse_from_bytes(&data) {
            match msg_in.union {
                Some(message::Union::VideoFrame(vf)) => {
                    
                    let display = vf.display as usize;
                    let mut video_queue_write = self.video_queue_map.write().unwrap();
                    if !video_queue_write.contains_key(&display) {
                        video_queue_write.insert(
                            display,
                            ArrayQueue::<VideoFrame>::new(120),
                        );
                    }
                    if Self::contains_key_frame(&vf) {
                        log::info!("handle VideoFrame contains_key_frame");
                        if let Some(video_queue) = video_queue_write.get_mut(&display) {
                            while let Some(_) = video_queue.pop() {}
                        }
                        self.video_sender
                            .send(MediaData::VideoFrame(Box::new(vf)))
                            .ok();
                    } else {
                        log::info!("handle VideoFrame not contains_key_frame");
                        if let Some(video_queue) = video_queue_write.get_mut(&display) {
                            video_queue.force_push(vf);
                        }
                        self.video_sender.send(MediaData::VideoQueue(display)).ok();
                    }
                }
                Some(message::Union::Hash(hash)) => {
                    log::info!("handle Hash msg received: {:?}", hash);
                    Client::send_login(hash, peer).await;
                }
                // Some(message::Union::TestDelay(t)) =>{
                //     // log::info!("handle TestDelay msg received: {:?}", t);
                //     let mut msg_out = Message::new();
                //     msg_out.set_test_delay(t);
                //     allow_err!(peer.send(&msg_out).await);
                // }
                Some(message::Union::LoginResponse(lr)) => match lr.union {
                    Some(login_response::Union::PeerInfo(pi)) => {
                        Client::handle_peer_info(sciterHandler,pi);
                    }
                    _ => {}
                }
                Some(message::Union::Misc(misc)) => match misc.union {
                    Some(misc::Union::PermissionInfo(p)) => {
                        log::info!("Change permission {:?} -> {}", p.permission, p.enabled);
                        Client::send_permission(peer, Permission::Keyboard, p.enabled).await;;
                        match p.permission.enum_value() {
                            _ => {log::info!("handle_msg_from_peer  Unexpected  Permission msg received: {:?}", p.permission.enum_value());}
                        }
                    }
                    _ => {log::info!("handle_msg_from_peer  Unexpected  Misc msg received: {:?}", misc);}
                }
                _ => {log::info!("handle_msg_from_peer  Unexpected msg received: {:?}", msg_in);}
            }
        }
        true
    }

    pub async fn io_loop(&mut self, rendezvous_server:&str,sciterHandler: &SciterHandler,id:&str,key: &str, token: &str) {
        match Client::start(
            rendezvous_server,
            id,
            key,
            token,
            ConnType::default(),
        )
        .await
        {
            Ok(((mut peer, pk), (feedback, rendezvous_server))) => {
                log::info!("peer.local_addr(): {}", peer.local_addr());
                loop {
                    tokio::select! {
                        res = peer.next() => {
                            if let Some(res) = res {
                                match res {
                                    Err(err) => {
                                        log::error!("on_establish_connection_error closed: {err}");
                                        break;
                                    }
                                    Ok(ref bytes) => {
                                        if !self.handle_msg_from_peer(bytes, &mut peer,sciterHandler).await {
                                            break
                                        }
                                    }
                                }
                            } else {
                                break;
                            }
                        }
                    }
                }
                log::debug!("Exit io_loop ");
            }
            Err(err) => {
                log::error!("Connection closed: {err}");
            }
        }
    }
}