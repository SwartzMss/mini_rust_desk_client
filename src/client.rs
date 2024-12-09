
use crossbeam_queue::ArrayQueue;
use mini_rust_desk_common::{
    allow_err,
    tcp::FramedStream,
    log,timeout,
    anyhow::{anyhow,Context},
    protobuf::Message as _,
    bail, rendezvous_proto::*,message_proto::{permission_info::Permission, *},
    socket_client::{connect_tcp,ipv4_to_ipv6,check_port}, ResultType, Stream,
    sodiumoxide::crypto::{box_, secretbox, sign},
    base64,
    bytes::Bytes,
};
use sha2::{Digest, Sha256};
use crate::sciter_session::*;
use std::ffi::c_void;
use std::sync::{Arc,RwLock,mpsc,Mutex};
use std::collections::HashMap;
pub struct Client;
use scrap::{
    codec::Decoder,
    record::Recorder,
    CodecFormat, ImageFormat,ImageRgb,
};

pub enum MediaData {
    VideoQueue(usize),
    VideoFrame(Box<VideoFrame>),
    Reset(Option<usize>),
}
pub type MediaSender = mpsc::Sender<MediaData>;


#[derive(Clone)]
pub enum Data {
    Close,
    Login((String, String, String, bool)),
    Message(Message),
}

pub async fn get_next_nonkeyexchange_msg(
    conn: &mut FramedStream,
    timeout: Option<u64>,
) -> Option<RendezvousMessage> {
    let timeout = timeout.unwrap_or(18_000);
    for _ in 0..2 {
        if let Some(Ok(bytes)) = conn.next_timeout(timeout).await {
            if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                match &msg_in.union {
                    Some(rendezvous_message::Union::KeyExchange(_)) => {
                        continue;
                    }
                    _ => {
                        return Some(msg_in);
                    }
                }
            }
        }
        break;
    }
    None
}
#[inline]
fn get_pk(pk: &[u8]) -> Option<[u8; 32]> {
    if pk.len() == 32 {
        let mut tmp = [0u8; 32];
        tmp[..].copy_from_slice(&pk);
        Some(tmp)
    } else {
        None
    }
}

pub fn decode_id_pk(signed: &[u8], key: &sign::PublicKey) -> ResultType<(String, [u8; 32])> {
    let res = IdPk::parse_from_bytes(
        &sign::verify(signed, key).map_err(|_| anyhow!("Signature mismatch"))?,
    )?;
    if let Some(pk) = get_pk(&res.pk) {
        Ok((res.id, pk))
    } else {
        bail!("Wrong their public length");
    }
}

#[inline]
pub fn decode64<T: AsRef<[u8]>>(input: T) -> Result<Vec<u8>, base64::DecodeError> {
    #[allow(deprecated)]
    base64::decode(input)
}

#[inline]
pub fn get_rs_pk(str_base64: &str) -> Option<sign::PublicKey> {
    if let Ok(pk) = decode64(str_base64) {
        get_pk(&pk).map(|x| sign::PublicKey(x))
    } else {
        None
    }
}

pub fn create_symmetric_key_msg(their_pk_b: [u8; 32]) -> (Bytes, Bytes, secretbox::Key) {
    let their_pk_b = box_::PublicKey(their_pk_b);
    let (our_pk_b, out_sk_b) = box_::gen_keypair();
    let key = secretbox::gen_key();
    let nonce = box_::Nonce([0u8; box_::NONCEBYTES]);
    let sealed_key = box_::seal(&key.0, &nonce, &their_pk_b, &out_sk_b);
    (Vec::from(our_pk_b.0).into(), sealed_key.into(), key)
}


impl Client{
    pub async fn start(
        rendezvous_server:&str,
        peer: &str,
        key: &str,
        token: &str,
        conn_type: ConnType,
    ) -> ResultType<((Stream, Option<Vec<u8>>), (i32, String))> {
        match Self::_start(rendezvous_server, peer, key, token, conn_type).await {
            Err(err) => {
                let err_str = err.to_string();
                if err_str.starts_with("Failed") {
                    bail!(err_str + ": Please try later");
                } else {
                    return Err(err);
                }
            }
            Ok(x) => Ok(x),
        }
    }
    pub async fn send_login(
        hash: Hash,
        peer: &mut Stream,
    ) {
        let mut hasher = Sha256::new();
        hasher.update("*Ab123456");
        hasher.update(&hash.salt);
        let mut hasher2 = Sha256::new();
        hasher2.update(&hasher.finalize()[..]);
        hasher2.update(&hash.challenge);
        let password: Vec<u8> = hasher2.finalize().to_vec();
        let lr = LoginRequest {
            username:"417866831".to_owned(),
            version: "1.1.0".to_owned(),
            password: password.into(),
            os_login: Some(OSLogin {
                ..Default::default()
            })
            .into(),
            ..Default::default()
        };
        let mut msg_out = Message::new();
        msg_out.set_login_request(lr);
        allow_err!(peer.send(&msg_out).await);
    }

    pub fn on_rgba(handler:&SciterHandler,display: usize, rgba: &mut scrap::ImageRgb)
    {
        handler.on_rgba(display, rgba);
    }

    pub fn handle_peer_info(handler:&SciterHandler,mut pi: PeerInfo) {
        log::info!("handle_peer_info :{:?}", pi);
        let current = &pi.displays[pi.current_display as usize];

    }

    pub async fn send_permission(peer: &mut Stream, permission: Permission, enabled: bool) {
        let mut misc = Misc::new();
        misc.set_permission_info(PermissionInfo {
            permission: permission.into(),
            enabled,
            ..Default::default()
        });
        let mut msg_out = Message::new();
        msg_out.set_misc(misc);
        allow_err!(peer.send(&msg_out).await);
    }

    async fn _start(
        rendezvous_server:&str,
        peer: &str,
        key: &str,
        token: &str,
        conn_type: ConnType,
     ) -> ResultType<((Stream, Option<Vec<u8>>), (i32, String))> {
       let socket = connect_tcp(rendezvous_server, 18_000).await;
       if socket.is_err(){
            bail!("connect failed {}",rendezvous_server);
       }
       let mut socket = socket?;

       let my_addr = socket.local_addr();
       let mut signed_id_pk = Vec::new();
       let start = std::time::Instant::now();
       let mut feedback = 0;
       let mut msg_out = RendezvousMessage::new();
       msg_out.set_punch_hole_request(PunchHoleRequest {
        id: peer.to_owned(),
        token: token.to_owned(),
        nat_type: NatType::ASYMMETRIC.into(),
        licence_key: key.to_owned(),
        conn_type: conn_type.into(),
        version: "1.3.2".to_owned(),
        ..Default::default()
        });

        socket.send(&msg_out).await?;
        if let Some(msg_in) = get_next_nonkeyexchange_msg(&mut socket, Some(6000)).await
        {
            match msg_in.union {
                Some(rendezvous_message::Union::RelayResponse(rr)) => {
                    log::info!(
                        "relay requested from peer, time used: {:?}, relay_server: {}",
                        start.elapsed(),
                        rr.relay_server
                    );
                    signed_id_pk = rr.pk().into();
                    let mut conn = Self::create_relay(
                        peer,
                        rr.uuid,
                        rr.relay_server,
                        key,
                        conn_type,
                        my_addr.is_ipv4(),
                    )
                    .await?;
                    feedback = rr.feedback;
                    let pk =
                        Self::secure_connection(peer, signed_id_pk, key, &mut conn).await?;
                    return Ok(((conn, pk), (feedback, rendezvous_server.to_string())));
                }
                _ => {
                    bail!("Unexpected protobuf msg received: {:?}", msg_in);
                }
            }
        }
        bail!("unexpected failure");
    }

    async fn secure_connection(
        peer_id: &str,
        signed_id_pk: Vec<u8>,
        key: &str,
        conn: &mut Stream,
    ) -> ResultType<Option<Vec<u8>>> {
        let rs_pk = get_rs_pk(if key.is_empty() {
            pub const PUBLIC_RS_PUB_KEY: &str = "OeVuKk5nlHiXp+APNn0Y3pC1Iwpwn44JGqrQCsWqmBw=";
            PUBLIC_RS_PUB_KEY
        } else {
            key
        });
        let mut sign_pk = None;
        let mut option_pk = None;
        if !signed_id_pk.is_empty() {
            if let Some(rs_pk) = rs_pk {
                if let Ok((id, pk)) = decode_id_pk(&signed_id_pk, &rs_pk) {
                    if id == peer_id {
                        sign_pk = Some(sign::PublicKey(pk));
                        option_pk = Some(pk.to_vec());
                    }
                }
            }
            if sign_pk.is_none() {
                log::error!("Handshake failed: invalid public key from rendezvous server");
            }
        }
        let sign_pk = match sign_pk {
            Some(v) => v,
            None => {
                // send an empty message out in case server is setting up secure and waiting for first message
                conn.send(&Message::new()).await?;
                return Ok(option_pk);
            }
        };
        match timeout(18_000, conn.next()).await? {
            Some(res) => {
                let bytes = res?;
                if let Ok(msg_in) = Message::parse_from_bytes(&bytes) {
                    if let Some(message::Union::SignedId(si)) = msg_in.union {
                        if let Ok((id, their_pk_b)) = decode_id_pk(&si.id, &sign_pk) {
                            if id == peer_id {
                                let (asymmetric_value, symmetric_value, key) =
                                    create_symmetric_key_msg(their_pk_b);
                                let mut msg_out = Message::new();
                                msg_out.set_public_key(PublicKey {
                                    asymmetric_value,
                                    symmetric_value,
                                    ..Default::default()
                                });
                                timeout(18_000, conn.send(&msg_out)).await??;
                                conn.set_key(key);
                            } else {
                                log::error!("Handshake failed: sign failure");
                                conn.send(&Message::new()).await?;
                            }
                        } else {
                            // fall back to non-secure connection in case pk mismatch
                            log::info!("pk mismatch, fall back to non-secure");
                            let mut msg_out = Message::new();
                            msg_out.set_public_key(PublicKey::new());
                            conn.send(&msg_out).await?;
                        }
                    } else {
                        log::error!("Handshake failed: invalid message type");
                        conn.send(&Message::new()).await?;
                    }
                } else {
                    log::error!("Handshake failed: invalid message format");
                    conn.send(&Message::new()).await?;
                }
            }
            None => {
                bail!("Reset by the peer");
            }
        }
        Ok(option_pk)
    }


    async fn create_relay(
        peer: &str,
        uuid: String,
        relay_server: String,
        key: &str,
        conn_type: ConnType,
        ipv4: bool,
    ) -> ResultType<Stream> {
        let mut conn = connect_tcp(
            ipv4_to_ipv6(check_port(relay_server, 21117 ), ipv4),
            18_000,
        )
        .await
        .with_context(|| "Failed to connect to relay server")?;
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_request_relay(RequestRelay {
            licence_key: key.to_owned(),
            id: peer.to_owned(),
            uuid,
            conn_type: conn_type.into(),
            ..Default::default()
        });
        conn.send(&msg_out).await?;
        Ok(conn)
    }
}



pub struct VideoHandler {
    decoder: Decoder,
    pub rgb: ImageRgb,
    pub texture: *mut c_void,
    _display: usize, // useful for debug
    fail_counter: usize,
    first_frame: bool,
}

impl VideoHandler {
    pub fn get_adapter_luid() -> Option<i64> {
        None
    }

    /// Create a new video handler.
    pub fn new(format: CodecFormat, _display: usize) -> Self {
        let luid = Self::get_adapter_luid();
        log::info!("new video handler for display #{_display}, format: {format:?}, luid: {luid:?}");
        VideoHandler {
            decoder: Decoder::new(format, luid),
            rgb: ImageRgb::new(ImageFormat::ARGB, 1),
            texture: std::ptr::null_mut(),
            _display,
            fail_counter: 0,
            first_frame: true,
        }
    }

    /// Handle a new video frame.
    #[inline]
    pub fn handle_frame(
        &mut self,
        vf: VideoFrame,
        pixelbuffer: &mut bool,
        chroma: &mut Option<Chroma>,
    ) -> ResultType<bool> {
        let format = CodecFormat::from(&vf);
        if format != self.decoder.format() {
            self.reset(Some(format));
        }
        match &vf.union {
            Some(frame) => {
                let res = self.decoder.handle_video_frame(
                    frame,
                    &mut self.rgb,
                    &mut self.texture,
                    pixelbuffer,
                    chroma,
                );
                if res.as_ref().is_ok_and(|x| *x) {
                    self.fail_counter = 0;
                } else {
                    if self.fail_counter < usize::MAX {
                        if self.first_frame && self.fail_counter < 3 {
                            log::error!("decode first frame failed");
                            self.fail_counter = 3;
                        } else {
                            self.fail_counter += 1;
                        }
                        log::error!(
                            "Failed to handle video frame, fail counter: {}",
                            self.fail_counter
                        );
                    }
                }
                self.first_frame = false;
                res
            }
            _ => Ok(false),
        }
    }

    pub fn reset(&mut self, format: Option<CodecFormat>) {
        log::info!(
            "reset video handler for display #{}, format: {format:?}",
            self._display
        );
        let luid = Self::get_adapter_luid();
        let format = format.unwrap_or(self.decoder.format());
        self.decoder = Decoder::new(format, luid);
        self.fail_counter = 0;
        self.first_frame = true;
    }


}

struct VideoHandlerController {
    handler: VideoHandler,
    skip_beginning: u32,
}

pub fn start_video_audio_threads<F>(
    video_callback: F,
) -> (
    MediaSender,
    Arc<RwLock<HashMap<usize, ArrayQueue<VideoFrame>>>>,
    Arc<RwLock<Option<usize>>>,
)
where
    F: 'static + FnMut(usize, &mut scrap::ImageRgb, *mut c_void, bool) + Send,
{
    let (video_sender, video_receiver) = mpsc::channel::<MediaData>();
    let video_queue_map: Arc<RwLock<HashMap<usize, ArrayQueue<VideoFrame>>>> = Default::default();
    let video_queue_map_cloned = video_queue_map.clone();
    let mut video_callback = video_callback;

    let fps = Arc::new(RwLock::new(None));
    let decode_fps_map = fps.clone();

    std::thread::spawn(move || {
        let mut handler_controller_map = HashMap::new();
        loop {
            if let Ok(data) = video_receiver.recv() {
                match data {
                    MediaData::VideoFrame(_) | MediaData::VideoQueue(_) => {
                        let vf = match data {
                            MediaData::VideoFrame(vf) => *vf,
                            MediaData::VideoQueue(display) => {
                                if let Some(video_queue) =
                                    video_queue_map.read().unwrap().get(&display)
                                {
                                    if let Some(vf) = video_queue.pop() {
                                        vf
                                    } else {
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                            }
                            _ => {
                                continue;
                            }
                        };
                        let display = vf.display as usize;
                        let format = scrap::CodecFormat::from(&vf);
                        if !handler_controller_map.contains_key(&display) {
                            handler_controller_map.insert(
                                display,
                                VideoHandlerController {
                                    handler: VideoHandler::new(format, display),
                                    skip_beginning: 0,
                                },
                            );
                        }
                        if let Some(handler_controller) = handler_controller_map.get_mut(&display) {
                            let mut pixelbuffer = true;
                            let mut tmp_chroma = None;
                            match handler_controller.handler.handle_frame(
                                vf,
                                &mut pixelbuffer,
                                &mut tmp_chroma,
                            ) {
                                Ok(true) => {
                                    video_callback(
                                        display,
                                        &mut handler_controller.handler.rgb,
                                        handler_controller.handler.texture,
                                        pixelbuffer,
                                    );

                                }
                                Err(e) => {
                                    log::error!("handle video frame error, {}", e);
                                }
                                _ => {}
                            }
                        }
                    }
                    MediaData::Reset(display) => {
                        if let Some(display) = display {
                            if let Some(handler_controler) =
                                handler_controller_map.get_mut(&display)
                            {
                                handler_controler.handler.reset(None);
                            }
                        } else {
                            for (_, handler_controler) in handler_controller_map.iter_mut() {
                                handler_controler.handler.reset(None);
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                break;
            }
        }
        log::info!("Video decoder loop exits");
    });
    return (
        video_sender,
        video_queue_map_cloned,
        decode_fps_map,
    );
}
