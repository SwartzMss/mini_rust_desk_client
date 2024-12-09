use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use mini_rust_desk_common::{
    allow_err,
    log,
    message_proto::*
};
use sciter::{
    dom::{
        event::{EventReason, BEHAVIOR_EVENTS, EVENT_GROUPS, PHASE_MASK},
        Element, HELEMENT,
    },
    make_args,
    video::{video_destination, AssetPtr, COLOR_SPACE},
    Value,
};
#[derive(Clone, Default)]
pub struct SciterHandler {
    element: Arc<Mutex<Option<Element>>>,
    close_state: HashMap<String, String>,
}
type Video = AssetPtr<video_destination>;

lazy_static::lazy_static! {
    static ref VIDEO: Arc<Mutex<Option<Video>>> = Default::default();
}

impl SciterHandler {
    #[inline]
    fn call(&self, func: &str, args: &[Value]) {
        if let Some(ref e) = self.element.lock().unwrap().as_ref() {
            allow_err!(e.call_method(func, args));
        }
    }

    fn set_display(&self, x: i32, y: i32, w: i32, h: i32, cursor_embedded: bool) {
        self.call("setDisplay", &make_args!(x, y, w, h, cursor_embedded));
        // https://sciter.com/forums/topic/color_spaceiyuv-crash
        // Nothing spectacular in decoder – done on CPU side.
        // So if you can do BGRA translation on your side – the better.
        // BGRA is used as internal image format so it will not require additional transformations.
        VIDEO.lock().unwrap().as_mut().map(|v| {
            v.stop_streaming().ok();
            let ok = v.start_streaming((w, h), COLOR_SPACE::Rgb32, None);
            log::info!("[video] reinitialized: {:?}", ok);
        });
    }
    /// 绑定 RGBA 数据
    pub fn on_rgba(&self, _display: usize, rgba: &mut scrap::ImageRgb) {
        VIDEO
            .lock()
            .unwrap()
            .as_mut()
            .map(|v| v.render_frame(&rgba.raw).ok());
        log::info!("[video] on_rgba:");
    }

    /// 初始化 SciterHandler 的根元素
    pub fn attached(&mut self, root: HELEMENT) {
        *self.element.lock().unwrap() = Some(Element::from(root));
        log::info!("Sciter element attached");
    }

    /// 解除绑定 SciterHandler 的根元素
    pub fn detached(&mut self) {
        *self.element.lock().unwrap() = None;
        log::info!("Sciter element detached");
    }

    pub fn handle_event(
        &mut self,
        _root: HELEMENT,
        source: HELEMENT,
        code: BEHAVIOR_EVENTS,
        phase: PHASE_MASK,
        reason: EventReason,
    ) -> bool {
        if phase != PHASE_MASK::BUBBLING {
            return false;
        }
        match code {
            BEHAVIOR_EVENTS::VIDEO_BIND_RQ => {
                if let EventReason::VideoBind(ptr) = reason {
                    if ptr.is_null() {
                        return true;
                    }
                    let site = AssetPtr::adopt(ptr as *mut video_destination);
                    log::info!("[video] start video");
                    *VIDEO.lock().unwrap() = Some(site);
                }
            }
            BEHAVIOR_EVENTS::VIDEO_STARTED => {
                log::info!("[video] Video started");
            }
            BEHAVIOR_EVENTS::VIDEO_STOPPED => {
                log::info!("[video] Video stopped");
            }
            _ => return false,
        }
        true
    }
}