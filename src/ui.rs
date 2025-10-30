use std::{
    collections::HashMap,
    iter::FromIterator,
    sync::{Arc, Mutex},
};

use sciter::Value;

use hbb_common::{
    allow_err,
    config::{LocalConfig, PeerConfig},
    log,
};

#[cfg(not(any(feature = "flutter", feature = "cli")))]
use crate::ui_session_interface::Session;
use crate::{common::get_app_name, ipc, ui_interface::*};

mod cm;
#[cfg(feature = "inline")]
pub mod inline;
pub mod remote;

#[allow(dead_code)]
type Status = (i32, bool, i64, String);

lazy_static::lazy_static! {
    // stupid workaround for https://sciter.com/forums/topic/crash-on-latest-tis-mac-sdk-sometimes/
    static ref STUPID_VALUES: Mutex<Vec<Arc<Vec<Value>>>> = Default::default();
}

#[cfg(not(any(feature = "flutter", feature = "cli")))]
lazy_static::lazy_static! {
    pub static ref CUR_SESSION: Arc<Mutex<Option<Session<remote::SciterHandler>>>> = Default::default();
}

struct UIHostHandler;

pub fn start(args: &mut [String]) {
    #[cfg(target_os = "macos")]
    crate::platform::delegate::show_dock();
    #[cfg(all(target_os = "linux", feature = "inline"))]
    {
        let app_dir = std::env::var("APPDIR").unwrap_or("".to_string());
        let mut so_path = "/usr/share/rustdesk/libsciter-gtk.so".to_owned();
        for (prefix, dir) in [
            ("", "/usr"),
            ("", "/app"),
            (&app_dir, "/usr"),
            (&app_dir, "/app"),
        ]
        .iter()
        {
            let path = format!("{prefix}{dir}/share/rustdesk/libsciter-gtk.so");
            if std::path::Path::new(&path).exists() {
                so_path = path;
                break;
            }
        }
        sciter::set_library(&so_path).ok();
    }
    #[cfg(windows)]
    // Check if there is a sciter.dll nearby.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            let sciter_dll_path = parent.join("sciter.dll");
            if sciter_dll_path.exists() {
                // Try to set the sciter dll.
                let p = sciter_dll_path.to_string_lossy().to_string();
                log::debug!("Found dll:{}, \n {:?}", p, sciter::set_library(&p));
            }
        }
    }
    // https://github.com/c-smile/sciter-sdk/blob/master/include/sciter-x-types.h
    // https://github.com/rustdesk/rustdesk/issues/132#issuecomment-886069737
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::GfxLayer(
        sciter::GFX_LAYER::WARP
    )));
    use sciter::SCRIPT_RUNTIME_FEATURES::*;
    allow_err!(sciter::set_options(sciter::RuntimeOptions::ScriptFeatures(
        ALLOW_FILE_IO as u8 | ALLOW_SOCKET_IO as u8 | ALLOW_EVAL as u8 | ALLOW_SYSINFO as u8
    )));
    let mut frame = sciter::WindowBuilder::main_window().create();
    #[cfg(windows)]
    allow_err!(sciter::set_options(sciter::RuntimeOptions::UxTheming(true)));
    frame.set_title(&crate::get_app_name());
    #[cfg(target_os = "macos")]
    crate::platform::delegate::make_menubar(frame.get_host(), args.is_empty());
    #[cfg(windows)]
    crate::platform::try_set_window_foreground(frame.get_hwnd() as _);
    let page;
    if args.len() > 1 && args[0] == "--play" {
        args[0] = "--connect".to_owned();
        let path: std::path::PathBuf = (&args[1]).into();
        let id = path
            .file_stem()
            .map(|p| p.to_str().unwrap_or(""))
            .unwrap_or("")
            .to_owned();
        args[1] = id;
    }
    if args.is_empty() {
        std::thread::spawn(move || check_zombie());
        crate::common::check_software_update();
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "index.html";
        // Start pulse audio local server.
        #[cfg(target_os = "linux")]
        std::thread::spawn(crate::ipc::start_pa);
    } else if args[0] == "--install" {
        frame.event_handler(UI {});
        frame.sciter_handler(UIHostHandler {});
        page = "install.html";
    } else if args[0] == "--cm" {
        frame.register_behavior("connection-manager", move || {
            Box::new(cm::SciterConnectionManager::new())
        });
        page = "cm.html";
        *cm::HIDE_CM.lock().unwrap() = crate::ipc::get_config("hide_cm")
            .ok()
            .flatten()
            .unwrap_or_default()
            == "true";
    } else if (args[0] == "--connect"
        || args[0] == "--file-transfer"
        || args[0] == "--port-forward"
        || args[0] == "--rdp")
        && args.len() > 1
    {
        #[cfg(windows)]
        {
            let hw = frame.get_host().get_hwnd();
            crate::platform::windows::enable_lowlevel_keyboard(hw as _);
        }
        let mut iter = args.iter();
        let Some(cmd) = iter.next() else {
            log::error!("Failed to get cmd arg");
            return;
        };
        let cmd = cmd.to_owned();
        let Some(id) = iter.next() else {
            log::error!("Failed to get id arg");
            return;
        };
        let id = id.to_owned();
        let pass = iter.next().unwrap_or(&"".to_owned()).clone();
        let args: Vec<String> = iter.map(|x| x.clone()).collect();
        frame.set_title(&id);
        frame.register_behavior("native-remote", move || {
            let handler =
                remote::SciterSession::new(cmd.clone(), id.clone(), pass.clone(), args.clone());
            #[cfg(not(any(feature = "flutter", feature = "cli")))]
            {
                *CUR_SESSION.lock().unwrap() = Some(handler.inner());
            }
            Box::new(handler)
        });
        page = "remote.html";
    } else {
        log::error!("Wrong command: {:?}", args);
        return;
    }
    #[cfg(feature = "inline")]
    {
        let html = if page == "index.html" {
            inline::get_index()
        } else if page == "cm.html" {
            inline::get_cm()
        } else if page == "install.html" {
            inline::get_install()
        } else {
            inline::get_remote()
        };
        frame.load_html(html.as_bytes(), Some(page));
    }
    #[cfg(not(feature = "inline"))]
    frame.load_file(&format!(
        "file://{}/src/ui/{}",
        std::env::current_dir()
            .map(|c| c.display().to_string())
            .unwrap_or("".to_owned()),
        page
    ));
    let hide_cm = *cm::HIDE_CM.lock().unwrap();
    if !args.is_empty() && args[0] == "--cm" && hide_cm {
        // run_app calls expand(show) + run_loop, we use collapse(hide) + run_loop instead to create a hidden window
        frame.collapse(true);
        frame.run_loop();
        return;
    }
    frame.run_app();
}

struct UI {}

impl UI {
    fn recent_sessions_updated(&self) -> bool {
        recent_sessions_updated()
    }

    fn get_id(&self) -> String {
        ipc::get_id()
    }

    fn temporary_password(&mut self) -> String {
        temporary_password()
    }

    fn update_temporary_password(&self) {
        update_temporary_password()
    }

    fn permanent_password(&self) -> String {
        permanent_password()
    }

    fn set_permanent_password(&self, password: String) {
        set_permanent_password(password);
    }

    fn get_remote_id(&mut self) -> String {
        LocalConfig::get_remote_id()
    }

    fn set_remote_id(&mut self, id: String) {
        LocalConfig::set_remote_id(&id);
    }

    fn goto_install(&mut self) {
        goto_install();
    }

    fn install_me(&mut self, _options: String, _path: String) {
        install_me(_options, _path, false, false);
    }

    fn update_me(&self, _path: String) {
        update_me(_path);
    }

    fn run_without_install(&self) {
        run_without_install();
    }

    fn show_run_without_install(&self) -> bool {
        show_run_without_install()
    }

    fn get_license(&self) -> String {
        get_license()
    }

    fn get_option(&self, key: String) -> String {
        get_option(key)
    }

    fn get_local_option(&self, key: String) -> String {
        get_local_option(key)
    }

    fn set_local_option(&self, key: String, value: String) {
        set_local_option(key, value);
    }

    fn peer_has_password(&self, id: String) -> bool {
        peer_has_password(id)
    }

    fn forget_password(&self, id: String) {
        forget_password(id)
    }

    fn get_peer_option(&self, id: String, name: String) -> String {
        get_peer_option(id, name)
    }

    fn set_peer_option(&self, id: String, name: String, value: String) {
        set_peer_option(id, name, value)
    }

    fn using_public_server(&self) -> bool {
        crate::using_public_server()
    }

    fn get_options(&self) -> Value {
        let hashmap: HashMap<String, String> =
            serde_json::from_str(&get_options()).unwrap_or_default();
        let mut m = Value::map();
        for (k, v) in hashmap {
            m.set_item(k, v);
        }
        m
    }

    fn test_if_valid_server(&self, host: String, test_with_proxy: bool) -> String {
        test_if_valid_server(host, test_with_proxy)
    }

    fn get_sound_inputs(&self) -> Value {
        Value::from_iter(get_sound_inputs())
    }

    fn set_options(&self, v: Value) {
        let mut m = HashMap::new();
        for (k, v) in v.items() {
            if let Some(k) = k.as_string() {
                if let Some(v) = v.as_string() {
                    if !v.is_empty() {
                        m.insert(k, v);
                    }
                }
            }
        }
        set_options(m);
    }

    fn set_option(&self, key: String, value: String) {
        set_option(key, value);
    }

    fn install_path(&mut self) -> String {
        install_path()
    }

    fn install_options(&self) -> String {
        install_options()
    }

    fn get_socks(&self) -> Value {
        Value::from_iter(get_socks())
    }

    fn set_socks(&self, proxy: String, username: String, password: String) {
        set_socks(proxy, username, password)
    }

    fn is_installed(&self) -> bool {
        is_installed()
    }

    fn is_root(&self) -> bool {
        is_root()
    }

    fn is_release(&self) -> bool {
        #[cfg(not(debug_assertions))]
        return true;
        #[cfg(debug_assertions)]
        return false;
    }

    fn is_share_rdp(&self) -> bool {
        is_share_rdp()
    }

    fn set_share_rdp(&self, _enable: bool) {
        set_share_rdp(_enable);
    }

    fn is_installed_lower_version(&self) -> bool {
        is_installed_lower_version()
    }

    fn closing(&mut self, x: i32, y: i32, w: i32, h: i32) {
        crate::server::input_service::fix_key_down_timeout_at_exit();
        LocalConfig::set_size(x, y, w, h);
    }

    fn get_size(&mut self) -> Value {
        let s = LocalConfig::get_size();
        let mut v = Vec::new();
        v.push(s.0);
        v.push(s.1);
        v.push(s.2);
        v.push(s.3);
        Value::from_iter(v)
    }

    fn get_mouse_time(&self) -> f64 {
        get_mouse_time()
    }

    fn check_mouse_time(&self) {
        check_mouse_time()
    }

    fn get_connect_status(&mut self) -> Value {
        let mut v = Value::array(0);
        let x = get_connect_status();
        v.push(x.status_num);
        v.push(x.key_confirmed);
        v.push(x.id);
        v
    }

    #[inline]
    fn get_peer_value(id: String, p: PeerConfig) -> Value {
        let values = vec![
            id,
            p.info.username.clone(),
            p.info.hostname.clone(),
            p.info.platform.clone(),
            p.options.get("alias").unwrap_or(&"".to_owned()).to_owned(),
        ];
        Value::from_iter(values)
    }

    fn get_peer(&self, id: String) -> Value {
        let c = get_peer(id.clone());
        Self::get_peer_value(id, c)
    }

    fn get_fav(&self) -> Value {
        Value::from_iter(get_fav())
    }

    fn store_fav(&self, fav: Value) {
        let mut tmp = vec![];
        fav.values().for_each(|v| {
            if let Some(v) = v.as_string() {
                if !v.is_empty() {
                    tmp.push(v);
                }
            }
        });
        store_fav(tmp);
    }

    fn get_recent_sessions(&mut self) -> Value {
        // to-do: limit number of recent sessions, and remove old peer file
        let peers: Vec<Value> = PeerConfig::peers(None)
            .drain(..)
            .map(|p| Self::get_peer_value(p.0, p.2))
            .collect();
        Value::from_iter(peers)
    }

    fn get_icon(&mut self) -> String {
        get_icon()
    }

    fn remove_peer(&mut self, id: String) {
        PeerConfig::remove(&id);
    }

    fn remove_discovered(&mut self, id: String) {
        remove_discovered(id);
    }

    fn send_wol(&mut self, id: String) {
        crate::lan::send_wol(id)
    }

    fn new_remote(&mut self, id: String, remote_type: String, force_relay: bool) {
        new_remote(id, remote_type, force_relay)
    }

    fn is_process_trusted(&mut self, _prompt: bool) -> bool {
        is_process_trusted(_prompt)
    }

    fn is_can_screen_recording(&mut self, _prompt: bool) -> bool {
        is_can_screen_recording(_prompt)
    }

    fn is_installed_daemon(&mut self, _prompt: bool) -> bool {
        is_installed_daemon(_prompt)
    }

    fn get_error(&mut self) -> String {
        get_error()
    }

    fn is_login_wayland(&mut self) -> bool {
        is_login_wayland()
    }

    fn current_is_wayland(&mut self) -> bool {
        current_is_wayland()
    }

    fn get_software_update_url(&self) -> String {
        crate::SOFTWARE_UPDATE_URL.lock().unwrap().clone()
    }

    fn get_new_version(&self) -> String {
        get_new_version()
    }

    fn get_version(&self) -> String {
        get_version()
    }

    fn get_fingerprint(&self) -> String {
        get_fingerprint()
    }

    fn get_app_name(&self) -> String {
        get_app_name()
    }

    fn get_software_ext(&self) -> String {
        #[cfg(windows)]
        let p = "exe";
        #[cfg(target_os = "macos")]
        let p = "dmg";
        #[cfg(target_os = "linux")]
        let p = "deb";
        p.to_owned()
    }

    fn get_software_store_path(&self) -> String {
        let mut p = std::env::temp_dir();
        let name = crate::SOFTWARE_UPDATE_URL
            .lock()
            .unwrap()
            .split("/")
            .last()
            .map(|x| x.to_owned())
            .unwrap_or(crate::get_app_name());
        p.push(name);
        format!("{}.{}", p.to_string_lossy(), self.get_software_ext())
    }

    fn create_shortcut(&self, _id: String) {
        #[cfg(windows)]
        create_shortcut(_id)
    }

    fn discover(&self) {
        std::thread::spawn(move || {
            allow_err!(crate::lan::discover());
        });
    }

    fn get_lan_peers(&self) -> String {
        // let peers = get_lan_peers()
        //     .into_iter()
        //     .map(|mut peer| {
        //         (
        //             peer.remove("id").unwrap_or_default(),
        //             peer.remove("username").unwrap_or_default(),
        //             peer.remove("hostname").unwrap_or_default(),
        //             peer.remove("platform").unwrap_or_default(),
        //         )
        //     })
        //     .collect::<Vec<(String, String, String, String)>>();
        serde_json::to_string(&get_lan_peers()).unwrap_or_default()
    }

    fn get_uuid(&self) -> String {
        get_uuid()
    }

    fn open_url(&self, url: String) {
        #[cfg(windows)]
        let p = "explorer";
        #[cfg(target_os = "macos")]
        let p = "open";
        #[cfg(target_os = "linux")]
        let p = if std::path::Path::new("/usr/bin/firefox").exists() {
            "firefox"
        } else {
            "xdg-open"
        };
        allow_err!(std::process::Command::new(p).arg(url).spawn());
    }

    fn change_id(&self, id: String) {
        reset_async_job_status();
        let old_id = self.get_id();
        change_id_shared(id, old_id);
    }

    fn http_request(&self, url: String, method: String, body: Option<String>, header: String) {
        http_request(url, method, body, header)
    }

    fn post_request(&self, url: String, body: String, header: String) {
        post_request(url, body, header)
    }

    fn is_ok_change_id(&self) -> bool {
        hbb_common::machine_uid::get().is_ok()
    }

    fn get_async_job_status(&self) -> String {
        get_async_job_status()
    }

    fn get_http_status(&self, url: String) -> Option<String> {
        get_async_http_status(url)
    }

    fn t(&self, name: String) -> String {
        crate::client::translate(name)
    }

    fn is_xfce(&self) -> bool {
        crate::platform::is_xfce()
    }

    fn get_api_server(&self) -> String {
        get_api_server()
    }

    fn has_hwcodec(&self) -> bool {
        has_hwcodec()
    }

    fn has_vram(&self) -> bool {
        has_vram()
    }

    fn get_langs(&self) -> String {
        get_langs()
    }

    fn video_save_directory(&self, root: bool) -> String {
        video_save_directory(root)
    }

    fn handle_relay_id(&self, id: String) -> String {
        handle_relay_id(&id).to_owned()
    }

    fn get_login_device_info(&self) -> String {
        get_login_device_info_json()
    }

    fn support_remove_wallpaper(&self) -> bool {
        support_remove_wallpaper()
    }

    fn has_valid_2fa(&self) -> bool {
        has_valid_2fa()
    }

    fn generate2fa(&self) -> String {
        generate2fa()
    }

    pub fn verify2fa(&self, code: String) -> bool {
        verify2fa(code)
    }

    fn verify_login(&self, raw: String, id: String) -> bool {
        crate::verify_login(&raw, &id)
    }

    fn generate_2fa_img_src(&self, data: String) -> String {
        let v = qrcode_generator::to_png_to_vec(data, qrcode_generator::QrCodeEcc::Low, 128)
            .unwrap_or_default();
        let s = hbb_common::sodiumoxide::base64::encode(
            v,
            hbb_common::sodiumoxide::base64::Variant::Original,
        );
        format!("data:image/png;base64,{s}")
    }

    pub fn check_hwcodec(&self) {
        check_hwcodec()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn get_id();
        fn temporary_password();
        fn update_temporary_password();
        fn permanent_password();
        fn set_permanent_password(String);
        fn get_remote_id();
        fn set_remote_id(String);
        fn closing(i32, i32, i32, i32);
        fn get_size();
        fn new_remote(String, String, bool);
        fn send_wol(String);
        fn remove_peer(String);
        fn remove_discovered(String);
        fn get_connect_status();
        fn get_mouse_time();
        fn check_mouse_time();
        fn get_recent_sessions();
        fn get_peer(String);
        fn get_fav();
        fn store_fav(Value);
        fn recent_sessions_updated();
        fn get_icon();
        fn install_me(String, String);
        fn is_installed();
        fn is_root();
        fn is_release();
        fn set_socks(String, String, String);
        fn get_socks();
        fn is_share_rdp();
        fn set_share_rdp(bool);
        fn is_installed_lower_version();
        fn install_path();
        fn install_options();
        fn goto_install();
        fn is_process_trusted(bool);
        fn is_can_screen_recording(bool);
        fn is_installed_daemon(bool);
        fn get_error();
        fn is_login_wayland();
        fn current_is_wayland();
        fn get_options();
        fn get_option(String);
        fn get_local_option(String);
        fn set_local_option(String, String);
        fn get_peer_option(String, String);
        fn peer_has_password(String);
        fn forget_password(String);
        fn set_peer_option(String, String, String);
        fn get_license();
        fn test_if_valid_server(String, bool);
        fn get_sound_inputs();
        fn set_options(Value);
        fn set_option(String, String);
        fn get_software_update_url();
        fn get_new_version();
        fn get_version();
        fn get_fingerprint();
        fn update_me(String);
        fn show_run_without_install();
        fn run_without_install();
        fn get_app_name();
        fn get_software_store_path();
        fn get_software_ext();
        fn open_url(String);
        fn change_id(String);
        fn get_async_job_status();
        fn post_request(String, String, String);
        fn is_ok_change_id();
        fn create_shortcut(String);
        fn discover();
        fn get_lan_peers();
        fn get_uuid();
        fn has_hwcodec();
        fn has_vram();
        fn get_langs();
        fn video_save_directory(bool);
        fn handle_relay_id(String);
        fn get_login_device_info();
        fn support_remove_wallpaper();
        fn has_valid_2fa();
        fn generate2fa();
        fn generate_2fa_img_src(String);
        fn verify2fa(String);
        fn check_hwcodec();
        fn verify_login(String, String);
    }
}

impl sciter::host::HostHandler for UIHostHandler {
    fn on_graphics_critical_failure(&mut self) {
        log::error!("Critical rendering error: e.g. DirectX gfx driver error. Most probably bad gfx drivers.");
    }
}

#[cfg(not(target_os = "linux"))]
fn get_sound_inputs() -> Vec<String> {
    let mut out = Vec::new();
    use cpal::traits::{DeviceTrait, HostTrait};
    let host = cpal::default_host();
    if let Ok(devices) = host.devices() {
        for device in devices {
            if device.default_input_config().is_err() {
                continue;
            }
            if let Ok(name) = device.name() {
                out.push(name);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn get_sound_inputs() -> Vec<String> {
    crate::platform::linux::get_pa_sources()
        .drain(..)
        .map(|x| x.1)
        .collect()
}

// sacrifice some memory
pub fn value_crash_workaround(values: &[Value]) -> Arc<Vec<Value>> {
    let persist = Arc::new(values.to_vec());
    STUPID_VALUES.lock().unwrap().push(persist.clone());
    persist
}

pub fn get_icon() -> String {
    // 128x128
    #[cfg(target_os = "macos")]
    // 128x128 on 160x160 canvas, then shrink to 128, mac looks better with padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAYAAABS3GwHAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyVpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDYuMC1jMDA2IDc5LjE2NDc1MywgMjAyMS8wMi8xNS0xMTo1MjoxMyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIDIyLjMgKE1hY2ludG9zaCkiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6ODJDQkY5NzU3NzAzMTFFRjg1RTdDQjY1MjUwMTREM0UiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6ODJDQkY5NzY3NzAzMTFFRjg1RTdDQjY1MjUwMTREM0UiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpENzg1M0IwQzc3MDIxMUVGODVFN0NCNjUyNTAxNEQzRSIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDo4MkNCRjk3NDc3MDMxMUVGODVFN0NCNjUyNTAxNEQzRSIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PqsNNtkAABgXSURBVHja7J0JeFPXlcePn2XZyPKCd2OwwZjEbIEYwhISp9Nl0nT60U6apgWGBDJNQ0NSStIyNJCUTprETSclHQoJJGlahgmknbZpZtpMOzP9SAhgwu4AAbNjbIzxhhdZyLI85+hKIMuSLVnvSVdP5/99+nQlPctP7/3vvb9zVwAABW5I8Xj29b73Z4Gmh/p3waQhStOgg9+gh3sw+AdDNDSLJa18lewOlY2rdQ2gx/vA6TClFS9DObwyga9HsP/M4fGsRTpciKV1BuZ0BNOKxiUWi2sAqWsAR5A3xeEDmfylWSxpZfBharVLJu/v5nR/3GRJWBVHS/XOYqluTgBu1uQYIAbSBh9VciBII9tNZgRiMQKxWIxAjECcDqEjzPO9gTqegnlwTcCZIBrSjBes2K6Co30oAZf+nB4yAoGflhVfCMSBKmcCRiAWSw+K82F6zdu/16xZ40yXlJRAe3s7ZGZmKr29vRAXJ04nmLTns/MHRVna/XtiUR0dHY7ExETo7OyEuro6T/+ByyOexKFJOm6AEt8RQFUdkPDHgMlkgqysLHpWEhISFIfD4XzQ95EJDAYDF0cxpJ6eHmEyh4PSlBEcWBg60AeOa9euOZqammDFihWaF8hxfgyuSu8k5eLCwkJISkpS4uPjDWh0ehjxBxtzc3NTU1JSzJgZkvAzo6s0ZPyKAdG9xocDfWBDs1ubm5vb0PwWvP82eg8zgR0zht1isdgvX74MoGFveVxFRQWsXLlSdQR68cUXAU2uoPkNZHj8UabS0tLiUaNG3YPvzcDXxYqiZOCPNuPhRjcWBItA0Z6Opd/qTntkBCs+OtDsjd3d3ccxE+w+duzYXxtQREj4N1Y7qrW11e7OBEuXLpUfgcj82dnZSnJychL+QPPMmTNn5eXlPW40Gj/FpTxrIGFmsGJs8E51dfWbZ86cOY5+abPZbJRRbPTxwoUL5UYgrFEUZH0FWd80fPjwrDlz5jxpNpsX4UcmLYLJqG+FiOIAXss0UkNDbW3t2t27d7+DiNyItNCBSGQ7ffq0qkhkoADV3SoTam5av369s0UHT96Unp6eU15e/hzmg/u9WzvUTjMC6S+Nps9BXH4W30veuXPn2/i6njIBFqo29/1ftmxZyAik+DH/kDq8CG8oyMWTTcWS/3tk/nCVotGajuZzD8O1MRQUFKyYNm3aXESjHMwASSNHjjRg4KzgA4biUe+0ao3QmzZtIuwxJCQkpJaVlf1tcXHxa/gDTEy1rFCFAfLF7du3P97U1HQI/dXY2dlpxbftqiAQDDwpfqBqpA8CYYBLr42YU9Mx1z5C5ufqPLA0a2Ch6UeWlpZ+qbKy8iJeN0tqaqqtqqqK6AVCRiCPF/7Wqhn0GDoRDHSVxMREE5b8NyUlJd0Rzpsb7VU+a/D7m5ub+wVMjsD40oz4YxwzZowqCGTwUfo7BmkG7af8/Hzq1TVg7jSNHj36c/TF3q00Xu2/qqdZ+hYSRg7y/6SampoLGGO2GgwGKxa8Dj9+DTitCgJR6U/fRRkgOTl5OrduMAJpISxop2AG2IXXrgHjgo6ioqLrvl28ePGQEMjgVS0E3QpErUiIPGC32w0pKSkZyGuFQ6niY7nVgxWYsKAtxqdUzABGxG0D9RCH2jMcMgLRwDar1apglWTE0j8Vq6d0X2gyEMawGWJXwWAsmt45dAb/hkYYKGlpabBly5bIIhANaXalqQnU7G79YQxgBVvzDyYsXE00pgzxh3CbyOO6L++7777IIFBtbS1gcEJmdjaDUucFV/EsjTKLATNBEmUAGkqP2A3z58+PLAIh9lAfABAGuWoUYARiaYFAbtKgZ5pH0NHRQR2wEW8F6jOZhVtCWFohkNt/RBvoOWfji1sPPPBAZBDo+huK0ud9NjZLqxrDNeYsJOOrhkDemcFflcYIxFIBgfoVrps3b448Avk6OUYglkYI5FMRRyCtfhiLpYXxGYFYUYtAnmIEYjECMQKxGIEYgViMQIxALC81HwA4vgFg3DcAsmcxAjECxZDaTwFUPgpw9ThAw4cAZc8DFN7LCMQIFAPqvACw62FhflJXPb7+JkAbZoqJT2AJJcdarIxAbH71ZbkozN980MttdoCPsRZoqxa1QVJO38+vNQMcXAWQcydA8fyYQiBfGiwXOQLFIVYYZWsB2PkQQONH/o85/x9YQ9QATP8XgOGTxXs9XQB7lwPU/AHg3K8xMzQCjP+29DWAj5oguBrA6w8DyVU+YwT3D+G5sZGOKhOwBJ8jSn9Ht//jGvcAfPA1rAl+DJCLJf7+lcL8zpvSA3DoGcSnTwCm/jPWFNm6vVyGIeSqPu91dXUpnlUZz40NBzijQePifX+WYAaY8gMs2acAHFgp2N8vKtUhKmFtYRoJ0HG2/+dnt4r3p78EkD5Rnwjk9YdBa+PGjWzIcAe3+1dgqV0OcPOj/o8r/DIauwCP/SfRFOoXdLGWGJYHYG0AsHf2//xKJdYU87CmeAFg5N8xAjECRTK4rcUS+xuC72v/G0vnc1jar8G76GcFyqzbAO7aJnDm7DbfxxDilD4GUP9/GAM8KTKYr0y35zFNMgAjEJs/MF1rAtj9zb7BbfUmYU4qnc1jfP8dtfTM3ACQXARw9CXREuS885hpJj8lzE/K/xzAnf8OsO+7Ij7w1oi7GYEYgSJl/mY0/xKAhp39P6OaoP0MwLQKgLxP+3EZ3uLJ3xccX/UcQNsJjBXS0PSf7XsctQiVv4XH/Ajg1Js33h99P8BtL3ErECNQBERcvmcpwKX/8X8Mtet/uAhxBnGo5CH/x42ai0ExBr77MTN0XQLYsQDgVjR7wT03jknMRLOvFTXGkQoRa8z4GUD8MG4FYgQKs6hNfx8GvLXvDX5sdxsy/BOYGU4C3PK077igaR/ASSrZXaVu+2mAnYtFHHHzkr7HTvgOQGYZQOo4Tc3PCMTyz/zUm1v/1+D+7sQrYrgDIVHKWA/z7xdmpw4wT/VYRXPp1aMiIDYOv/EZlf4aixGIEcg/9gRrfrcIlz44jyjzU4CcO0StQAG0t/k9dfrfADrOi97h1Jti5lIzAskmGpLw0XdEcBuKKC7YsRBgHMYElz8QuDOY6Dhq878VA+WCz4fl5zICsTyKE5sw//nfqBdDfLJOfG+gcsYFi0QcUbqUEYgRKIw6uBrg3NvqfR/1Bk/AwPjUL/DxyyBqIasYFUqZgVqWElIZgRiBtDb/KtGxpZaoT4DG8FCz5nSMBZILAY68KMwdqCjjUJ/B1B8CZE5nBGIE0kiHsZQ9vl6976PAd/ZGYX6nyxRRE6SNFz29NKQiUFHnW8sRzTIAI1CsIxANTzj2snrfR+N/yPy+hjBTh5dphBj6fGV3YN83GY8d+w+MQIxAGoiMX/Wset+XUQZQjjFEYob/Y2iYdPlWEW+c2TLw9018EmDSSm4FYgTSQMTXhD5qippQaSJ84oyBjzOmA8z4VwDzaBEX+GoluvlboiWIW4EYgVQXlbwHnlL/e2kG1/tfFRNiBhoT5I4LJmI8kFYqzsVzGHTJItErHANiBAq3aD4ujdkJpm0+GNmuiu+/Wo0m/sHg43hGflHUBDQfuHEvwJivA0z7CRZtCWG5HIxAsSTq3dXS/J6qfhVL9fMAZRVo8KKBj02fBDDnV3h+fxJDn8NkfkagWEKguj8DVH5LjNoMW4Z7T8zppaEN+Z8Z+FhqHaLV42JMjEDhELWlk/lpaEK4RQtj0dAGGvc/9kHpLg0jkN5FY/Arl4hZXZFSdzvAR8tccwVWSTW5hRFIzwjUfEgsUjXQMORw6vjPRTOpMy4YzYUTI5CGouHIux/xvcpCpANxWk2CWnpy76A7wAjECKSB+Wn2FQ0kk1EUF1B/wV2/DsusL0agWEIg98K0rUflPs+smQApxYxAjEAqynpZLF/Sclju88y9C+D216VY85MRSC+i1ZSp5KeNKKQ2/51o/tekWfCWEUgPCOScxP64mFMrszKmAsx6pf++AIxAjEAhmz+QtXsiqeG3COyhlaAlEiNQNIvW2aQFZS/8Tu7zpGVObn8Dg94S+S4hI1C0IlCvWGLw3Da5T5MGwhHz0wpvLEYgdbyPl+DgUwAnX5Pc/KNFyU+zwCQVI1A0iqYxnnhV7nOkVp5ZeI6Z0+QuSxiBogyBaArhsbWSmz8HYParUm6MzQgUzQhExqdtRmUWLWJFTZ3+9gpgBGIEGpJowwg1V3DQQjTMmdbyH2zyCyMQI1BQOv0rsdlcr0Pec6T9AGilh8K/Z65hBFJRtFYnraY20J67EeeIeLEMYtF9UWdARiCZdfGPUWB+vH1lGJeMmReVl5gRSFYEookjex4V0wll1q1o/pseYZZhBFJRDbvEvri0xo7Mom1Ovff2YgRiBApJtEfu7ofF8GaZRau6TVoR9ZebEUgmBGo+ALDzH4NbPjwSos2tb1nN/MIIpKJonizN5qIpjTKLFq+iDSt0IhkQaKj/0/kF/hAoqnp4afI6LR5Fk9llNz9tf0rNnjpRxBHIB9ooXgcpftI+EWiwzCBd6U+4Q8uXUA0gs4q+Kpo74wy6w5BQMNlV8g/mVb9pgxfa+OL8wXKT4svMUcH/XfVi/1xawEpmjfoSwIyX8UobdWl+d+EZSNpfyT9kBPL6Pl+mHxCBtGY7zURLFVJrD63bKbNov95ZG7CuTtZlEOpp7EDSjEBqqLtD7MR+eYfc7qDlS2b+XLfmZwSKBAJRzy51csk+iZ2WL3Hu9Jile/MzAoVLNKaHdkKp+YPcrqAtSWe/BjAsD/QuRqBwmn//CrFFkcyi+buzN8WE+RmBwolAB1aKSS0yizaynvNmTK3ZyQgUDtFMrpNvyO0E8xhR8sfYgrWMQFrr4wqxG7vs5p9Dy5dMhlgUI5BWIuMfqZD77hPr08JVtMt7jJqfEUgL0U7sVT+S++4nZooVHKjVJ0bFCKSFaDaXcyf2XnnvvHG4aOfP+xuIdTECqSnrFTT/9wF6rPLececKDrR8yWfZ/IxAKuvk62JzaGnveLzYpXHUXGAxAql7NS11Yg0fmVWyCGDsA+x8RiANEKjuL2KIs6wyjQCY8AQ7nhFII13ZJffdHrMAM0EBu54RSKNM0nZK4sA3mbmfEUhjBLI2yHuXaZuitJvY7YxAWkrixWtptxYlkR3PCKQhAlHPKrUEyajEDHa7hAik+EEg79pgsLRPBFIjZwellLHy3mW7hZ0+AAK5TT5Q2l/J7yr9FQ9PBpzWFwLllgNceEfOO91ZA2JoRhy7nhFIo0xS8AUxAlTGpQ1p8S3KBMmF7HpGII0QiIYWy9rRRGOUZJ+LzAikg7FAJQ+KDrHzv5XvbldvAij8iugRZjECaZJJaOnA6T8Vp3b+N/LFAQdXiWHQOlzljREo0gjkljENTfaKWENftqDzwu8B9nwbwNbKzmcE0vLKGsQa+tQ0evBpuTa8OLcNoKsO4DasqVJKGIEYgTQUbR5HKy3QNqcyLYJ7+QOA978OcOuzAAX3MAIxAmmorJkA5VsxAP2yXHe+/RTAzsUAJ15lBGIE0ljD8sW6O8lFAJ/8TJ7zoqmbtGhX+0lEtmdE/MIIxAikiajlhbYXohXYDj0j1+hRWrirDTPB9J8ApN7MCMQIpGVcgOx95xaA9IlyOcEdF9T9mRGIEUjruGAGxgXbxAoSF/9LnvOiCf07HxI1Fe0JxgjECKSZkkcBzPkFwJEfy7V8or0TYN93AVqPAExZg3FBOiMQI5CGccEtTwPMXC/mE8ikU78E+PBB0VrECMQIpKmKF4hOM9pDoKVKorjgfYwL7geYvErMKVYSGIEYgTRS9izRX0BxQc278pxX+xmAY2sB8j+jSxxiBJJJtGwJrdZc+jhIM46I5hBQ86gO+wgYgWQUTV6nIQrUTHpwdWTHEdHQado1JnMatwIxAoVZ1F9gLgLY+wTA1U/C//9pIv3MDbo1PyNQb6/8dyd7tugvCPeiVmR+2jsg71O6Nz8jkOyiWuD2NwA+fg6D0Ze1/3+0ihyV/CPuBr2LEShq4oIE0SllHivGEdlatIs/aJ5AwechVsQIFE0au9A1jmiSBuY3ovnXAoz+WkyZnxEo2pQzB+Au1ziimv9U73vLELGK50MsiREoWmUaiXHB6wBVzwMcX4cXIJR1SeNEs+u4hyEWxQgUrSJep1GbFLCGMo5oKsYWpY/FrPkZgaJd1F9AI0v3PQlw9Xhwf0sLeY1fBrEqRiA9xQXlbwMcejrwcURk/CnPQKyLEUgvov4CmnfsHEc0iGiyC+ETm58RSFeKTxIBbWoJ1gZrfPcX0FItZc8DixFIv3d27IMAKeMA9n8PoPXojfepjZ/a+nlpREYg3SFQv7jgdjGOyN2rS0Mbpr8kagkWI1BMiFqHZm0EuPBbsQJcgpmvCSNQjGUSmshS8hC7XUIE0tc2qayoRaBA0/5Kft4mlcUIxAjEYgSKEAK5InaHZ9TOCMTSAIEcJLdvpECgnp4ecD3b8URteHJGNjZLbQRC39vQY07zd3d3Ozo6Oq4fs2HDhsggUHt7O6SlpVEudVy7ds2KJ2hRlL69PFojUDAliKzpYGpLPaWDQSCbzUb+suFb9oSEBKfvFixYEFkEMpvNSnx8vLNe6uzs7MATbMOTSw/XRQw2iJIxHc0ZN5xpi8XSSoRBGYD8hwUtbN261enDefPmRQaB6uvrITEx0ZGUlGTDGgDP0XIB04XhRqBovrF6yMThSLe0tNThk5UyAJrfYbfbr/v0rbfeilwrUEpKClUAdnxYmpubj2RkZNwRLAINNR1MV7rM6VhFoEDTpNra2nP4Xge+JhRytLW1wZIlSyI7FmjNmjWOq1ev0klSAGw5ceLEXuK0cJUKekIgTvtPt7a21qPPavF1G142DAds9q6uLli7dq2DHhDJsUCIPo7k5GQ75U5U3ZUrVyrz8vLKGYEYgdRKnzlzpgqvVwOmW/HZajQanQWvW1QQRwqBHA0NDZCVlUUIRHzWfPTo0fcQg6biSaYyAjEChZpuamqqP3v2LO1xW4/vtRkMBhvij6OoqMixePHikBAonv6XO6N5ZII4D5P3eh3TL719+/bee++9Ny4+Ph7PuzeeqibqC8jOzp6Iz3HhagWKlc6gWEpT0/qePXv+gp46iK9PUS3Q3d3diTWCY/ny5W6feno3qHQoTTV9mpTWr18PmZmZVKNQqU+tQJMmTJjwlfHjx38RI3ZF6wwQ7WlWf6H5bZWVlf+LhLEDr9MBvF7VWPo3YmawuppCQy98QkCgfunNmzcrw4YNM2IQnIEvR+MJTyguLr4bM8GnTSZTulZNo9wRpq80ojQ0Nzc3HjhwYFdLS8te/OgIflaNhFFHDS0nT560r169esjYozoCudMzZsxw9ghjJqAxQdcoWsfovbWmpoZOHCgTJCQkGBmBGIH81YJo+FaMIasOHz68g7AH36L5pKfR/JfROxa0U7fZbHbMnTu399133x0S9miCQO40RuPKpEmTDJiLqSagUj8PH4X4Iwvx41EYLBfn5eUVpqWlZWFGMbkyhIHHDsXeGCDqO6L2zM7OTuo/arx06VIdpqmwrEU/XMDnC3joRSToZnzuwAxhw2A40FbK8COQO71u3TpIT09XEhMTKROY8cdk4CMLP8vBH0XP9Jr2+zHhj0uisUP4WsHPFDXHCLHkNL7bK5QB0B9WV+8ujWyjJTQaKdClZ9ejDUt/K2aM6+anQjYUf3qm4/yU6kqoueyFF15QkP8VDFqctQE+TPi2GS8ABclm1yOJWovczbHuDMDSvdzDmanz1O7KABbKBNTRhQViBz2ox5eOqa2ttbv9uHz58iGN+fGXVh2BvNMVFRVQVFREGYEMTmZ3Gp7S+DB49EV4lv6cEfRbAzg8+J98Qh2ozoyAJb2Nhjyj+e0Wi4VGfNqrq6tVRZ6wIJBX2lll5efnA/4gwiIaPKdg1Ueto85SHzGQPgPGn9jBIPccEhpI2d3d7cwMlDmsVqsD/eDsXHW19Kjlw/AikJ/vpCDZ+eaIESOAhlEbjUagOQX4w2lQ3fWMwNKvWltbnU2d2dnZzsxgt9uBhjW4hjZcb0xRE3UGSQ/Z2MGkWSzppHiYVPF6T/FzzFCMH8j3DTWthJApZUornI5I2meprqicycL2A6K4IOJ05NKMQCxGIEYgRiBGIEYgRiBGIEYgFiMQIxAjECMQIxAjECMQIxCLEYgRiBGIEYgRiBGIEYgRiMUIxAjECMQIxAjECBTl6f8XYAD1Oh5Q5WFjjQAAAABJRU5ErkJggg==".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAMAAAADACAYAAABS3GwHAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAAyVpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADw/eHBhY2tldCBiZWdpbj0i77u/IiBpZD0iVzVNME1wQ2VoaUh6cmVTek5UY3prYzlkIj8+IDx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IkFkb2JlIFhNUCBDb3JlIDYuMC1jMDA2IDc5LjE2NDc1MywgMjAyMS8wMi8xNS0xMTo1MjoxMyAgICAgICAgIj4gPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4gPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIgeG1sbnM6eG1wPSJodHRwOi8vbnMuYWRvYmUuY29tL3hhcC8xLjAvIiB4bWxuczp4bXBNTT0iaHR0cDovL25zLmFkb2JlLmNvbS94YXAvMS4wL21tLyIgeG1sbnM6c3RSZWY9Imh0dHA6Ly9ucy5hZG9iZS5jb20veGFwLzEuMC9zVHlwZS9SZXNvdXJjZVJlZiMiIHhtcDpDcmVhdG9yVG9vbD0iQWRvYmUgUGhvdG9zaG9wIDIyLjMgKE1hY2ludG9zaCkiIHhtcE1NOkluc3RhbmNlSUQ9InhtcC5paWQ6ODJDQkY5NzU3NzAzMTFFRjg1RTdDQjY1MjUwMTREM0UiIHhtcE1NOkRvY3VtZW50SUQ9InhtcC5kaWQ6ODJDQkY5NzY3NzAzMTFFRjg1RTdDQjY1MjUwMTREM0UiPiA8eG1wTU06RGVyaXZlZEZyb20gc3RSZWY6aW5zdGFuY2VJRD0ieG1wLmlpZDpENzg1M0IwQzc3MDIxMUVGODVFN0NCNjUyNTAxNEQzRSIgc3RSZWY6ZG9jdW1lbnRJRD0ieG1wLmRpZDo4MkNCRjk3NDc3MDMxMUVGODVFN0NCNjUyNTAxNEQzRSIvPiA8L3JkZjpEZXNjcmlwdGlvbj4gPC9yZGY6UkRGPiA8L3g6eG1wbWV0YT4gPD94cGFja2V0IGVuZD0iciI/PqsNNtkAABgXSURBVHja7J0JeFPXlcePn2XZyPKCd2OwwZjEbIEYwhISp9Nl0nT60U6apgWGBDJNQ0NSStIyNJCUTprETSclHQoJJGlahgmknbZpZtpMOzP9SAhgwu4AAbNjbIzxhhdZyLI85+hKIMuSLVnvSVdP5/99+nQlPctP7/3vvb9zVwAABW5I8Xj29b73Z4Gmh/p3waQhStOgg9+gh3sw+AdDNDSLJa18lewOlY2rdQ2gx/vA6TClFS9DObwyga9HsP/M4fGsRTpciKV1BuZ0BNOKxiUWi2sAqWsAR5A3xeEDmfylWSxpZfBharVLJu/v5nR/3GRJWBVHS/XOYqluTgBu1uQYIAbSBh9VciBII9tNZgRiMQKxWIxAjECcDqEjzPO9gTqegnlwTcCZIBrSjBes2K6Co30oAZf+nB4yAoGflhVfCMSBKmcCRiAWSw+K82F6zdu/16xZ40yXlJRAe3s7ZGZmKr29vRAXJ04nmLTns/MHRVna/XtiUR0dHY7ExETo7OyEuro6T/+ByyOexKFJOm6AEt8RQFUdkPDHgMlkgqysLHpWEhISFIfD4XzQ95EJDAYDF0cxpJ6eHmEyh4PSlBEcWBg60AeOa9euOZqammDFihWaF8hxfgyuSu8k5eLCwkJISkpS4uPjDWh0ehjxBxtzc3NTU1JSzJgZkvAzo6s0ZPyKAdG9xocDfWBDs1ubm5vb0PwWvP82eg8zgR0zht1isdgvX74MoGFveVxFRQWsXLlSdQR68cUXAU2uoPkNZHj8UabS0tLiUaNG3YPvzcDXxYqiZOCPNuPhRjcWBItA0Z6Opd/qTntkBCs+OtDsjd3d3ccxE+w+duzYXxtQREj4N1Y7qrW11e7OBEuXLpUfgcj82dnZSnJychL+QPPMmTNn5eXlPW40Gj/FpTxrIGFmsGJs8E51dfWbZ86cOY5+abPZbJRRbPTxwoUL5UYgrFEUZH0FWd80fPjwrDlz5jxpNpsX4UcmLYLJqG+FiOIAXss0UkNDbW3t2t27d7+DiNyItNCBSGQ7ffq0qkhkoADV3SoTam5av369s0UHT96Unp6eU15e/hzmg/u9WzvUTjMC6S+Nps9BXH4W30veuXPn2/i6njIBFqo29/1ftmxZyAik+DH/kDq8CG8oyMWTTcWS/3tk/nCVotGajuZzD8O1MRQUFKyYNm3aXESjHMwASSNHjjRg4KzgA4biUe+0ao3QmzZtIuwxJCQkpJaVlf1tcXHxa/gDTEy1rFCFAfLF7du3P97U1HQI/dXY2dlpxbftqiAQDDwpfqBqpA8CYYBLr42YU9Mx1z5C5ufqPLA0a2Ch6UeWlpZ+qbKy8iJeN0tqaqqtqqqK6AVCRiCPF/7Wqhn0GDoRDHSVxMREE5b8NyUlJd0Rzpsb7VU+a/D7m5ub+wVMjsD40oz4YxwzZowqCGTwUfo7BmkG7af8/Hzq1TVg7jSNHj36c/TF3q00Xu2/qqdZ+hYSRg7y/6SampoLGGO2GgwGKxa8Dj9+DTitCgJR6U/fRRkgOTl5OrduMAJpISxop2AG2IXXrgHjgo6ioqLrvl28ePGQEMjgVS0E3QpErUiIPGC32w0pKSkZyGuFQ6niY7nVgxWYsKAtxqdUzABGxG0D9RCH2jMcMgLRwDar1apglWTE0j8Vq6d0X2gyEMawGWJXwWAsmt45dAb/hkYYKGlpabBly5bIIhANaXalqQnU7G79YQxgBVvzDyYsXE00pgzxh3CbyOO6L++7777IIFBtbS1gcEJmdjaDUucFV/EsjTKLATNBEmUAGkqP2A3z58+PLAIh9lAfABAGuWoUYARiaYFAbtKgZ5pH0NHRQR2wEW8F6jOZhVtCWFohkNt/RBvoOWfji1sPPPBAZBDo+huK0ud9NjZLqxrDNeYsJOOrhkDemcFflcYIxFIBgfoVrps3b448Avk6OUYglkYI5FMRRyCtfhiLpYXxGYFYUYtAnmIEYjECMQKxGIEYgViMQIxALC81HwA4vgFg3DcAsmcxAjECxZDaTwFUPgpw9ThAw4cAZc8DFN7LCMQIFAPqvACw62FhflJXPb7+JkAbZoqJT2AJJcdarIxAbH71ZbkozN980MttdoCPsRZoqxa1QVJO38+vNQMcXAWQcydA8fyYQiBfGiwXOQLFIVYYZWsB2PkQQONH/o85/x9YQ9QATP8XgOGTxXs9XQB7lwPU/AHg3K8xMzQCjP+29DWAj5oguBrA6w8DyVU+YwT3D+G5sZGOKhOwBJ8jSn9Ht//jGvcAfPA1rAl+DJCLJf7+lcL8zpvSA3DoGcSnTwCm/jPWFNm6vVyGIeSqPu91dXUpnlUZz40NBzijQePifX+WYAaY8gMs2acAHFgp2N8vKtUhKmFtYRoJ0HG2/+dnt4r3p78EkD5Rnwjk9YdBa+PGjWzIcAe3+1dgqV0OcPOj/o8r/DIauwCP/SfRFOoXdLGWGJYHYG0AsHf2//xKJdYU87CmeAFg5N8xAjECRTK4rcUS+xuC72v/G0vnc1jar8G76GcFyqzbAO7aJnDm7DbfxxDilD4GUP9/GAM8KTKYr0y35zFNMgAjEJs/MF1rAtj9zb7BbfUmYU4qnc1jfP8dtfTM3ACQXARw9CXREuS885hpJj8lzE/K/xzAnf8OsO+7Ij7w1oi7GYEYgSJl/mY0/xKAhp39P6OaoP0MwLQKgLxP+3EZ3uLJ3xccX/UcQNsJjBXS0PSf7XsctQiVv4XH/Ajg1Js33h99P8BtL3ErECNQBERcvmcpwKX/8X8Mtet/uAhxBnGo5CH/x42ai0ExBr77MTN0XQLYsQDgVjR7wT03jknMRLOvFTXGkQoRa8z4GUD8MG4FYgQKs6hNfx8GvLXvDX5sdxsy/BOYGU4C3PK077igaR/ASSrZXaVu+2mAnYtFHHHzkr7HTvgOQGYZQOo4Tc3PCMTyz/zUm1v/1+D+7sQrYrgDIVHKWA/z7xdmpw4wT/VYRXPp1aMiIDYOv/EZlf4aixGIEcg/9gRrfrcIlz44jyjzU4CcO0StQAG0t/k9dfrfADrOi97h1Jti5lIzAskmGpLw0XdEcBuKKC7YsRBgHMYElz8QuDOY6Dhq878VA+WCz4fl5zICsTyKE5sw//nfqBdDfLJOfG+gcsYFi0QcUbqUEYgRKIw6uBrg3NvqfR/1Bk/AwPjUL/DxyyBqIasYFUqZgVqWElIZgRiBtDb/KtGxpZaoT4DG8FCz5nSMBZILAY68KMwdqCjjUJ/B1B8CZE5nBGIE0kiHsZQ9vl6976PAd/ZGYX6nyxRRE6SNFz29NKQiUFHnW8sRzTIAI1CsIxANTzj2snrfR+N/yPy+hjBTh5dphBj6fGV3YN83GY8d+w+MQIxAGoiMX/Wset+XUQZQjjFEYob/Y2iYdPlWEW+c2TLw9018EmDSSm4FYgTSQMTXhD5qippQaSJ84oyBjzOmA8z4VwDzaBEX+GoluvlboiWIW4EYgVQXlbwHnlL/e2kG1/tfFRNiBhoT5I4LJmI8kFYqzsVzGHTJItErHANiBAq3aD4ujdkJpm0+GNmuiu+/Wo0m/sHg43hGflHUBDQfuHEvwJivA0z7CRZtCWG5HIxAsSTq3dXS/J6qfhVL9fMAZRVo8KKBj02fBDDnV3h+fxJDn8NkfkagWEKguj8DVH5LjNoMW4Z7T8zppaEN+Z8Z+FhqHaLV42JMjEDhELWlk/lpaEK4RQtj0dAGGvc/9kHpLg0jkN5FY/Arl4hZXZFSdzvAR8tccwVWSTW5hRFIzwjUfEgsUjXQMORw6vjPRTOpMy4YzYUTI5CGouHIux/xvcpCpANxWk2CWnpy76A7wAjECKSB+Wn2FQ0kk1EUF1B/wV2/DsusL0agWEIg98K0rUflPs+smQApxYxAjEAqynpZLF/Sclju88y9C+D216VY85MRSC+i1ZSp5KeNKKQ2/51o/tekWfCWEUgPCOScxP64mFMrszKmAsx6pf++AIxAjEAhmz+QtXsiqeG3COyhlaAlEiNQNIvW2aQFZS/8Tu7zpGVObn8Dg94S+S4hI1C0IlCvWGLw3Da5T5MGwhHz0wpvLEYgdbyPl+DgUwAnX5Pc/KNFyU+zwCQVI1A0iqYxnnhV7nOkVp5ZeI6Z0+QuSxiBogyBaArhsbWSmz8HYParUm6MzQgUzQhExqdtRmUWLWJFTZ3+9gpgBGIEGpJowwg1V3DQQjTMmdbyH2zyCyMQI1BQOv0rsdlcr0Pec6T9AGilh8K/Z65hBFJRtFYnraY20J67EeeIeLEMYtF9UWdARiCZdfGPUWB+vH1lGJeMmReVl5gRSFYEookjex4V0wll1q1o/pseYZZhBFJRDbvEvri0xo7Mom1Ovff2YgRiBApJtEfu7ofF8GaZRau6TVoR9ZebEUgmBGo+ALDzH4NbPjwSos2tb1nN/MIIpKJonizN5qIpjTKLFq+iDSt0IhkQaKj/0/kF/hAoqnp4afI6LR5Fk9llNz9tf0rNnjpRxBHIB9ooXgcpftI+EWiwzCBd6U+4Q8uXUA0gs4q+Kpo74wy6w5BQMNlV8g/mVb9pgxfa+OL8wXKT4svMUcH/XfVi/1xawEpmjfoSwIyX8UobdWl+d+EZSNpfyT9kBPL6Pl+mHxCBtGY7zURLFVJrD63bKbNov95ZG7CuTtZlEOpp7EDSjEBqqLtD7MR+eYfc7qDlS2b+XLfmZwSKBAJRzy51csk+iZ2WL3Hu9Jile/MzAoVLNKaHdkKp+YPcrqAtSWe/BjAsD/QuRqBwmn//CrFFkcyi+buzN8WE+RmBwolAB1aKSS0yizaynvNmTK3ZyQgUDtFMrpNvyO0E8xhR8sfYgrWMQFrr4wqxG7vs5p9Dy5dMhlgUI5BWIuMfqZD77hPr08JVtMt7jJqfEUgL0U7sVT+S++4nZooVHKjVJ0bFCKSFaDaXcyf2XnnvvHG4aOfP+xuIdTECqSnrFTT/9wF6rPLececKDrR8yWfZ/IxAKuvk62JzaGnveLzYpXHUXGAxAql7NS11Yg0fmVWyCGDsA+x8RiANEKjuL2KIs6wyjQCY8AQ7nhFII13ZJffdHrMAM0EBu54RSKNM0nZK4sA3mbmfEUhjBLI2yHuXaZuitJvY7YxAWkrixWtptxYlkR3PCKQhAlHPKrUEyajEDHa7hAik+EEg79pgsLRPBFIjZwellLHy3mW7hZ0+AAK5TT5Q2l/J7yr9FQ9PBpzWFwLllgNceEfOO91ZA2JoRhy7nhFIo0xS8AUxAlTGpQ1p8S3KBMmF7HpGII0QiIYWy9rRRGOUZJ+LzAikg7FAJQ+KDrHzv5XvbldvAij8iugRZjECaZJJaOnA6T8Vp3b+N/LFAQdXiWHQOlzljREo0gjkljENTfaKWENftqDzwu8B9nwbwNbKzmcE0vLKGsQa+tQ0evBpuTa8OLcNoKsO4DasqVJKGIEYgTQUbR5HKy3QNqcyLYJ7+QOA978OcOuzAAX3MAIxAmmorJkA5VsxAP2yXHe+/RTAzsUAJ15lBGIE0ljD8sW6O8lFAJ/8TJ7zoqmbtGhX+0lEtmdE/MIIxAikiajlhbYXohXYDj0j1+hRWrirDTPB9J8ApN7MCMQIpGVcgOx95xaA9IlyOcEdF9T9mRGIEUjruGAGxgXbxAoSF/9LnvOiCf07HxI1Fe0JxgjECKSZkkcBzPkFwJEfy7V8or0TYN93AVqPAExZg3FBOiMQI5CGccEtTwPMXC/mE8ikU78E+PBB0VrECMQIpKmKF4hOM9pDoKVKorjgfYwL7geYvErMKVYSGIEYgTRS9izRX0BxQc278pxX+xmAY2sB8j+jSxxiBJJJtGwJrdZc+jhIM46I5hBQ86gO+wgYgWQUTV6nIQrUTHpwdWTHEdHQado1JnMatwIxAoVZ1F9gLgLY+wTA1U/C//9pIv3MDbo1PyNQb6/8dyd7tugvCPeiVmR+2jsg71O6Nz8jkOyiWuD2NwA+fg6D0Ze1/3+0ihyV/CPuBr2LEShq4oIE0SllHivGEdlatIs/aJ5AwechVsQIFE0au9A1jmiSBuY3ovnXAoz+WkyZnxEo2pQzB+Au1ziimv9U73vLELGK50MsiREoWmUaiXHB6wBVzwMcX4cXIJR1SeNEs+u4hyEWxQgUrSJep1GbFLCGMo5oKsYWpY/FrPkZgaJd1F9AI0v3PQlw9Xhwf0sLeY1fBrEqRiA9xQXlbwMcejrwcURk/CnPQKyLEUgvov4CmnfsHEc0iGiyC+ETm58RSFeKTxIBbWoJ1gZrfPcX0FItZc8DixFIv3d27IMAKeMA9n8PoPXojfepjZ/a+nlpREYg3SFQv7jgdjGOyN2rS0Mbpr8kagkWI1BMiFqHZm0EuPBbsQJcgpmvCSNQjGUSmshS8hC7XUIE0tc2qayoRaBA0/5Kft4mlcUIxAjEYgSKEAK5InaHZ9TOCMTSAIEcJLdvpECgnp4ecD3b8URteHJGNjZLbQRC39vQY07zd3d3Ozo6Oq4fs2HDhsggUHt7O6SlpVEudVy7ds2KJ2hRlL69PFojUDAliKzpYGpLPaWDQSCbzUb+suFb9oSEBKfvFixYEFkEMpvNSnx8vLNe6uzs7MATbMOTSw/XRQw2iJIxHc0ZN5xpi8XSSoRBGYD8hwUtbN261enDefPmRQaB6uvrITEx0ZGUlGTDGgDP0XIB04XhRqBovrF6yMThSLe0tNThk5UyAJrfYbfbr/v0rbfeilwrUEpKClUAdnxYmpubj2RkZNwRLAINNR1MV7rM6VhFoEDTpNra2nP4Xge+JhRytLW1wZIlSyI7FmjNmjWOq1ev0klSAGw5ceLEXuK0cJUKekIgTvtPt7a21qPPavF1G142DAds9q6uLli7dq2DHhDJsUCIPo7k5GQ75U5U3ZUrVyrz8vLKGYEYgdRKnzlzpgqvVwOmW/HZajQanQWvW1QQRwqBHA0NDZCVlUUIRHzWfPTo0fcQg6biSaYyAjEChZpuamqqP3v2LO1xW4/vtRkMBhvij6OoqMixePHikBAonv6XO6N5ZII4D5P3eh3TL719+/bee++9Ny4+Ph7PuzeeqibqC8jOzp6Iz3HhagWKlc6gWEpT0/qePXv+gp46iK9PUS3Q3d3diTWCY/ny5W6feno3qHQoTTV9mpTWr18PmZmZVKNQqU+tQJMmTJjwlfHjx38RI3ZF6wwQ7WlWf6H5bZWVlf+LhLEDr9MBvF7VWPo3YmawuppCQy98QkCgfunNmzcrw4YNM2IQnIEvR+MJTyguLr4bM8GnTSZTulZNo9wRpq80ojQ0Nzc3HjhwYFdLS8te/OgIflaNhFFHDS0nT560r169esjYozoCudMzZsxw9ghjJqAxQdcoWsfovbWmpoZOHCgTJCQkGBmBGIH81YJo+FaMIasOHz68g7AH36L5pKfR/JfROxa0U7fZbHbMnTu399133x0S9miCQO40RuPKpEmTDJiLqSagUj8PH4X4Iwvx41EYLBfn5eUVpqWlZWFGMbkyhIHHDsXeGCDqO6L2zM7OTuo/arx06VIdpqmwrEU/XMDnC3joRSToZnzuwAxhw2A40FbK8COQO71u3TpIT09XEhMTKROY8cdk4CMLP8vBH0XP9Jr2+zHhj0uisUP4WsHPFDXHCLHkNL7bK5QB0B9WV+8ujWyjJTQaKdClZ9ejDUt/K2aM6+anQjYUf3qm4/yU6kqoueyFF15QkP8VDFqctQE+TPi2GS8ABclm1yOJWovczbHuDMDSvdzDmanz1O7KABbKBNTRhQViBz2ox5eOqa2ttbv9uHz58iGN+fGXVh2BvNMVFRVQVFREGYEMTmZ3Gp7S+DB49EV4lv6cEfRbAzg8+J98Qh2ozoyAJb2Nhjyj+e0Wi4VGfNqrq6tVRZ6wIJBX2lll5efnA/4gwiIaPKdg1Ueto85SHzGQPgPGn9jBIPccEhpI2d3d7cwMlDmsVqsD/eDsXHW19Kjlw/AikJ/vpCDZ+eaIESOAhlEbjUagOQX4w2lQ3fWMwNKvWltbnU2d2dnZzsxgt9uBhjW4hjZcb0xRE3UGSQ/Z2MGkWSzppHiYVPF6T/FzzFCMH8j3DTWthJApZUornI5I2meprqicycL2A6K4IOJ05NKMQCxGIEYgRiBGIEYgRiBGIEYgFiMQIxAjECMQIxAjECMQIxCLEYgRiBGIEYgRiBGIEYgRiMUIxAjECMQIxAjECBTl6f8XYAD1Oh5Q5WFjjQAAAABJRU5ErkJggg==".into()
    }
}
