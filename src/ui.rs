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

    fn is_incoming_only(&self) -> bool {
        hbb_common::config::is_incoming_only()
    }

    pub fn is_outgoing_only(&self) -> bool {
        hbb_common::config::is_outgoing_only()
    }

    pub fn is_custom_client(&self) -> bool {
        crate::common::is_custom_client()
    }

    pub fn is_disable_settings(&self) -> bool {
        hbb_common::config::is_disable_settings()
    }

    pub fn is_disable_account(&self) -> bool {
        hbb_common::config::is_disable_account()
    }

    pub fn is_disable_installation(&self) -> bool {
        hbb_common::config::is_disable_installation()
    }

    pub fn is_disable_ab(&self) -> bool {
        hbb_common::config::is_disable_ab()
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

    fn is_option_fixed(&self, key: String) -> bool {
        crate::ui_interface::is_option_fixed(&key)
    }

    fn get_builtin_option(&self, key: String) -> String {
        crate::ui_interface::get_builtin_option(&key)
    }

    fn is_remote_modify_enabled_by_control_permissions(&self) -> String {
        match crate::ui_interface::is_remote_modify_enabled_by_control_permissions() {
            Some(true) => "true",
            Some(false) => "false",
            None => "",
        }
        .to_string()
    }
}

impl sciter::EventHandler for UI {
    sciter::dispatch_script_call! {
        fn t(String);
        fn get_api_server();
        fn is_xfce();
        fn using_public_server();
        fn is_custom_client();
        fn is_outgoing_only();
        fn is_incoming_only();
        fn is_disable_settings();
        fn is_disable_account();
        fn is_disable_installation();
        fn is_disable_ab();
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
        fn is_option_fixed(String);
        fn get_builtin_option(String);
        fn is_remote_modify_enabled_by_control_permissions();
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
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAIGNIUk0AAHolAACAgwAA+f8AAIDpAAB1MAAA6mAAADqYAAAXb5JfxUYAABWFSURBVHja7J17cFRVnsc/595+pBMgSQMKAiOg7IQRhBV3FXGBUmTwMWRWZEpxFGRqXcuZ9Y/VWamp2rKsmnKI7uyOszu+2JlxF8ogmGQKxp1ZcZCHMog8VkBUEEQCApoHkHQ693V++0ffjk3kkU46SQfut+pU9eN29+nz/Z7f+Z3f+Z1zlYgQ4OKFETRBIIAAgQACXKwIZT5RSnX1+0ygBHgYeARoDJq4SygFfgk8B5wAvK582Rn9PRFpK13ElT7pAjQBrv84KJ0vrt+W4rftlV0VQPuiMonvggVYAPwWsH2VxgBGjBjBwIED8Twv6MvZmFHTpL6+ntra2vRLSd+6RoAHgJdzZQFCXazrTcAwn/wWoDBN/Lhx41i0aBFTp07Ftu2A1SwQiUTYsGEDixcvZvfu3dTW1sb8t1r8tvaAI8DaLv9YF4aAORmmqhWQeDwu8+fPl9WrV4uIiOd5EqBzSLfd6tWrZf78+RKPx09ra7/M6eoQ0FkBzAOczMoUFxdLTU1N2x+wbTtgsYvIbMOamhopLi6Wdp3O8bnoUQHM902Rk65MRUWFLFu2TERELMsKmMsx0m26bNkyqaioyBSB43MxvycEMBdYAtT5Y5AAsnz58raKOo4TsNVNyGzb5cuXZ4rA8zlZ4nPUbQJ4tv00ZcWKFaK1Dsx9Dw8LWmtZsWLFmaaNz3aXAO4Djmf2/KqqKrEsS1zXDVjpYbiuK5ZlSVVVVXtLcNznKqcCmAec8n9AA1JTUyOO4wRefi/PEhzHkZqamrQAtM/RqbM5htkKQPljSosf4NGmaUp1dbU4jiNa64CFXobWWhzHkerqajFNMy0C2+dsrs9hpwUwzQ9FJgGJxWKycuVKsSwr6Pl5Zgksy5KVK1dKLBZLW4Okz920rgjgvrTJj8fjUllZKVrrYMzPU59Aay2VlZWZASPd3h/oqACifmy/Ler05JNPBtO8PjJNfPLJJ9tHDBf4nJ5RAGfKBxiQEduPDho0iNGjRyMihEKhIFCfr+v6oRAiwujRoxk0aFC6I6fXDgZ0dC0gAvwDYAEyatQoqaqqajMzAfJ/KBARqaqqklGjRqUtgeVzGunoECC+cqS8vPxrMekA+R8oEhEpLy+XTC47OgT8M5AAYmPGjGHhwoXYtk04HA5sbB9BOBzGtm0WLlzImDFj8HMzEj63580JfCTtMMTjcWbPnp2LNLEAPQylFLNnzyYej2c69o90RACNQGjkyJE8/fTTOI4T9P4+agUcx+Hpp59m5MiR6cSfxvMmhaZRXFzM1KlT0VoHrdmH08qmTp1KcXHxOa87Y1q41hrbtjGMIGu8r8IwDGzbPm8nDhi+2IUSNEEggACBAAIEAggQCCDAxYcuLe+dOnWKffv20dLSktpndgFHDUUEwzAoLi6mrKysUwGyXbt2UVdXh2EYOWmrdJsPHTo0HfbtGQHU1tbyyiuv8M477/DJJ59cdAIYO3YsN910E/PmzaOoqOi8n922bRvPP/88W7du7TYBTJ06lYceeojRo0dn/yUZq4F7ARk/fvxZN3hs27ZNpk+fftHv3I1Go3LvvffK4cOHz7k6t2PHDikrK+uROt16661y4MCB0zaUjB8/Pv3+3o4sB59TAJ9++qlMmTIl2LadUe6//36pr68/I/nJZFLmzJnTo/V5/PHHsxJAVkPAz3/+c955552255FIhDlz5jBhwoS2jJT26IvDwtlS5FtbW9m4cSNvvPFG22uVlZVMmTKFBx988GvXHzx4kNWrV/do3detW8fBgwfTi0C58wE++ugj3nzzzbbn/fr149e//jWzZs2isLCw+4lWCuWvTQhAL5w5oLXm4YcfZsmSJSxatAgAx3F4/fXXufPOO9OpWG2or6/v8a3x9fX1HDt2LPcC2LFjB8eOHWt7/sADDzBnzhxM0+yRP+Zs3ULdgw9AYSGxexdQ/NAP6WnjYpom8XicBQsWsH79ev7whz+0efcHDx78mgB6A0qprDpjh+MAzc3NOI7T9nzKlCk9Rj6A15JEvvwS7/hxdCJBby5UDx48mBtvvLHteV1dHSdPnry44gA9Pra7DoZhoEMhVEGM3nQtlFKnZUhn2+sikQgFBQVdrkcikejy8Tt9Js/ba7URFBgGKtK7WUrSxUO1Jk+ezOzZs9FadyrpRimF67q8+OKLfPbZZxe+AATwWpOpnW6miYpG6cshp0QiwfHjx1PC7kQPVkrhed5pQ/IFKQD3yBGkJYEaNhy0To37yoRwpE9HFbdu3crWrVtzNhx1xRrlrwC0JvHqcuz3/kzoO3fiHDkMoRBiGBAJE+Qqnztm0ecFoF0X6/+24e7bi73nQ+TwIYxwGJRCQn07U3natGnccccdiEiXfYBDhw5dmALwLAu3vg6K+qEHDiKyfy+uUqhIFGyX1jffxPnzRsRxwVAggjJMIlP+huiMW/JaAE1NTRw+fDg1q+lk5rXneViWdeH6AF5LErSHGQrhxQpQzadAKYyiQloP7Md6Yy/ehrWI5/kCAJQicuwYA2fckteJDtu3b2f79u19Ow7Q7WNbSwJlO2CaECuE5qaUAEJhdEsS1dIC/Yr8uHCKfETQjQ14Tc0Y/fsFDkKf9gGaEyjHRkUHoPsNQCeaAYWYJkQjCAJaQ7/+SEkco6EOSbagm5twjx0j3P/KvG306667jptvvhmtdaedOK01lZWVHD58+AK1AIlmxHbwwmGksAiSLaBAmQY6HAGtUZaFjL8GZ/Ycon9cBdu2oJqa8I4cgTH5KwDDMIhEIiilOu0DuK57gVuApibEcxAzhGiNODZEomjDRAwTpTXK85CSErwJf4X7xXFiH+1BxwqQZHNem93NmzezZcuWHMyU9YUrAGlqAgHVdIrQ2v+FUCr4I0qhAUN7KZ/AtjGaTuKNuwbrgQKMSy6laOasvJ+758sR+nkhAAHsA/sJXXIpZj/feUs0o1DoxnqMjX9CR6Mox0FCqSCQ0hodCmN8spfYi8+iIhHEdTENRdOpegrvmE24pPi03wiCR3kqAPvDPZz4yT9RMOt2+v/d32MYBmL5ZxyJgOumAkBKoUwTQ2tMz0ObBrrhS4zPa1PDRCiELYLes4vQt75F+JpJbeQnN6wn+s1vYl46JGA9nwQggPXH13He24I+chjCEUKTp2DX1qbI1x4oIxXoUQoVCoHo1AxABFUQg3ETIVqAOnUC9fGHaNvC3fMB+AJI/OlPNP/jDxnwxE+J/e2c4NCLfBKAc+QIrdu2Q79+6ESCxL89g3799ykyAQr7oVwXsa3UXD8cBu0hnodoTbh0IImHH0UPGY753iZiT/0E59Qp3F078QBryxYSFT/FaWwksX4dBbd8G9W/f8B8ekbS273feWcj7o6tEIthlJaCaWDs3YOq/xIzGkVm3o552TA/4mekVgK1+DmBCkRj2DYqmUDZqZwBZZo4n+zl5Isv0PQvFbiHa1HxgTibNmLt3hWwni8WwGuop2XjBrTVinHZMNwZt2Hu3wvvb0/1+EgEPWES6oNdIIIYBioUTj3WHso08U6eIPJfL0HIhBONaMMApXAPfor3/C/BsVGhEMo0kEQziTVrKJh0LSoSCdjvbQtg7dmDs2N76iSSseNxvnMXzh1zUH5ypTaM1MrfyRMoQ4FSeOEwWlJRQDEU2rKQHVuQLZuQfR8i/viuAOW6GCWlcMM01CVDUYaJvfYNknv3EtwxuZcF4DU3k1y7Fl3/JWYkinf1NXiXDUcGFIPhJ5tGCpBwBGlJhYGVUhAKobX31RDgxwbEMBD11d9RnocaUIx3azmtP3wMuWoCCpAvvyC5/i1UcCu73hWAfegQ7rYtqbn9qCvwvvmtVHWam5Fk6mxDVVQEjuOngymUSlkE5bpIZihUqa9KmwBcVEkcd+Jf4428Amfy38DgS1BK4by1huSh2oD93hKAtm1a1q3F3fcxIQPk6mtwR14JViu0NKMcO9Xj+/VHWa2E0r1VKcxQGCUapb1zRna0YSItCczGOlSyBef6qXBlWSqFav9+rE1vp6aZgQB6Hu4XX+Bu+XNqLl9cgjtuAlJcAo6NkWjG8DwUghT2w0gmU49FUuN6OITh6dQQIKRIPFNRCtVYh3nwADgOUhDDuWEalJSitcZ5fRV2XX0ggN6Y+rVs3oy75V0MQ+GNvRqn7GpwHJSW1CJPaRxj0CW4l1yKIKjSQZilcVR8IPQvTk0Z+w3AKCnFKC5pKyqzlMQhGoNTjahkSyrmcN0UuPwKlKHw9n5EcvOmYBrY4+a/oRFr7RugwFAmeugwMBXmoQOIp5H4QPSM21Ne/vAR6Fgh7u3l4Ak6HMa7fBS0JlGFRYiizRFEqVSOACrl7EEqdjD4UlSiCRUKo6IFeH85CXP/x3hWEvu1FTgzv004Gg0E0FNo+WA37vq3IFqAVgr2fUTBf/47uA6iTFQ4ghcKpeL+R2oJKXBC4VTMRxnI8aOpdfRwGEy/+r4QxDRTG0cATBPPCKG++ILI72tQolMO5PGjqetFcD/6gNaNGwnPmBEIoEd6v2VhvfE/KUdMqVR//eRjjI93pwj0nTLVfsxoeygZq3oqlQuYicxZgErtIjp9wDPACKERUCbatrGXL0PffDPGRbo+0KMCaP3sEO6ba5AMkyvhMF6W5+2c1XfP8OrPfo32p4yAFqwPPyC5fj1F06cHTmB3I/naq7iJ5u47HsO3LJyvpGGa6KYmrBWVXKxhoR6zAK2f7EeW/RYzkWj3jjrjwy7NNNKWQJ3ldzJfdV3stWtoXf4KRXd37Ebc2e4GviAFEMlyMcUsLaXoX/+jLVb/NYPePmVHOkDwud4TfbpfIHL273VdzKGXdfi/tN8eflEK4L333uO73/1uh68PD4wTnnXrBdFozc3NbNq06eIWwPPPP8/QoUOZO3cuBQUFHctQzZHZTEcFc35KxHlCw0opGhoa+NWvftXjhz/lnQAaGxv58Y9/zFNPPUU0Gu3Ru4vYto3ruoTD4R69pY1SimQySUNDw2l5+dKH1xQ6LICBAwdSUFBAIsOJa21t5ejRoz1e6bFjx1JWVsbmzZu7vDs2Fxg+fDiDBw++sKeBkydP7vDRY92Jq666ildffZXq6mpeeOGFvDiZa9KkSTlrG9M0ufbaa7n77rs7ff5vtwhg6NChfP/73+9173fYsGGMGDECgCuuuKJDZ/V2J4qLi7nnnnvon4NEU6UUN9xwA2vWrKGyspKXX36Zb3zjG/kTCPrRj37ED37wg169ldzGjRt55plnWLduHRUVFdTW1vYq+U888QS33XZbznyM66+/npKSEgAmTJjAxIkTu/dPZHtYdDKZlMWLF8uECRMkGo12Y1BPnbF09dpclP79+8uNN94oS5cuPedB0W+//XbW3z1p0iR5//33pampSSorK2XYsGFZfX7MmDGyefPm7jkrWEQoKCjg8ccfp7y8nE2bNnHs2LGc7VRN94L00exne991XRzHIRKJnPW69PErhmHk1EuPRCKMHDmS6dOnM2TIkK+mpTmakm7bto177rmHiRMnsm7dOj7//PP8mQZm/smysjLKysq6pVJr1qzhd7/73Tmnluc6HUtrTVFREQsXLmTcuHE9Mj3MJfbs2cOePXvyOw7QnVi7di3PPfdc15wbw2DChAk9IoC+jLw8SicajXbZ0RwwYEBw3+O+KoAAgQACBAIIEAggwMUpgFzciCIfkjZ6Y5Uw26Psu72FbNumqakpK+Isy8pJ4zU1NXHixIkOHciUDubE4/GczevPFqTKp7hEtwqgrq6OJUuWtB2N3pGKhcNhdu7c2eVTtBKJBC+99BJvvfUWra2t573e8zxCoRCzZs3ie9/7Xk4Wdy677DJKS0tpbGzsMfKHDx+e3QJStmsB2eBnP/tZn7sPoGEY8tprr0ku4DiOPProoz1Wd6WU/OIXv8jqvoHdaqM60vPyDVrrnNyJAyAUCvHYY49llTvZWcRiMR599FEWLFiQXR27s1ILFy7k5MmTbN++Ha11XqdSa62JRCLccsstzJw5M2ffO2TIEH7zm98wY8YM1q1bx5EjR3LmH4gIpmkyatQoZs6cyV133UU0y32OKtPZUkrtBcaMHz+erVu3Zp36fTYn8OjRoz2aM9jZxgyHw23JJt2BEydOUF9fn7Wjdq46G4bBkCFDiMViZ2z7a6+9ll27dgHsE5G/6PFZQCQS4fLLLw8m3EBJSUlbskcQBwgQCCBAIIAAgQACBAIIkF8CSN/SJN+nbgHOH9c4X7zhjO+ePHmSDRs25M1dLQJkD8/z2LBhw3lva98+EPQlUAKErrvuOjZv3ozjOEFuXR9DmrPrr7+ed999F8AFTojI4PNZgF8CFkBDQwOrVq3q0ztfL1aICKtWraKhoSH9kuVze+aL2yURCNACSHl5uYiI2LYtAfoG0lyVl5dLJpftuT7bamAEeAQwAXbu3El1dTXhcDjwB/rIuB8Oh6murmbnzp3pl02f00hHLcBgXzEJQAYNGiRLly4VrXXQvfIcWmtZunSpDBo0SDI59Dmlo/kAp4AHgELAqqur48CBA2178gLkJ1zXRSnFgQMHqKurS4/7hT6Xp87pMJwlkfA+QAMSj8elsrJStNbium7Q1fIMruuK1loqKyslHo+ne7/2OTwj122cn0MA0/zpQxKQWCwmK1euFMuyxPO8oNXzBJ7niWVZsnLlSonFYmnykz5307oiAAXM9b1IG9CmaUp1dbU4jhP4BHky5juOI9XV1WKaZrrX2z5nc2l/7HKWAkhjnj+GeOkhoaamRhzHCSxBL/d8x3GkpqYm0+R7PlfzzjfcZyOAtD9w3P8BAaSqqkosywp8gl4a8y3LkqqqqsysYM/n6L6O+HvZCgDgWdqlIa9YsUK01kGgqIcDPVprWbFixZlSw589X4SwKwKYCywB6jItwfLly0/Lgw/QPchs2+XLl7fv+XU+N3O7UwBpzPedDCddiYqKClm2bFnbZoQAuUW6TZctWyYVFRWZ5Ds+F/M7ukaQCwGkHUMHaE1Xpri4WGpqar4Wkw7Q9bi+iEhNTY0UFxdnkt/qczCvo6TlUgAAc9pVRuLxuMyfP19Wr17d5qkG6LyXLyKyevVqmT9/fmaApzWj3edku0rYvrTPB8hWBDcBw4D/9k1RIcCIESMYN24cixYtYurUqdi2HcRqs0AkEmHDhg0sXryY3bt3Zx6GmW7j+4EjwNpsBXC+hJDO1nkB8Fs/COEBsbQQBg4cGKwkZgnTNKmvr88kPumv6kX82P7Lnc0TyGYtIFtc6S87CtDkhyIlKF0qrt+W4rftlV1NFMn1EPA18fopZQ/7FW4M+nOXUOpn8jwHnPCta5cEcM4hIMDFh2BfQCCAAIEAAly0+P8BAL8120edmHEoAAAAAElFTkSuQmCC".into()
    }
    #[cfg(not(target_os = "macos"))] // 128x128 no padding
    {
        "data:image/png;base64,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".into()
    }
}
