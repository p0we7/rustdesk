use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Duration,
};

#[cfg(not(any(target_os = "ios")))]
use crate::{ui_interface::get_builtin_option, Connection};
use hbb_common::{
    config::{self, keys, Config, LocalConfig},
    log,
    tokio::{self, sync::broadcast, time::Instant},
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

const TIME_HEARTBEAT: Duration = Duration::from_secs(15);
const UPLOAD_SYSINFO_TIMEOUT: Duration = Duration::from_secs(120);
const TIME_CONN: Duration = Duration::from_secs(3);

#[cfg(not(any(target_os = "ios")))]
lazy_static::lazy_static! {
    static ref SENDER : Mutex<broadcast::Sender<Vec<i32>>> = Mutex::new(start_hbbs_sync());
    static ref PRO: Arc<Mutex<bool>> = Default::default();
}

#[cfg(not(any(target_os = "ios")))]
pub fn start() {
    let _sender = SENDER.lock().unwrap();
}

#[cfg(not(target_os = "ios"))]
pub fn signal_receiver() -> broadcast::Receiver<Vec<i32>> {
    SENDER.lock().unwrap().subscribe()
}

#[cfg(not(any(target_os = "ios")))]
fn start_hbbs_sync() -> broadcast::Sender<Vec<i32>> {
    let (tx, _rx) = broadcast::channel::<Vec<i32>>(16);
    std::thread::spawn(move || start_hbbs_sync_async());
    return tx;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StrategyOptions {
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub config_options: HashMap<String, String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, String>,
}

#[cfg(not(any(target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
async fn start_hbbs_sync_async() {
    log::info!("开始执行 start_hbbs_sync_async 函数");
    let mut interval = crate::rustdesk_interval(tokio::time::interval_at(
        Instant::now() + TIME_CONN,
        TIME_CONN,
    ));
    let mut last_sent: Option<Instant> = None;
    let mut info_uploaded: (bool, String, Option<Instant>, String) =
        (false, "".to_owned(), None, "".to_owned());
    let mut sysinfo_ver = "".to_owned();
    log::info!("开始进入同步循环");
    loop {
        tokio::select! {
            _ = interval.tick() => {
                log::debug!("定时器触发，开始处理同步");
                let url = heartbeat_url();
                log::info!("获取到 heartbeat_url: {}", url);
                let id = Config::get_id();
                log::info!("当前设备 ID: {}", id);
                
                if url.is_empty() {
                    log::warn!("URL为空，跳过此次循环");
                    *PRO.lock().unwrap() = false;
                    continue;
                }
                
                if config::option2bool("stop-service", &Config::get_option("stop-service")) {
                    log::warn!("服务已停止，跳过此次循环");
                    continue;
                }
                
                let conns = Connection::alive_conns();
                log::debug!("当前活跃连接数: {}", conns.len());
                
                if info_uploaded.0 && (url != info_uploaded.1 || id != info_uploaded.3) {
                    log::info!("URL或ID发生变化，需要重新上传系统信息");
                    info_uploaded.0 = false;
                    *PRO.lock().unwrap() = false;
                }
                
                // 检查是否需要上传系统信息
                let need_upload = !info_uploaded.0 && info_uploaded.2.map(|x| x.elapsed() >= UPLOAD_SYSINFO_TIMEOUT).unwrap_or(true);
                log::info!("是否需要上传系统信息: {}, 已上传: {}, 超时条件: {}", 
                           need_upload, 
                           info_uploaded.0,
                           info_uploaded.2.map(|x| x.elapsed() >= UPLOAD_SYSINFO_TIMEOUT).unwrap_or(true));
                
                if need_upload {
                    log::info!("开始准备上传系统信息");
                    let mut v = crate::get_sysinfo();
                    // username is empty in login screen of windows, but here we only upload sysinfo once, causing
                    // real user name not uploaded after login screen. https://github.com/rustdesk/rustdesk/discussions/8031
                    if !cfg!(windows) || !v["username"].as_str().unwrap_or_default().is_empty() {
                        log::debug!("系统信息验证通过，继续构建完整数据");
                        v["version"] = json!(crate::VERSION);
                        v["id"] = json!(id);
                        v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
                        
                        // 添加可选字段
                        let ab_name = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_NAME);
                        if !ab_name.is_empty() {
                            v[keys::OPTION_PRESET_ADDRESS_BOOK_NAME] = json!(ab_name);
                        }
                        let ab_tag = Config::get_option(keys::OPTION_PRESET_ADDRESS_BOOK_TAG);
                        if !ab_tag.is_empty() {
                            v[keys::OPTION_PRESET_ADDRESS_BOOK_TAG] = json!(ab_tag);
                        }
                        let username = get_builtin_option(keys::OPTION_PRESET_USERNAME);
                        if !username.is_empty() {
                            v[keys::OPTION_PRESET_USERNAME] = json!(username);
                        }
                        let strategy_name = get_builtin_option(keys::OPTION_PRESET_STRATEGY_NAME);
                        if !strategy_name.is_empty() {
                            v[keys::OPTION_PRESET_STRATEGY_NAME] = json!(strategy_name);
                        }
                        let device_group_name = get_builtin_option(keys::OPTION_PRESET_DEVICE_GROUP_NAME);
                        if !device_group_name.is_empty() {
                            v[keys::OPTION_PRESET_DEVICE_GROUP_NAME] = json!(device_group_name);
                        }
                        
                        let v_str = v.to_string();
                        log::debug!("构建的系统信息数据(前100字符): {}", v_str.chars().take(100).collect::<String>());
                        
                        // 计算哈希
                        use sha2::{Digest, Sha256};
                        let mut hasher = Sha256::new();
                        hasher.update(url.as_bytes());
                        hasher.update(&v_str.as_bytes());
                        let res = hasher.finalize();
                        let hash = hbb_common::base64::encode(&res[..]);
                        let old_hash = config::Status::get("sysinfo_hash");
                        let ver = config::Status::get("sysinfo_ver"); // sysinfo_ver is the version of sysinfo on server's side
                        
                        log::info!("当前哈希值: {}, 旧哈希值: {}", hash, old_hash);
                        
                        if hash == old_hash {
                            log::info!("哈希值相同，检查服务器版本");
                            // When the api doesn't exist, Ok("") will be returned in test.
                            let sysinfo_ver_url = url.replace("heartbeat", "sysinfo_ver");
                            log::info!("请求版本信息，URL: {}", sysinfo_ver_url);
                            
                            let samever = match crate::post_request(sysinfo_ver_url, "".to_owned(), "").await {
                                Ok(x)  => {
                                    log::info!("获取到服务器版本信息: {}", x);
                                    sysinfo_ver = x.clone();
                                    *PRO.lock().unwrap() = true;
                                    let result = x == ver;
                                    log::info!("版本比较结果: {}, 本地版本: {}", result, ver);
                                    result
                                }
                                Err(e) => {
                                    log::error!("获取服务器版本信息失败: {}", e);
                                    false // to make sure Pro can be assigned in below post for old
                                          // hbbs pro not supporting sysinfo_ver, use false for ensuring
                                }
                            };
                            
                            if samever {
                                info_uploaded = (true, url.clone(), None, id.clone());
                                log::info!("系统信息未改变，跳过上传");
                                continue;
                            }
                        }
                        
                        // 上传系统信息
                        let sysinfo_url = url.replace("heartbeat", "sysinfo");
                        log::info!("准备上传系统信息，URL: {}", sysinfo_url);
                        
                        match crate::post_request(sysinfo_url, v_str, "").await {
                            Ok(x)  => {
                                log::info!("系统信息上传响应: {}", x);
                                if x == "SYSINFO_UPDATED" {
                                    info_uploaded = (true, url.clone(), None, id.clone());
                                    log::info!("系统信息更新成功");
                                    config::Status::set("sysinfo_hash", hash);
                                    config::Status::set("sysinfo_ver", sysinfo_ver.clone());
                                    *PRO.lock().unwrap() = true;
                                } else if x == "ID_NOT_FOUND" {
                                    log::warn!("ID未找到，下次心跳将重新上传系统信息");
                                    info_uploaded.2 = None; // next heartbeat will upload sysinfo again
                                } else {
                                    log::warn!("其他响应，稍后将重试: {}", x);
                                    info_uploaded.2 = Some(Instant::now());
                                }
                            }
                            _ => {
                                info_uploaded.2 = Some(Instant::now());
                            }
                        }
                    } else {
                        log::warn!("Windows登录屏幕用户名为空，暂不上传系统信息");
                    }
                }
                
                // 检查是否需要发送心跳
                let skip_heartbeat = conns.is_empty() && last_sent.map(|x| x.elapsed() < TIME_HEARTBEAT).unwrap_or(false);
                log::debug!("是否跳过心跳: {}, 连接为空: {}, 最后发送时间条件: {}", 
                            skip_heartbeat, 
                            conns.is_empty(), 
                            last_sent.map(|x| x.elapsed() < TIME_HEARTBEAT).unwrap_or(false));
                
                if skip_heartbeat {
                    log::debug!("跳过本次心跳发送");
                    continue;
                }
                
                log::info!("准备发送心跳请求");
                last_sent = Some(Instant::now());
                let mut v = Value::default();
                v["id"] = json!(id);
                v["uuid"] = json!(crate::encode64(hbb_common::get_uuid()));
                v["ver"] = json!(hbb_common::get_version_number(crate::VERSION));
                if !conns.is_empty() {
                    v["conns"] = json!(conns);
                }
                let modified_at = LocalConfig::get_option("strategy_timestamp").parse::<i64>().unwrap_or(0);
                v["modified_at"] = json!(modified_at);
                
                let v_str = v.to_string();
                log::debug!("心跳数据(前100字符): {}", v_str.chars().take(100).collect::<String>());
                log::info!("发送心跳请求，URL: {}", url);
                
                match crate::post_request(url.clone(), v_str, "").await {
                    Ok(s) => {
                        log::info!("心跳响应(前100字符): {}", s.chars().take(100).collect::<String>());
                        if let Ok(mut rsp) = serde_json::from_str::<HashMap::<&str, Value>>(&s) {
                            if rsp.remove("sysinfo").is_some() {
                                log::info!("服务器要求强制更新系统信息");
                                info_uploaded.0 = false;
                                config::Status::set("sysinfo_hash", "".to_owned());
                            }
                            if let Some(conns)  = rsp.remove("disconnect") {
                                if let Ok(conns) = serde_json::from_value::<Vec<i32>>(conns) {
                                    log::info!("接收到断开连接请求: {:?}", conns);
                                    SENDER.lock().unwrap().send(conns).ok();
                                }
                            }
                            if let Some(rsp_modified_at) = rsp.remove("modified_at") {
                                if let Ok(rsp_modified_at) = serde_json::from_value::<i64>(rsp_modified_at) {
                                    if rsp_modified_at != modified_at {
                                        log::info!("更新策略时间戳: {} -> {}", modified_at, rsp_modified_at);
                                        LocalConfig::set_option("strategy_timestamp".to_string(), rsp_modified_at.to_string());
                                    }
                                }
                            }
                            if let Some(strategy) = rsp.remove("strategy") {
                                if let Ok(strategy) = serde_json::from_value::<StrategyOptions>(strategy) {
                                    log::info!("更新策略配置");
                                    handle_config_options(strategy.config_options);
                                }
                            }
                        } else {
                            log::warn!("解析心跳响应失败");
                        }
                    }
                    Err(e) => {
                        log::error!("发送心跳请求失败: {}", e);
                    }
                }
                log::debug!("完成本次同步循环");
            }
        }
    }
}


fn heartbeat_url() -> String {
    let url = crate::common::get_api_server(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
    );
    if url.is_empty() || url.contains("rustdesk.com") {
        return "".to_owned();
    }
    format!("{}/api/heartbeat", url)
}

fn handle_config_options(config_options: HashMap<String, String>) {
    let mut options = Config::get_options();
    config_options
        .iter()
        .map(|(k, v)| {
            if v.is_empty() {
                options.remove(k);
            } else {
                options.insert(k.to_string(), v.to_string());
            }
        })
        .count();
    Config::set_options(options);
}

#[allow(unused)]
#[cfg(not(any(target_os = "ios")))]
pub fn is_pro() -> bool {
    PRO.lock().unwrap().clone()
}
