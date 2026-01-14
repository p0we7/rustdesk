import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
// 引入必要的 RustDesk 绑定
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/common/shared_state.dart'; // 假设 bind 在这里或 global
import 'package:flutter_hbb/common.dart'; // 引入 gFFI 和 translate 函数

/// 试用版配置
class TrialConfig {
  static bool? _isTrialVersion;

  /// 从 Rust FFI 获取是否为试用版本（编译时环境变量控制）
  static Future<bool> isTrialVersion() async {
    _isTrialVersion ??= await bind.mainIsTrialVersion();
    return _isTrialVersion!;
  }

  // 试用天数
  static const int trialDays = 1;
}

/// 试用版逻辑管理器
class TrialManager {
  static final TrialManager _instance = TrialManager._internal();
  factory TrialManager() => _instance;
  TrialManager._internal();

  int? _remainingSeconds;
  bool _dialogShown = false;

  /// 计算剩余时间
  Future<int> checkRemainingTime() async {
    if (!await TrialConfig.isTrialVersion()) return -1; // 非试用版返回 -1

    try {
      final buildDateStr = await bind.mainGetBuildDate();
      // 解析构建时间 (需确保 bind 返回格式兼容)
      final buildDate = DateTime.parse(buildDateStr.replaceAll(' ', 'T'));
      final expireDate = buildDate.add(const Duration(days: TrialConfig.trialDays));
      final remaining = expireDate.difference(DateTime.now()).inSeconds;
      _remainingSeconds = remaining;
      return remaining;
    } catch (e) {
      debugPrint("Failed to check trial date: $e");
      return 0; // 出错视为过期，或根据需求改为 -1
    }
  }

  /// 获取格式化的时间字符串
  String getFormattedTime() {
    final s = _remainingSeconds ?? 0;
    if (s <= 0) return translate("Expired");
    final hours = (s / 3600).ceil();
    return "$hours ${translate("hours")}";
  }

  bool get isExpired => (_remainingSeconds != null && _remainingSeconds! <= 0);

  /// 显示过期强制退出弹窗
  Future<void> showExpiredDialogIfNeeded() async {
    if (!await TrialConfig.isTrialVersion()) return;
    if (!isExpired || _dialogShown) return;

    _dialogShown = true;
    int countdown = 5;
    Timer? timer;

    gFFI.dialogManager.show((setState, close, context) {
      timer ??= Timer.periodic(const Duration(seconds: 1), (t) {
        if (countdown > 1) {
          setState(() => countdown--);
        } else {
          t.cancel();
          close();
          // 强制退出
          SystemNavigator.pop();
          if (Platform.isWindows) exit(0);
        }
      });

      return CustomAlertDialog(
        title: Text(translate("Trial Expired")),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Icon(Icons.warning_amber_rounded, size: 64, color: Colors.orange),
            const SizedBox(height: 16),
            Text(
              translate("trial_expired_message"),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 16),
            Text(
              translate("Closing in {} seconds...").replaceAll("{}", "$countdown"),
              style: const TextStyle(fontSize: 18, fontWeight: FontWeight.bold, color: Colors.red),
            ),
          ],
        ),
      );
    }, clickMaskDismiss: false, backDismiss: false);
  }
}