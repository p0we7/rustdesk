import 'package:flutter/material.dart';
import 'package:flutter_hbb/common/widgets/trial_manager.dart'; // 引入上面的文件

class TrialBanner extends StatelessWidget {
  final VoidCallback? onExpired;
  final bool isTrialVersion;

  const TrialBanner({
    Key? key,
    this.onExpired,
    required this.isTrialVersion,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    // 如果配置关闭，直接不渲染
    if (!isTrialVersion) return const SizedBox.shrink();

    final manager = TrialManager();
    // 这里假设 manager 已经在上层初始化并计算过时间
    final expired = manager.isExpired;

    // 如果过期，触发回调（用于在上层显示弹窗）
    if (expired && onExpired != null) {
      // 使用 postFrameCallback 避免构建时调用 setState
      WidgetsBinding.instance.addPostFrameCallback((_) => onExpired!());
    }

    final colors = expired
        ? [const Color(0xFFD32F2F), const Color(0xFFC62828)]
        : [const Color(0xFFFF9800), const Color(0xFFF57C00)];
    
    final title = expired ? "试用已过期" : "试用版本";
    final message = expired
        ? "请联系管理员获取正式版本"
        : "有效期 ${TrialConfig.trialDays} 天\n剩余 ${manager.getFormattedTime()}";

    return Container(
      margin: const EdgeInsets.fromLTRB(0, 20, 0, 0),
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.centerLeft,
          end: Alignment.centerRight,
          colors: colors,
        ),
      ),
      child: Row(
        children: [
          Icon(expired ? Icons.error : Icons.access_time, color: Colors.white, size: 32),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title, style: const TextStyle(color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
                const SizedBox(height: 4),
                Text(message, style: const TextStyle(color: Colors.white, fontSize: 13, height: 1.5)),
              ],
            ),
          ),
        ],
      ),
    );
  }
}