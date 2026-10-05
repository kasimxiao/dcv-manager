"""命令行部署托管组件（与控制台「系统设置 → 初始化向导」的部署步骤相同，可重复执行）。

部署到当前设置的区域：定时任务执行角色与调度组、运行历史规则与日志组、托管开机函数与关机改回规则，
并把现有「开机」定时任务升级为调用托管开机函数。

用法：cd backend && python ../provisioning/deploy_power_function.py
"""
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
import config  # noqa: E402
import setup_service  # noqa: E402

if __name__ == "__main__":
    r = config.AWS_REGION
    setup_service.ensure_scheduler(r)
    setup_service.ensure_history(r)
    arn = setup_service.ensure_power_function(r)
    time.sleep(8)  # IAM 生效
    import eb_scheduler
    n = 0
    for sc in eb_scheduler.list_all():
        if sc["action"] == "start" and not sc.get("managed_start"):
            eb_scheduler.update(sc["name"])
            n += 1
    print(f"完成：{arn}；升级开机定时任务 {n} 个")
