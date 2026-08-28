
# 二次开发优化

本插件在 [sqsec/BurpShiroPassiveScan](https://github.com/sqsec/BurpShiroPassiveScan) 基础上二次开发，主要优化如下：

- **GUI 配置界面**：将"基本设置"重构为二级子标签页，可直接在界面修改并一键保存到 config.yml，无需手动编辑配置文件。
- **字典导入与切换**：Shiro Key、域名黑白名单、URL 后缀黑名单均支持本地字典文件导入与下拉随时切换，方便按场景换用不同 payload 集合。
- **插件热插拔**：插件开关即时生效——关闭即中止（含正在进行的 shiro key 爆破），重新开启即恢复，且开关复位后各站点的扫描/上报上限归零，可对同一站点重新完整复测。
- **扫描次数语义修正**：站点扫描次数（siteScanNumber）改为统计插件实际指纹探测次数，而非站点地图请求总数，更符合"只测 N 次"的预期。
- **问题上报上限重置**：指纹问题数、Key 问题上限改为插件自管计数，随插件开关复位，不再被已存在于 Burp 中的历史问题卡死。
- **扫描队列增强**：新增"清空记录"按钮，可一键清空队列及右侧 Request/Response 视图。
- **多项稳定性修复**：修复 NPE、字段重叠、下拉框长文件名显示不全、字典切换计数异常等多个问题。

# 鸣谢

感谢原作者 [sqsec/BurpShiroPassiveScan](https://github.com/sqsec/BurpShiroPassiveScan) 提供的优秀基座与实现，也感谢上游 [pmiaowu/BurpShiroPassiveScan](https://github.com/pmiaowu/BurpShiroPassiveScan) 及 l1nk3r 师傅的检测思路贡献。

