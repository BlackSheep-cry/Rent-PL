# Rent-PL
> ***一个端口流量限制脚本，辅助用户对特定端口组进行流量统计与限制，为意欲出租转发、代理类流量的用户提供面板之外的另一种选择***

### 🛠功能特点
- 基于iptables及cron实现了端口流量统计、流量超限拦截和定期重置三大核心功能
- 高可用性，支持TCP+UDP、IPv4+IPv6
- 低破坏性，不会改动已有的iptables规则及cron任务
- 高灵活性，支持添加多组端口/端口范围/两者的组合
- 简易WEB服务，查询流量无需登录机器
- 统计指定sports+出站及指定dports+入站的流量——用于转发、代理类用途时，可视为****单向流量****

### ⚠注意事项
- 如果你****使用iptables进行流量转发，请将落地机和中转机端口保持一致****，否则脚本无法正常统计流量
- 如果你****设置的端口在动态端口范围内****(可用```sysctl net.ipv4.ip_local_port_range```查询)，****请确保端口有服务在监听****，否则有小概率多统计流量
- 在****V0.8.6前****的版本中，status命令显示的****月度限制发生变化是预期行为****，****V0.8.6及以后****则非预期

### 📑快速使用
> **以下以Debian/Ubuntu系统为示例**

****1. 安装依赖****

```
sudo apt update && sudo apt upgrade
sudo apt install iptables bc python3 wget nano openssl
```
> 其他部分发行版可能还需手动安装cron (cronie/dcron)

****2. 下载并启动脚本****
```
wget -q https://raw.githubusercontent.com/BlackSheep-cry/Rent-PL/main/rent.sh -O /usr/local/bin/rent.sh && chmod +x /usr/local/bin/rent.sh && rent.sh set
```

****3. 端口配置模板****
```
配置格式：单端口/端口范围/两者的自由组合 月度流量限制(GiB) 重置日期(1-28日)
例如：
6020-6030 100.00 1
443,80 1.5 15
5201,5202-5205 1 20 
7020-7030,7090-7095,7096-8000 10 12
PS: 组合端口时请用英文逗号隔开
```

****4-A. 交互模式****
```
sudo rent.sh
```

****4-B. 命令行模式****
```
sudo rent.sh 命令选项
```

### ⭐使用截图
|***WEB***|***交互***|
|---|---|
|![image](https://raw.githubusercontent.com/BlackSheep-cry/Rent-PL/main/images/WEB.png)|![image](https://raw.githubusercontent.com/BlackSheep-cry/Rent-PL/main/images/interactive2.png)|
