# nikki-traffic

给 nikki(mihomo)用的流量面板:按 **设备 / 节点出口 / 策略组 / 规则 / 访问目标** 统计流量,看小时、天趋势。
数据只存在你自己的路由器上(SQLite),不联网上报。

## 功能
- 设备:同一台设备的 IPv4 / 多个 IPv6 按 MAC 合并;可改名,可粘贴 `uci show dhcp` 批量导入名字;顶部可多选筛选设备
- 出口:每个节点的延迟、真实出口 IP / 位置 / 运营商(需要一次性在 nikki 里加一段配置,页面「出口」标签里有现成片段)
- 趋势:24 小时 / 48 小时 / 7 天(按小时)、14 / 30 天(按天),带表格视图
- 规则与策略组:点一行就能钻取
- 连接设置:在网页里填 nikki API 地址和密码,保存前会先验证
- 新版本提示:查 GitHub Release,更新只需一条命令

## 部署(路由器上)
```sh
mkdir -p /mnt/data/docker/nikki-traffic && cd /mnt/data/docker/nikki-traffic
# 放入 docker-compose.yml和 .env(可选)
docker compose up -d
```
打开 `http://路由器IP:8099/`,右上角「连接设置」填 nikki API(同机一般是 `http://127.0.0.1:9090`)和密码。

## 更新
```sh
cd /mnt/data/docker/nikki-traffic && docker compose pull && docker compose up -d
```
数据在 `./data`,更新不丢。旧版 v1 的数据库会自动升级。

## 发布新版本(开发者)
推一个 `v*` 标签,GitHub Actions 会构建 amd64 + arm64 镜像并推到 `ghcr.io/<owner>/nikki-traffic`,同时创建 Release。
首次发布后,到仓库 Packages 页面把该包设为 Public,路由器才能免登录拉取。

## 精度说明
- 每 10 秒采样一次 `/connections`,短于一个周期的连接看不到,连接关闭前最后一个周期的字节会丢
- 不经过 nikki 的流量(绕过大陆 IP、局域网内互访、路由器自身)统计不到;设置 `WAN_IFACE` 可在页面看到 WAN 实际总量对账
- 出口探测期间会临时切换 `egress-probe` 组,探测完自动还原;探测自己的连接不计入统计

## 测试
```sh
python3 tests/test_units.py && python3 tests/test_e2e.py
```
