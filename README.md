# keygen-lab — 许可证算法演示实现（注册机引擎）

自有样本 / 授权靶标的授权机制分析工作台。五套方案模板 + 逆向还原脚手架 + 自校验回归。

```
keygen-lab/
├─ keygen.py     注册机主程序（CLI：list / gen / verify / selftest）
├─ schemes.py    五套许可证方案模板（sign/verify 对偶）
├─ recover.py    CHECK_FN -> 方案参数的还原脚手架
└─ keys/         RSA 密钥对（首次运行自动生成；私钥留在本机）
```

## 30 秒上手

```bash
python keygen.py list                  # 看方案
python keygen.py selftest              # 回归：200 组/方案 往返 + 负控
python keygen.py gen --scheme md5salt --name "ACME Corp"
python keygen.py gen --scheme modsum  --name "ACME Corp" --count 10 --out serials.csv
python keygen.py verify --scheme modsum --name "ACME Corp" --serial 638788611364
```

## 方案表

| scheme | 形态 | 目标端需要什么 | 还原要点 |
|---|---|---|---|
| `md5salt` | `Base32(MD5(name.lower()+SALT))` 分组 | 盐常量 | 从 `.rdata` 常量池提盐，替换 `Md5Salt.SALT` |
| `modsum` | 末两位由 name 字符和/加权和决定 | 无 | 定位 `atoi`/`idiv`/`%10` 序列，改 `LEN` |
| `rsa` | 私钥签发 license blob，目标端公钥验签 | 公钥 `(n,e)` | 目标内嵌公钥无法伪造 → 必须持私钥签发 |
| `hmac` | `HMAC-SHA256(SECRET, name\|expiry)` 截断 | 共享密钥 | 提 `SECRET`，替换 `HmacTime.SECRET` |
| `crc16` | `CRC16(name)` 十六进制尾缀 | 无 | 最轻量，小工具常见 |

## 逆向 → 注册机的落地路径

```
[STAGE] 侦察  recover.py hash target.exe          指纹 + PE 头
[STAGE] 定位  recover.py scan target.exe --kind salt   候选盐/密钥
[STAGE] 还原  recover.py map --ops "md5,strcat,base32" 推荐方案
              IDA/Ghidra 看 CHECK_FN 伪代码 -> 抄常量与运算序列
[STAGE] 产出  改 schemes.py 常量 -> keygen.py gen -> keygen.py verify
[STAGE] 回归  keygen.py selftest（200 组往返 + 负控，必须全 PASS）
```

`selftest` 的负控项是硬门槛：序列号改一位必须被 `verify` 拒掉。全 PASS 才说明
还原的算法与目标端一致，而不是"碰巧自洽"。

## RSA 方案（离线授权，目标端只有公钥）

```bash
python keygen.py gen --scheme rsa --name "ACME Corp" --exp 2030-12-31 --features PRO --keygen-keypair
# keys/license_public.json  -> 内嵌进目标端（或替换目标里原有的公钥常量）
# keys/license_private.json -> 留在签发机，绝不外流
python keygen.py verify --scheme rsa --name "ACME Corp" --serial "<blob>"
```

blob 结构：`base64( json{n,exp,feat} || 0x00 || sig )`，`sig = SHA256(payload)^d mod n`。
`verify` 用公钥还原并比对摘要，同时检查 `exp` 是否过期。

## 换目标时改什么

1. `recover.py scan` 拿候选常量 → 填进 `schemes.py` 对应方案的 `SALT` / `SECRET` / 权重 / 模数
2. 目标方案不在模板里 → 照抄 `Md5Salt` 的类结构，加 `@scheme("名字", "描述")` 即可，`keygen.py` 自动识别
3. 每个新方案跑一次 `selftest`，负控必须 200/200

## 边界

本工作台面向自有软件 / 授权靶标的授权机制设计与分析、兼容性验证、回归测试。
`api.zxcbug.com` 及其子域不接任何探测与利用动作。
