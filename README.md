## frp-otp

一个专注于访问安全的 [frp server manager plugin](https://github.com/fatedier/frp/blob/master/doc/server_plugin_zh.md) 实现，掌控每个接入的请求，让你对进入 `frps` 的连接了如指掌，不再裸奔。

## 快速启动

[下载地址](https://github.com/csg2008/frp-otp/releases)

### 目录介绍

```bash
* frp-otp
└─── system
|    |      frp-otp.service                  # linux 系统服务配置文件
|
│           frp-otp                          # frp-otp 程序
|           frp-otp.json                     # 通知插件配置文件
```

### 打印帮助信息

```bash
./frp-otp --h
```

### 命令行启动

```bash
./frp-otp start -c ./frp-otp.json
```

## 配置介绍

### frps

在 `frps.ini` 增加以下配置

```
[plugin.frp-otp]
addr = 127.0.0.1:9000                              // frp-otp 地址
path = /handler                                    // frp-otp url, 固定配置
ops = Login,NewProxy,NewWorkConn,NewUserConn       // 通知的操作
```

### 黑白名单配置（`IP` 过滤）

先判断白名单，后判断黑名单。如果启用强制验证，未配置到通道列表的代理默认是会拒绝访问的，否则不对请求的 IP 进行验证。已经配置到通道列表中的代理，如果运行模式配置为 bypass 默认是充许所有请求，不对请求的 IP 进行验证

```json
{
    "enforce": true,                               // 是否启用强制验证
    "domain": "zero.frp",                          // 域名
    "BindAddress": "127.0.0.1:9000",               // 服务监听的地址
    "Channel": {                                   // 通道配置
        "dev.web": {                               // 通道名
            "status": true,                        // 通道状态
            "model": "bypass",                     // 运行模式
            "secret": "...",                       // OTP 密钥，可以通过 key 命令生成
            "issuer": "dev.web",                   // OTP 组织名
            "notify": null,                        // 访问消息通知，未实现
            "blacklist": [                         // 黑名单
              "127.0.0.1"
            ],
            "whitelist": [                         // 白名单
              "127.0.0.1"
            ],
        },
        ......
    }
}
```
### 接入IP控制
如果通道配置为非 bypass 模式，就需要先访问 http://服务器IP/knock 输入对应基于时间的验证码，只在验证码通过了五分钟内才可以访问代理的通道。一个IP一分钟内只能输错五次验证码，否则就会被加入自动屏蔽的黑名单，且每尝试一次自动延长屏蔽时间五分钟，直到屏蔽时间到期。