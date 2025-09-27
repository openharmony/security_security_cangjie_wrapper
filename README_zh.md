# 安全基础能力仓颉封装

## 简介

安全基础能力仓颉封装包括系统安全、数据安全、应用安全等功能，为OpenHarmony提供有效保护应用和用户数据的能力。当前支持的功能包括加解密算法基础功能、密钥管理功能且仅支持standard设备。

## 系统架构

**图 1** 安全基础能力仓颉架构图

![安全基础能力仓颉架构图](figures/security_cangjie_wrapper_architecture.png "安全基础能力仓颉架构图")

接口层：

- 加解密算法基础功能：加解密算法基础功能主要是为了屏蔽底层硬件和算法库，向上提供统一的密码算法库加解密相关接口。它的主要功能提供密码操作、秘钥材料和生成器、密码加解密、签名验签、安全随机数等相关功能。开发者可以通过使用该功能，忽略底层不同三方算法库的差异，实现迅捷开发。
- 密钥管理功能：密钥管理功能主要是为了向上层应用提供一套完整、统一、安全的密钥生命周期管理接口，屏蔽不同硬件安全模块和底层密钥管理服务的实现差异。它的主要功能包括：密钥生成与派生、密钥存储、密钥导入、销毁等一系列关键操作。开发者通过调用该功能，可以忽略底层不同密钥存储介质的复杂细节和安全策略差异，确保密钥材料的机密性、完整性和可用性，从而实现安全、可靠、高效的业务开发。

框架层：

- 加解密算法基础功能封装：仓颉加解密算法基础功能的实现封装，提供加解密算法基础功能。
- 密钥管理功能封装：仓颉密钥管理功能的实现封装，提供密钥管理功能。

架构图中的依赖部件引入说明：

- 加解密算法库框架：负责提供加解密、签名验签、消息验证码、哈希、安全随机数等相关功能。
- HUKS部件：负责提供密钥库能力，包括密钥管理及密钥的密码学操作等功能。
- cangjie_ark_interop：负责提供仓颉注解类定义，用于对API进行标注，以及提供抛向用户的BusinessException异常类定义。
- hiviewdfx_cangjie_wrapper：负责提供日志接口，用于在关键路径处打印日志。

## 目录

```
base/security/security_cangjie_wrapper
├── figures                         # 存放README中的架构图
├── kit                             # 仓颉安全kit化代码
|   ├── CryptoArchitectureKit       # 加解密算法库Kit
|   ├── UniversalKeystoreKit        # 设备密钥管理Kit
├── ohos                            # 仓颉安全基础能力接口实现
|   ├── crypto_framework            # 密码算法库加解密相关接口
|   └── huks                        # 密钥相关接口
|       ├── huks_key_item.cj        # 密钥管理相关接口
|       └── huks_session.cj         # 密钥会话
└── test                            # 仓颉测试代码
    ├── crypto                      # crypto测试用例
    └── security_huks               # security_huks测试用例
```

## 使用说明

当前安全基础能力仓颉封装提供了以下功能：

- 加解密算法基础功能
- 密钥管理功能

安全基础能力相关API请参见[密钥管理能力](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/UniversalKeystoreKit/cj-apis-security_huks.md)，[加解密算法库框架](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/API_Reference/source_zh_cn/apis/CryptoArchitectureKit/cj-apis-crypto.md)，相关指导请参见[加解密算法库开发指南](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/Dev_Guide/source_zh_cn/security/CryptoArchitectureKit/cj-crypto-architecture-kit-intro.md)以及[密钥管理能力](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop/blob/master/doc/Dev_Guide/source_zh_cn/security/UniversalKeystoreKit/cj-huks-overview.md)。

## 约束

与ArkTS提供的API能力相比：

- 密钥管理暂不支持以下功能：
  - 程序访问控制功能
  - 用户认证

- 暂不支持证书算法框架、证书管理功能。

## 参与贡献

欢迎广大开发者贡献代码、文档等，具体的贡献流程和方式请参见[参与贡献](https://gitcode.com/openharmony/docs/blob/master/zh-cn/contribute/%E5%8F%82%E4%B8%8E%E8%B4%A1%E7%8C%AE.md)。

## 相关仓

[arkcompiler_cangjie_ark_interop](https://gitcode.com/openharmony-sig/arkcompiler_cangjie_ark_interop)

[hiviewdfx_hiviewdfx_cangjie_wrapper](https://gitcode.com/openharmony-sig/hiviewdfx_hiviewdfx_cangjie_wrapper)

[security_crypto_framework](https://gitcode.com/openharmony/security_crypto_framework)

[security_huks](https://gitcode.com/openharmony/security_huks)
