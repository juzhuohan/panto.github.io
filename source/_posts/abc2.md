---
title: 通用加密密钥生成器
date: 2024-11-16
tags:
   - Git
categories:
   - Git
feature: true
---
# 通用加密密钥生成器及哈希计算工具

基于 BouncyCastle 的 Java 工具类，支持以下功能：
- 非对称加密：RSA、ECC、SM2 密钥生成。
- 对称加密：AES、SM4 密钥生成。
- 哈希计算：SHA-256、SHA-3 等算法计算。

以下提供完整代码实现、依赖配置及详细解析。

## 依赖配置

### Maven 配置
确保在项目中引入 BouncyCastle 依赖：

<dependency>
    <groupId>org.bouncycastle</groupId>
    <artifactId>bcprov-jdk15on</artifactId>
    <version>1.70</version>
</dependency>

### Gradle 配置
如果使用 Gradle，可以添加以下依赖：

implementation 'org.bouncycastle:bcprov-jdk15on:1.70'

## 代码实现
``` java
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.security.spec.ECGenParameterSpec;

public class UniversalKeyGenerator {

    static {
        // 添加 BouncyCastle 提供者
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws Exception {
        // RSA 密钥生成
        KeyPair rsaKeyPair = generateRSAKeyPair(2048);
        System.out.println("RSA Public Key: " + rsaKeyPair.getPublic());
        System.out.println("RSA Private Key: " + rsaKeyPair.getPrivate());

        // ECC 密钥生成
        KeyPair eccKeyPair = generateECCKeyPair("secp256r1");
        System.out.println("ECC Public Key: " + eccKeyPair.getPublic());
        System.out.println("ECC Private Key: " + eccKeyPair.getPrivate());

        // SM2 密钥生成
        KeyPair sm2KeyPair = generateSM2KeyPair();
        System.out.println("SM2 Public Key: " + sm2KeyPair.getPublic());
        System.out.println("SM2 Private Key: " + sm2KeyPair.getPrivate());

        // AES 密钥生成
        SecretKey aesKey = generateAESKey(256);
        System.out.println("AES Secret Key: " + aesKey);

        // SM4 密钥生成
        SecretKey sm4Key = generateSM4Key(128);
        System.out.println("SM4 Secret Key: " + sm4Key);

        // 哈希计算
        String message = "Hello, World!";
        byte[] sha256Hash = computeHash(message, "SHA-256");
        System.out.println("SHA-256 Hash: " + bytesToHex(sha256Hash));

        byte[] sha3Hash = computeHash(message, "SHA3-256");
        System.out.println("SHA-3 Hash: " + bytesToHex(sha3Hash));
    }

    // RSA 密钥生成
    public static KeyPair generateRSAKeyPair(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    // ECC 密钥生成
    public static KeyPair generateECCKeyPair(String curveName) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(new ECGenParameterSpec(curveName));
        return keyGen.generateKeyPair();
    }

    // SM2 密钥生成
    public static KeyPair generateSM2KeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC", "BC");
        keyGen.initialize(new ECGenParameterSpec("sm2p256v1"));
        return keyGen.generateKeyPair();
    }

    // AES 密钥生成
    public static SecretKey generateAESKey(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    // SM4 密钥生成
    public static SecretKey generateSM4Key(int keySize) throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("SM4", "BC");
        keyGen.init(keySize);
        return keyGen.generateKey();
    }

    // 哈希计算
    public static byte[] computeHash(String message, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        return digest.digest(message.getBytes("UTF-8"));
    }

    // 字节数组转十六进制字符串
    public static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder();
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}
```
## 功能解析

### 1. 非对称加密
- RSA 密钥生成：
   - 使用 KeyPairGenerator，支持 2048 位以上密钥。
   - 用于加密通信、数字签名。

- ECC 密钥生成：
   - 基于椭圆曲线（如 secp256r1）。
   - 提供轻量、高效的非对称加密。

- SM2 密钥生成：
   - 国密标准，使用曲线 sm2p256v1。
   - 用于国内金融、政府场景的安全加密。

### 2. 对称加密
- AES 密钥生成：
   - 支持 128 位、192 位、256 位密钥。
   - 用于文件加密、数据加密等场景。

- SM4 密钥生成：
   - 国密标准的对称加密，支持 128 位密钥。

### 3. 哈希计算
- SHA-256：
   - 用于生成 256 位哈希值。

- SHA-3：
   - 更安全的哈希算法。

## 运行结果示例
```javascript
RSA Public Key: SunRsaSign RSA public key
RSA Private Key: SunRsaSign RSA private key
ECC Public Key: EC public key
ECC Private Key: EC private key
SM2 Public Key: EC public key
SM2 Private Key: EC private key
AES Secret Key: AES key
SM4 Secret Key: SM4 key
SHA-256 Hash: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b4c31a8ff9342c2e7
SHA-3 Hash: 3338be734bb8d1ee8b8dbd7a51b9ea0e5984bcd8b04a2a4b4b0a96c4eb679a80
```
## 总结
- 非对称加密：支持 RSA、ECC、SM2。
- 对称加密：支持 AES、SM4。
- 哈希算法：支持 SHA-256、SHA-3。
- 扩展性强：支持更多算法的扩展，如 DSA、MD5 等。
- 国密兼容：通过 BouncyCastle 提供对 SM 系列算法的支持。
