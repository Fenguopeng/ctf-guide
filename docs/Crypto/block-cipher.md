# 分组密码

在密码学中，分组密码（Block cipher）,又称分块加密或块密码，是一种对称密钥算法。它将明文分成多个等长的模块
## 分组密码的常见工作模式

有5种常见的模式：电子密码本（ECB）、密码分组链接（CBC）、密码反馈（CFB）、输出反馈（OFB）和计数器（CTR）模式。

### 电子密码本（ECB）

ECB（Electronic Codebook，电子密码本）

ECB模式的缺点在于同样的明文块会被加密成相同的密文块，

### 密码分组链接（CBC）

1976年，IBM发明了CBC（Cipher Block Chaining，密码分组链接）模式。在CBC模式中，每个明文块先与前一个密文块进行异或，再对其结果进行加密。

![](https://upload.wikimedia.org/wikipedia/commons/a/a4/CBC_decryption_%28zh-CN%29.svg)
### 密码反馈（CFB）
### 输出反馈（OFB）
### 计数器（CTR）

## DES

DES（Data Encryption Standard，数据加密标准）是一种对称密钥加密算法，用于加密数字数据。它是由IBM开发，并于1977年被美国国家标准局（现为国家标准与技术研究院，NIST）作为联邦信息处理标准（FIPS）发布。

## AES