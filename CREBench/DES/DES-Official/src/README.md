# DES Single Block Implementation

这是一个规范化的 DES (Data Encryption Standard) 实现，专注于单个 64 位块的加密和解密操作。

## 特性

- **单块加密**: 只处理单个 64 位 (8 字节) 数据块
- **标准 DES**: 完全符合 DES 规范，包括所有置换表和 S-盒
- **加密/解密**: 支持加密和解密操作
- **规范化接口**: 简洁易用的 API
- **无外部依赖**: 纯 C 实现

## 文件结构

```
src/
├── des.h          # DES 头文件，包含函数声明和常量
├── des.c          # DES 算法实现
├── example.c      # 示例程序，演示如何使用 DES
├── Makefile       # 构建脚本
└── README.md      # 本文档
```

## 编译

使用 Makefile 编译项目：

```bash
make          # 编译示例程序
make clean    # 清理编译产物
make rebuild  # 重新编译
make run      # 编译并运行示例
```

## 使用方法

### 基本用法

```c
#include "des.h"

// 准备密钥和数据 (8 字节)
uint8_t key[DES_KEY_SIZE] = {0x13, 0x34, 0x57, 0x79, 0x9B, 0xBC, 0xDF, 0xF1};
uint8_t plaintext[DES_BLOCK_SIZE] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
uint8_t ciphertext[DES_BLOCK_SIZE];
uint8_t decrypted[DES_BLOCK_SIZE];

// 生成子密钥
des_key_set key_sets[17];
des_generate_subkeys(key, key_sets);

// 加密
des_process_block(plaintext, ciphertext, key_sets, DES_ENCRYPT);

// 解密
des_process_block(ciphertext, decrypted, key_sets, DES_DECRYPT);
```

### API 参考

#### 常量

- `DES_BLOCK_SIZE`: 块大小 (8 字节)
- `DES_KEY_SIZE`: 密钥大小 (8 字节)
- `DES_ENCRYPT`: 加密模式
- `DES_DECRYPT`: 解密模式

#### 函数

- `void des_generate_key(uint8_t* key)`: 生成随机 DES 密钥
- `void des_generate_subkeys(const uint8_t* main_key, des_key_set* key_sets)`: 从主密钥生成 16 个子密钥
- `void des_process_block(const uint8_t* input, uint8_t* output, const des_key_set* key_sets, int mode)`: 处理单个数据块
- `void des_print_hex(const uint8_t* data, size_t length)`: 以十六进制格式打印数据
- `void des_print_binary(const uint8_t* data, size_t length)`: 以二进制格式打印数据

## 示例输出

运行示例程序会显示：

```
DES Single Block Encryption/Decryption Example
==============================================

Key:        13 34 57 79 9B BC DF F1
Plaintext:  01 23 45 67 89 AB CD EF
Subkeys generated successfully.

Ciphertext: 85 E8 13 54 0F 0A B4 05
Decrypted:  01 23 45 67 89 AB CD EF

✓ Encryption/Decryption successful! Plaintext matches decrypted text.
```

## 技术细节

- **算法**: DES (Data Encryption Standard)
- **块大小**: 64 位
- **密钥长度**: 56 位有效 (从 64 位密钥导出)
- **轮数**: 16 轮
- **S-盒**: 8 个 4x16 的 S-盒
- **置换表**: 初始置换、最终置换、扩展置换等

## 注意事项

- 此实现仅处理单个块，不支持 CBC、ECB 等块密码模式
- 对于多块数据的处理，需要在上层实现相应的模式
- DES 已被认为不安全，仅用于教育和兼容性目的

## 许可证

此代码基于原有的 DES 实现，经过重新组织和规范化。
