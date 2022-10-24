# Ga1axy
[![Author](https://img.shields.io/badge/Author-ol4three-blueviolet.svg)](https://github.com/ol4three)     [![Version](https://img.shields.io/badge/Version-1.0-green.svg)](https://github.com/ol4three)

### 程序简介
Ga1axy是一款用于加解密的多功能利用神器，含特定模式加解密，内建自己的Hash样本库，可以在离线环境对简单的Hash算法进行加解密，批量加解密的CLI版本，之后会继续更新界面优化版本。目前实现加解密方式如下：



| Encryption | Support |
| ---------- | ------- |
| Url        | ✅       |
| Unicode    | ✅       |
| Hex        | ✅       |
| Base16     | ✅       |
| Base32     | ✅       |
| Base64     | ✅       |
| Base85     | ✅       |
| Html       | ✅       |
| Time       | ✅       |
| Morse      | ✅       |
| Md5        | ✅       |
| Sha1       | ✅       |
| Sha224     | ✅       |
| Sha384     | ✅       |
| Sha512     | ✅       |
| Des        | ✅       |
| Aes        | ✅       |
| Jwt        | ✅       |
| base64img  | ✅       |
| Runtime    | ✅       |

------



## Args

- -M
  - e (default)
  - d 
- -key
- -iv
- -mode
  - ecb
  - cbc
  - ...
- -resu
  - hex
  - base64
- -c
  - choice mode
- -f
  - file encryption
- -o
  - output file

# Mode

## All

```
python3 Ga1axy.py -A {echo} -key 1234 -iv 1234
python3 Ga1axy.py -A o4JcYiS4szqphHpzTQKVxg== -key 1234 -iv 1234 -M d
```

![image-20221021164607237](https://oss-map.oss-cn-beijing.aliyuncs.com/img/image-20221021164607237.png)



## Url

```
python3 Ga1axy.py -url https://www.baidu.com
python3 Ga1axy.py -url https://www.baidu.com -M e
python3 Ga1axy.py -url %68%74%74%70%73%3a%2f%2f%77%77%77%2e%62%61%69%64%75%2e%63%6f%6d -M d
```

## Unicode

```
python3 Ga1axy.py -unicode 你好
python3 Ga1axy.py -unicode 你好 -M e
python3 Ga1axy.py -unicode '\u4f60\u597d' -M d
```

## Hex

```
python3 Ga1axy.py -hex aaa
python3 Ga1axy.py -hex aaa -M e
python3 Ga1axy.py -hex 616161 -M d
python3 Ga1axy.py -hex 0x610x610x61 -M d
python3 Ga1axy.py -hex '\x61\x61\x61' -M d
```

## Base

```
python3 Ga1axy.py -base aaa
python3 Ga1axy.py -base aaa -M e
python3 Ga1axy.py -base MFQWC=== -M d
```

## Html

```
python3 Ga1axy.py -html '<~!a#>'
python3 Ga1axy.py -html '<~!a#>' -M e
python3 Ga1axy.py -html '&lt;~!a#&gt;' -M d
```

## Time

```
python3 Ga1axy.py -time '2022-10-21 17:10:09'
python3 Ga1axy.py -time '2022-10-21 17:10:09' -M e
python3 Ga1axy.py -time '1666343409' -M d
```

## Runtime

```
python3 Ga1axy.py -runtime 'open -a Calculator'
python3 Ga1axy.py -runtime 'open -a Calculator' -M e
```

## Morse

```
python3 Ga1axy.py -morse ol4three
python3 Ga1axy.py -morse ol4three -M e
python3 Ga1axy.py -morse '--- .-.. ....- - .... .-. . .' -M d
```

## Md5

```
python3 Ga1axy.py -md5 123456
python3 Ga1axy.py -md5 123456 -M e
python3 Ga1axy.py -md5 e10adc3949ba59abbe56e057f20f883e -M d
```

## Des

```
python3 Ga1axy.py -des aaa -key 1234 -iv 1234
python3 Ga1axy.py -des aaa -key 1234 -iv 1234 -M e
python3 Ga1axy.py -des aaa -key 1234 -iv 1234 -M e -resu hex
python3 Ga1axy.py -des kNy9q8orGGI= -key 1234 -iv 1234 -M d
python3 Ga1axy.py -des kNy9q8orGGI= -key 1234 -iv 1234 -M d -resu base
python3 Ga1axy.py -des 90dcbdabca2b1862 -key 1234 -iv 1234 -M d -resu hex
```

## Aes

```
python3 Ga1axy.py -aes aaa -key 1234 -iv 1234
python3 Ga1axy.py -aes aaa -key 1234 -iv 1234 -M e
python3 Ga1axy.py -aes aaa -key 1234 -iv 1234 -M e -resu hex
python3 Ga1axy.py -aes 5pnlmNFAmxosZYjisJEtpA== -key 1234 -iv 1234 -M d
python3 Ga1axy.py -aes 5pnlmNFAmxosZYjisJEtpA== -key 1234 -iv 1234 -M d -resu base
python3 Ga1axy.py -aes ec14cec8ffd02caf5204b3eeb04e1363 -key 1234 -iv 1234 -M d -resu hex
```

## Jwt

```
python3 Ga1axy.py -jwt "{'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}" -key 1234
python3 Ga1axy.py -jwt "{'sub': '1234567890', 'name': 'John Doe', 'iat': 1516239022}" -key 1234 -mode none
python3 Ga1axy.py -jwt "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.B3gYryCXk5aEJpcECJizJrB1F0NWd9LogK9Ay4nf_x8" -key 1234 -M d
```

## BaseImg

```
python3 Ga1axy.py -baseimg aaa.png -M e
python3 Ga1axy.py -baseimg result/BaseImg.txt -M d
```

## Hash

```
python3 Ga1axy.py -sha1 aaa -M e
python3 Ga1axy.py -sha224 aaa -M e
python3 Ga1axy.py -sha256 aaa -M e
python3 Ga1axy.py -sha384 aaa -M e
python3 Ga1axy.py -sha512 aaa -M e
```

## File

```
python3 Ga1axy.py -f test.txt -c base64 -o base64.txt
python3 Ga1axy.py -f test.txt -c base64 -M e -o base64.txt 
python3 Ga1axy.py -f base64.txt -c base64 -M d -o base64de.txt
python3 Ga1axy.py -f test.txt -c aes -key 1234 -iv 1234 -mode cbc
python3 Ga1axy.py -f test.txt -c aes -key 1234 -iv 1234 -mode cbc -M e
python3 Ga1axy.py -f result/aes.txt -c aes -key 1234 -iv 1234 -mode cbc -M d
```

# HashDB

使用**HashDB.py** 来进行自己的本地Hash数据配置

```
python3 HashDB.py
```



# Directory

```
.
├── Ga1axy.py
├── HashDB.py
├── Readme.md
├── aaa.png
├── base
│   └── dic.txt
├── bbb.png
├── config
│   ├── md5.txt
│   ├── sha1.txt
│   ├── sha224.txt
│   ├── sha256.txt
│   ├── sha384.txt
│   └── sha512.txt
├── result
│   ├── BaseImg.png
│   ├── BaseImg.txt
│   ├── aes.txt
│   ├── base64.txt
│   ├── des.txt
│   ├── md5.txt
│   ├── sha1.txt
│   └── sha256.txt
└── test.txt
```



# Star History

[![Star History Chart](https://api.star-history.com/svg?repos=OL4THREE/Ga1axy&type=Date)](https://star-history.com/#OL4THREE/Ga1axy&Date)

