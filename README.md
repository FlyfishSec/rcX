
# <img src="https://i.ibb.co/HX4pLRN/apple-touch-icon.png" alt="rcX" width="20"/>rcX
[![Build](https://github.com/FlyfishSec/rcX/actions/workflows/build.yml/badge.svg)](https://github.com/FlyfishSec/rcX/actions/workflows/build.yml)
[![Python 2.6|2.7|3.8|3.9](https://img.shields.io/badge/python-2.6|2.7|3.6|3.7|3.8|3.9|3.10-green.svg?logo=python&logoColor=yellow)](https://www.python.org/)
[![GitHub release](https://img.shields.io/github/v/tag/FlyfishSec/rcX.svg?label=release&sort=semver&color=%22blue%22)](https://github.com/FlyfishSec/rcX/releases)
[![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/LICENSE)
## What is rcX?
### "rc" - stands for remote command or remote code.
### "X" - you can understand as assistant or tool.

  The predecessor of rcX is rsGen(A Reverse Shell Payload Generator). Currently, it is a powerful Reverse/Bind shell Generator.
  More features will be added in the future.
  
![rcX](https://cdn.rawgit.com/FlyfishSec/rcX/main/rcX-png/rcX-main.png "rcX")

## Follow me
### CLI Usage
##### 1.Get a bash reverse shell and output in tabular format.
`python rcX.py -l 127.0.0.1 -p 8888 -t bash --table`
##### 2.Custom shell path.
`python rcX.py -l 127.0.0.1 -p 8888 -t bash -s "/bin/sh"`
##### 3.Copy the specified id payload to the clipboard.
`python rcX.py -l 127.0.0.1 -p 8888 -t bash --table -c 5`
##### 4.Get a base64 encoded bash reverse shell.
`python rcX.py -l 127.0.0.1 -p 8888 -t bash -e base64`
##### 5.Get a xor encoded and obfuscated bash reverse shell.
`python rcX.py -l 127.0.0.1 -p 8888 -t b#### Examle:
ash -e base64 --obf reverse`
##### 6.Get a staging bash reverse shell.
`python rcX.py -l 127.0.0.1 -p 8888 -t bash --staging-url 0 --staging-cmd 0`
##### 7.Get a staging bash reverse shell and forward local port using ngrok tunnel.
`python rcX.py -l 127.0.0.1 -p 8888 -t bash --tunnel ngrok_jp`
##### 8.Get a Windows Powershell reverse shell.
`python rcX.py -l 127.0.0.1 -p 8888 -t powershell -P windows`
#### ...

### Web UI
> At the same time, rcX also provides a web interface. 
Use rcX as a server then you can use it with your team or friends.
> Tip: When rcX is running as a server, if the request origin is not 127.0.0.1 or localhost, the ngrok tunnel feature will be disabled and the related options will be hidden on the Front-end
#### Examle:
`python rcX.py -w`
![rsGen](https://cdn.rawgit.com/FlyfishSec/rsGen/master/Screenshot/rsgen.png "rsGen")

### Web CLI
> When rcX is running as a server, you can use curl in terminal to get the payload.
#### Example:
![rsGen](https://cdn.rawgit.com/FlyfishSec/rsGen/master/Screenshot/rsgen.png "rsGen")

##### 1.Get a bash reverse shell payload
  `curl http://127.0.0.1/linux/bash/127.0.0.4/8888`

##### 2.Base64 encoded
  `curl http://127.0.0.1/linux/bash/127.0.0.4/8888/base64`

##### 3.Base64 and hex encoded
  `curl http://127.0.0.1/linux/bash/127.0.0.4/8888/base64,hex`

##### 4.Gzip compress and replace_char(obfuscation method)
  `curl http://127.0.0.1/linux/bash/127.0.0.4/8888/gzip/replace_char`

##### 5.xor encoded and reverse(obfuscation method)
  `curl http://127.0.0.1/linux/bash/127.0.0.4/8888/xor/reverse`

##### 6.Get a windows powershell reverse shell payload
  `curl http://127.0.0.1/windows/powershell/127.0.0.4/44444`

##### 6.replace_char(obfuscation method) only without using encoder
  `curl http://127.0.0.1/windows/powershell/127.0.0.4/44444/,/replace_char`

##### 7.Only use stagers, without any encoder and obfuscator
  `curl http://127.0.0.1/linux/bash/127.0.0.4/8888/,/,/1/1`

##### 8.Get a bind linux netcat shell payload
  `curl http://127.0.0.1/bind/linux/netcat/127.0.0.4/8888`


## Support rcX

|                                            Bitcoin Address QR Code                                             |                                                 Ethereum Address QR Code                                                  |                                                  Monero Address QR Code                                                   |                                                  DOGECOIN Address QR Code                                                  |
|:--------------------------------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------:|:-------------------------------------------------------------------------------------------------------------------------:|:--------------------------------------------------------------------------------------------------------------------------:|
| <img width="175" height="175" src="https://cdn.rawgit.com/FlyfishSec/rsGen/master/Screenshot/donate-btc.png"/> | <img width="175" height="175" src="https://raw.githubusercontent.com/FlyfishSec/rsGen/master/Screenshot/donate-eth.png"/> | <img width="175" height="175" src="https://raw.githubusercontent.com/FlyfishSec/rsGen/master/Screenshot/donate-xmr.png"/> | <img width="175" height="175" src="https://raw.githubusercontent.com/FlyfishSec/rsGen/master/Screenshot/donate-doge.png"/> |

**BTC**: 3F2R6KMXbJ576yJNJpjrBnhVG64Ltg1WoF

**ETH**: 0xab15323b0c7721B6B9fDf5A8089a6Ec697C9feED

**XMR**: 48rBRHh2iV27oHzXMGnjbwCLLyinpqFry6gLTAaQiFVtMRw4kqabeoFiBYqNAPCBHbKjgQezPNLwDihMSNbEPCuYP1xzCWi

**Dogecoin**: DBQATuB7t4wk56dwFqcGdqQtY8BSjL77if


