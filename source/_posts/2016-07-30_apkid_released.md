title: "APKiD Released"
tags:
	- apkid
	- research
comments: true
date: 2016-07-30 00:00
author: caleb
---

We recently gave a presentation at [HITCON 2016](http://hitcon.org/2016/CMT/) where we released a tool called: [APKiD](https://github.com/rednaga/APKiD). It's basically PEiD for Android -- it detects several compilers, obfuscators, and packers and we're adding to it whenever we find new stuff. You're welcome to submit your rules also.

For more information, check out our slides:
[Android Compiler Fingerprinting](http://hitcon.org/2016/CMT/slide/day1-r0-e-1.pdf)

We'll post the video of our talk as soon as it's available!

<!-- more -->

This is the output when it's run against our test files:

```
$ apkid test-data
[!] APKiD 0.9.3 :: from RedNaga :: rednaga.io
[*] test-data/apk/dexguard1.apk!classes.dex
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexGuard
[*] test-data/apk/dexguard2.apk!classes.dex
 |-> anti_disassembly : illegal class name
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexGuard
[*] test-data/apk/dexguard_6_1.apk!classes.dex
 |-> anti_disassembly : illegal class name
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexGuard
[*] test-data/apk/pikekapril.apk!classes.dex
 |-> compiler : dexlib 1.x
 |-> obfuscator : Bitwise AntiSkid
[*] test-data/dex/big-endian.dex
 |-> abnormal : non little-endian format
 |-> compiler : Android SDK (dx)
[*] test-data/dex/dexguard1.dex
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexGuard
[*] test-data/dex/dexguard2.dex
 |-> anti_disassembly : illegal class name
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexGuard
[*] test-data/dex/dexguard3.dex
 |-> anti_disassembly : illegal class name
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexGuard
[*] test-data/dex/dexlib1.dex
 |-> compiler : dexlib 1.x
[*] test-data/dex/dexlib2.dex
 |-> compiler : dexlib 2.x
[*] test-data/dex/dexmerge.dex
 |-> compiler : Android SDK (dexmerge)
[*] test-data/dex/dexprotector1.dex
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexProtect
[*] test-data/dex/dexprotector2.dex
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexProtect
[*] test-data/dex/dexprotector3.dex
 |-> compiler : dexlib 1.x
 |-> obfuscator : DexProtect
[*] test-data/dex/dx.dex
 |-> compiler : Android SDK (dx)
[*] test-data/dex/non-standard-header.dex
 |-> abnormal : non-standard header size
 |-> compiler : Android SDK (dx)
[*] test-data/dex/non_zero_link_offset.dex
 |-> abnormal, anti_disassembly : non-zero link offset
 |-> compiler : Android SDK (dx)
[*] test-data/dex/non_zero_link_size.dex
 |-> abnormal, anti_disassembly : non-zero link size
 |-> compiler : Android SDK (dx)
[*] test-data/samples/alibaba/apk/071d9e73a1badf763bc6bb843c51c208ad17c91b24192e79f045ed1e4fc8148a
 |-> packer : Alibaba
[*] test-data/samples/apkprotect/9ac20091b8e82c8ff2882422450e30c03043136ca009affe59e51edabf753337
 |-> packer : APKProtect
[*] test-data/samples/apkprotect/9ac20091b8e82c8ff2882422450e30c03043136ca009affe59e51edabf753337!classes.dex
 |-> compiler : dexlib 1.x
[*] test-data/samples/apkprotect/9ac20091b8e82c8ff2882422450e30c03043136ca009affe59e51edabf753337!res/raw/ister2015050620.apk
 |-> packer : Bangcle
[*] test-data/samples/baidu/ae369707b32a37f2b5c78f27418f90c54c7f84d5fd8f96a9e1595e27182b3173
 |-> packer : Baidu
[*] test-data/samples/baidu/ae369707b32a37f2b5c78f27418f90c54c7f84d5fd8f96a9e1595e27182b3173!classes.dex
 |-> compiler : Android SDK (dx)
[*] test-data/samples/bangcle/a1f851511e9ca191a97a295f7edb9bb44694b413
 |-> packer : Bangcle
[*] test-data/samples/bangcle/a1f851511e9ca191a97a295f7edb9bb44694b413!classes.dex
 |-> compiler : dexlib 2.x
[*] test-data/samples/bangcle/a1f851511e9ca191a97a295f7edb9bb44694b413!assets/com.mobi.screensaver.kansiphone3
 |-> packer : Bangcle/SecNeo (UPX)
[*] test-data/samples/bangcle/elf/bf286487b7bbd549b8cdb00dc9a80a5404ed68103ff0fffd94a85907db9c439d
 |-> packer : newer-style Bangcle/SecNeo (UPX)
[*] test-data/samples/ijiami/6d19105bedeebad4140e9b212baae4063cbd01f3
 |-> packer : Ijiami
[*] test-data/samples/ijiami/6d19105bedeebad4140e9b212baae4063cbd01f3!classes.dex
 |-> compiler : dexlib 1.x
[*] test-data/samples/ijiami/6d19105bedeebad4140e9b212baae4063cbd01f3!assets/ijm_lib/armeabi/libexec.so
 |-> packer : Ijiami (UPX)
[*] test-data/samples/jiangu/f8493d91c4250cff4d4f9a47538a2b0b39f7c4d87e6fe4035d4c304c70b5ad1c
 |-> packer : Jiangu
[*] test-data/samples/jiangu/f8493d91c4250cff4d4f9a47538a2b0b39f7c4d87e6fe4035d4c304c70b5ad1c!classes.dex
 |-> compiler : dexlib 2.x
[*] test-data/samples/kiro/061af556e934fec5fdcbec732bc7128cbf5a45012310fc8ee2f39e26bd81e982
 |-> packer : Kiro
[*] test-data/samples/kiro/061af556e934fec5fdcbec732bc7128cbf5a45012310fc8ee2f39e26bd81e982!classes.dex
 |-> compiler : dexlib 2.x
[*] test-data/samples/level/c2d3ceea0dda80e80d7def8e9ea127b9a633208ffcb106c5db3674e1c58baac4
 |-> packer : 'qdbh' (?)
[*] test-data/samples/liapp/b5be20d225edf55634621aa17988a6ed3368d4f7632c8a1eb4d3fc3b6a61c325
 |-> packer : LIAPP
[*] test-data/samples/liapp/b5be20d225edf55634621aa17988a6ed3368d4f7632c8a1eb4d3fc3b6a61c325!classes.dex
 |-> compiler : dexlib 2.x
[*] test-data/samples/medusa/b92c0090038f3185908f2fb3b7e927da734040b9332332fc09542e20c615e083
 |-> packer : Medusa
[*] test-data/samples/medusa/b92c0090038f3185908f2fb3b7e927da734040b9332332fc09542e20c615e083!classes.dex
 |-> compiler : dexlib 1.x
[*] test-data/samples/naga/89297d34ee79adf8390a173aefd31e65c47e18c7dfc0a3f1508ca2255991efb2
 |-> packer : Naga
[*] test-data/samples/naga/89297d34ee79adf8390a173aefd31e65c47e18c7dfc0a3f1508ca2255991efb2!classes.dex
 |-> compiler : Android SDK (dx)
[*] test-data/samples/nqshield/997a3986cc8437772b569d0319044764a1cbac9d296af01d77c857b887c49b48
 |-> packer : NQ Shield
[*] test-data/samples/nqshield/997a3986cc8437772b569d0319044764a1cbac9d296af01d77c857b887c49b48!classes.dex
 |-> compiler : dexlib 1.x
[*] test-data/samples/qihoo360/66126fb7d5977cf8dbac401330f25d06a9101680874ae43eb6bd201f2b92c727
 |-> packer : Qihoo 360, Tencent
[*] test-data/samples/qihoo360/66126fb7d5977cf8dbac401330f25d06a9101680874ae43eb6bd201f2b92c727!classes.dex
 |-> compiler : dexlib 1.x
[*] test-data/samples/rootkit/5ddda7355599a1819e03ee881e56453f492f6cf03674347513bf26f83b81a415
 |-> packer : UPX (unknown, unmodified)
[*] test-data/samples/tencent/66126fb7d5977cf8dbac401330f25d06a9101680874ae43eb6bd201f2b92c727
 |-> packer : Qihoo 360, Tencent
[*] test-data/samples/tencent/66126fb7d5977cf8dbac401330f25d06a9101680874ae43eb6bd201f2b92c727!classes.dex
 |-> compiler : dexlib 1.x
[*] test-data/samples/unicom_sdk/bb11a710258077213ce4281e78a1c19a940c02dc3ddaa5f1d8046380173e0da7
 |-> packer : Unicom SDK Loader
[*] test-data/samples/unicom_sdk/bb11a710258077213ce4281e78a1c19a940c02dc3ddaa5f1d8046380173e0da7!classes.dex
 |-> compiler : Android SDK (dexmerge), dexlib 1.x
 ```