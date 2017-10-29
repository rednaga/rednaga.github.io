title: "Remote Kext Debugging (No, really - it worked!)"
tags:
 - kext
 - research
 - macos
 - lldb
 - gdb
 - vmware
 - kernel
 - reverse engineering
comments: true
date: 2017-04-09 00:00
author: tim
---

![](/images/remote_kext_debugging/drinking.gif)
This gif perfectly describe me attempting to connect debuggers to a kext using all the "simple" instructions on the internet.

Recently I had far too much time on my hands and a Kext binary which seemed to pique my interest. After spending a bit of time analyzing the binary in IDA Pro, I wanted to prove out some theories I had by debugging it. A while back I had set up MacOS to be running as a QEMU/KVM machine - though I no longer had access to the hardware that I set this up on. The purpose of the previous use case was to have lots of instances up (fuzzing) as opposed to in depth debugging, and I had never actually wondered about debugging the kernel. Anyhoo - I decided to revisit setting up a virtualized instance of MacOS and decided to go the VMWare Fusion route. I had a license on the computer I had in front of me, wanted to continually do snapshots, and just assumed it would be easy to get it working locally. Well, I was sort of right?
<!-- more -->

The bulk of the VMWare fusion part was just following the [knowledgebase article from VMWare](https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2129534) - there really isn't any magic to do there.

After getting the VM built and set up - all the sources I found online seem to point out you will need to disable SIP and get your host environment setup. Patrick Wardle [documented this process](https://objective-see.com/blog.html#blogEntry9) quite well over on his blog, though it didn't "just work" for me - though I kept being stumped as to why. Honestly, I still have no idea what the issue was, though I've been able to implement a workaround for the time being.
To summarize the steps from Patrick's page, we need to do the following;

 - Disable SIP on the vm
   Boot into Recovery Mode, open a terminal and type `csrutil disable`.
   Reboot the VM
 - Enable Debugging in the Guest environment
   After the VM reboots, open a terminal and change the `boot-args` by doing the following;
   ```
   $ sudo nvram boot-args="debug=0x141 pmuflags=1 -v
   ```
   Reboot the VM

This is the first step that didn't work out quite the way I had hoped. According to most sources online, setting `debug=0x141` should cause the system to prompt you with a `Waiting for remote debugger connection.` while booting up. However, this never occured for me. After Googling more and more, I couldn't really find anyone who had mentioned this issue (which is the main motivation for writing this) - so I pushed on until I found a better explanation of the boot args. According to the [Apple Developer Documentation Page](https://developer.apple.com/library/content/documentation/Darwin/Conceptual/KernelProgramming/build/build.html#//apple_ref/doc/uid/TP30000905-CH221-BABDGEGF) by setting `0x141` - these are the correct flags for us to set. Since `0x141 = (DB_HALT | DB_ARP | DB_LOG_PI_SCREEN)`, however it would appear the `DB_HALT` option is non-functional at this point in time. If anyone knows the reasoning behind the, or if this is just a weird blunder on my part, feel  free to comment here or shoot me a message. I cannot seem to find any real reasoning behind this no longer working.

The workaround for this, which I assume everyone doing kernel debugging is using at this point, is to use the `DB_NMI` flag, so the command we run to properly set up the `boot-args` will be;
   ```
   $ sudo nvram boot-args="debug=0x144 pmuflags=1 -v"
   ```
Then reboot the machine.
This allows us to have the debugger listen for *N*on-*M*asking *I*terrupts, which we can cause at any time. These can be create by pressing `Esc + Control + Option + Command` at the same time - if on a laptop where you  have turned on the "Use function keys as function keys" option, you'll need to hold the `fn` key as well. This will overlay text on the top left of your screen indicating the IP address to connect too.

 - On host, download and install Apple's "Kernel Debug Kit" which is specific to the kernel
   of the guest environment you want to debug.
 - Start `lldb` on the host machine and point it at the kernel you just downloaded
   ```
   $ lldb
   (lldb) target create /Library/Developer/KDKs/KDK_10.11.5_15F34.kdk/System/Library/Kernels/kernel.development
   (lldb) command script import "/Library/Developer/KDKs/KDK_10.11.5_15F34.kdk/System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/../Python/kernel.py
   ```

Now, if you have your guest properly set up and waiting for the debugger, you could now attach `lldb` directly to the ip address.
   ```
   (lldb) kdp-remote 172.16.210.142
   ```

Voila! Well, sort of? It did work for a short time, approximately ~60 seconds or so. The debugger appears to attach fine, breakpoints would be set and hit. Though after the first minute or so, it would seem the the remote connect somehow would continuously drop. Neither lldb or the guest environment would notice this or complain - just every command would seemingly either silently fail or error out for unknown Python reasons.

At this point I was getting a bit frustrated. I had to have done something wrong: The entire set up got trashed and I started again, checking every step to ensure I was doing it correctly. Though the resulting set up seemed to always have the same outcome - 60 or so seconds of debug time and then a reboot would be required to connect again. This clearly wasn't a workable option. I blindly started tweeting some rage about how silly debugging kernel code on MacOS seemed to be, no documentation I could find correctly explained getting it working, and seemingly no one had ever run into this problem. Magically, complaining on twitter did something and a friend I met at [Hoodsec](https://www.hoodsec.org) mentioned something along the lines of _"lldb kdb over udp is often laggy and not stable, use gdb"_. Without attempting to start an `emacs vs vim` style fight, I immediately loved the idea since I prefer `gdb` over `lldb` anyway - it just seems to be a comfort zone for me. Off to Google - more about using `gdb` to debug kexts I come across [Snare's post on the matter](http://ho.ax/posts/2012/02/vmware-hardware-debugging/).

Not only is this post simple to understand, it is essentially the exact setup I was using. Turns out that VMWare made it pretty easy for us, since they have a `debugStub` which can be enabled on any VM. Opening up the VM config file, for me it was in `~/VMs/OSX10_11_5.vmwarevm/OSX10_11_5.vmx` and adding the following lines at the bottom (while VM is not running).
```
debugStub.listen.guest32 = "TRUE"
debugStub.listen.guest64 = "TRUE"
```
This seems like it will work great, except Apple no longer ships `gdb` nor does it ship any macros to assist debugging for `gdb` anymore. Luckily someone has done all the work for us, thanks OSXreverser! Pedro wrote a great article a few years back about compiling `gdb` which can be [found on his blog](https://reverse.put.as/2013/03/20/how-to-compile-gdb-in-mountain-lion-updated/). After that, go snag the repo [gdbinit/kgmacros](https://github.com/gdbinit/kgmacros) which contains the older macros which /mostly/ work for newer kernels. If you didn't already have the `.gdbinit` script from Pedro, you should also [get and install that](https://github.com/gdbinit/Gdbinit). After getting all this preparation work done, fire the VM back up and prepare gdb before connection. Target the kernel the guest machine is using, add the symbols for it and then load the helper macros and connect to the guest.
```
diff@rigby:[~/kext_work/] $ gdb /Library/Developer/KDKs/KDK_10.11.5_15F34.kdk/System/Library/Kernels/kernel
GNU gdb 6.3.50-20050815 (Apple version gdb-1824 + reverse.put.as patches v0.4) (Sat Jan  4 20:24:02 UTC 2014)
Copyright 2004 Free Software Foundation, Inc.
GDB is free software, covered by the GNU General Public License, and you are
welcome to change it and/or distribute copies of it under certain conditions.
Type "show copying" to see the conditions.
There is absolutely no warranty for GDB.  Type "show warranty" for details.
This GDB was configured as "x86_64-apple-darwin"...
gdb$
gdb$
gdb$ add-symbol-file /Library/Developer/KDKs/KDK_10.11.5_15F34.kdk/System/Library/Kernels/kernel.dSYM/
Added dsym "/Library/Developer/KDKs/KDK_10.11.5_15F34.kdk/System/Library/Kernels/kernel.dSYM/" to "/Library/Developer/KDKs/KDK_10.11.5_15F34.kdk/System/Library/Kernels/kernel.dSYM/Contents/Resources/DWARF/kernel".
gdb$
gdb$ source  ~/repo/kgmacros/kgmacros_mavericks
Loading Kernel GDB Macros package.  Type "help kgm" for more info.
/Users/diff/repo/kgmacros/kgmacros_mavericks:6745: Error in sourced command file:
No symbol "ctrace_stack_size" in current context.
gdb$ target remote localhost:8864
[New thread 1]
warning: Error 268435459 getting port names from mach_port_names
[Switching to process 1 thread 0x0]
0xffffff801f7a25b8 in ?? ()
-----------------------------------------------------------------------------------------------------------------------[regs]
  RAX: 0x0000000000000000  RBX: 0x000000000000FFFF  RBP: 0xFFFFFF8059AB3E10  RSP: 0xFFFFFF8059AB3DF0  o d i t s z a P c
  RDI: 0xFFFFFF801FE2D120  RSI: 0x0000000000000002  RDX: 0x00000000000000BC  RCX: 0x000000000000FFFF  RIP: 0xFFFFFF801F7A25B8
  R8 : 0x0000000000000001  R9 : 0xFFFFFF8021D4A5D0  R10: 0xFFFFFF8059B05000  R11: 0xFFFFFF8059B15000  R12: 0xFFFFFF801FE2D150
  R13: 0x000000000000000A  R14: 0x0000000000000001  R15: 0x0000000000000000
  CS: 0008  DS: 0000  ES: 0000  FS: 0000  GS: 0000  SS: 0010
  -----------------------------------------------------------------------------------------------------------------------[code]
  0xffffff801f7a25b8:  83 3d d9 d2 75 00 00          cmp    DWORD PTR [rip+0x75d2d9],0x0        # 0xffffff801feff898
  0xffffff801f7a25bf:  0f 85 7b ff ff ff             jne    0xffffff801f7a2540
  0xffffff801f7a25c5:  b8 01 00 00 00                mov    eax,0x1
  0xffffff801f7a25ca:  f0 48 29 05 ce d2 75 00       lock sub QWORD PTR [rip+0x75d2ce],rax        # 0xffffff801feff8a0
  0xffffff801f7a25d2:  48 83 c4 08                   add    rsp,0x8
  0xffffff801f7a25d6:  5b                            pop    rbx
  0xffffff801f7a25d7:  41 5e                         pop    r14
  0xffffff801f7a25d9:  41 5f                         pop    r15
  -----------------------------------------------------------------------------------------------------------------------------
  Kernel is located in memory at 0xffffff801f600000 with uuid of 749F71AC-4136-320E-8416-570E59A180B4
  Kernel slid 0x1f400000 in memory.
  Current language:  auto; currently minimal
gdb$
```

Awesome! Now we have a fully functional MacOS guest and a host connected with a debugger. Haven't had any issues with disconnects yet while using `gdb`. It also might be worth noting that many people have said you can also connect `lldb` to this debugStub using it's `gdb-remote` command using the command `(lldb) gdb-remote localhost:8864`.

Afterthoughts - something very wrong might be lurking in my set up and may have been causing the udp issues with the kernel debugger,  especially since I can't really find anyone else discussing this problem. I was also loaded on pain medication due to a motorcycle  accident, so it is extremely likely that I misread something or came up with my solutions in backwards ways. Regardless, this seems to have worked. Discussing this on twitter and slack with a few people, it seems like many others rely on the VMWare debugStub - though [@i0n1c](https://twitter.com/i0n1c) disagrees with me and said there must be something wrong with my setup. He is probably correct. If I end up solving the underlying issue, I will post the solution here. This blog was primarily just to serve as a culmination of all the random things I ended up trying to get this to work so I don't have to go through the pain again. Hopefully someone else finds this useful!

Special thanks to [@tamakikusu](https://twitter.com/tamakikusu), [@OngEmil](https://twitter.com/OngEmil) and all of [@RedNagaSec](https://twitter.com/RedNagaSec) for your assistance both in knowledge, editing and insults to keep the world humble.