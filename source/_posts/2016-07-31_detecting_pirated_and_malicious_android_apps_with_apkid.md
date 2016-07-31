title: "Detecting Pirated and Malicious Android Apps with APKiD"
tags:
	- apkid
	- research
comments: true
date: 2016-07-31 00:00
author: caleb
---

Android apps are much easier to modify than those of traditional desktop operating systems like Windows or Linux, and there's primarily only _one_ way to modify Android apps after they have been compiled from source: [dexlib](https://mvnrepository.com/artifact/org.smali/dexlib2). Even if you're actually using [Apktool](https://ibotpeaches.github.io/Apktool/) or [Smali](https://github.com/JesusFreke/smali), they are both using dexlib under the hood. Actually, Apktool uses Smali, and Smali and dexlib are part of the same project.

Why is this important? Any app which has had malware injected into it or has been cracked or pirated will have *probably* been disassembled and recompiled by dexlib. Also, there are very few reasons why a developer with access to the source code would use dexlib. Therefore, you know an app has been modified by dexlib, it's probably interesting to you if you're worried about malware or app piracy. This is where [APKiD](https://github.com/rednaga/APKiD) comes in. In addition to detecting packers, obfuscators, and other weird stuff, it can also identify if an app was compiled by the standard Android compilers or dexlib.
<!-- more -->

APKiD can look at an Android APK or DEX file and detect the fingerprints of several different compilers:

* dx - standard Android SDK compiler
* dexmerge - used for incremental builds by some IDEs (after using dx)
* dexlib 1.x
* dexlib 2.x beta
* dexlib 2.x

If any of the dexlib families have been used to create a DEX file, you can be fairly suspicious it has been cracked and it may have been injected with malware. For more info on how we used compiler fingerprinting to detect malware and cracks, check out our talk [Android Compiler Fingerprinting](/2016/07/30/2016-07-30_apkid_and_android_compiler_fingerprinting/).

What follows now is a technical description of how each compiler is detected.

## dx and dexmerge detection

The main way dx and dexmerge are identified are by looking at the ordering of the map types in the DEX file.

![](/images/detecting_pirated_and_malicious_android_apps_with_apkid/abnormal_type_order.png)

This is a good place to identify different compilers because the order is not defined in the spec so it's up to the compiler how it wants to order these things.

In order to have something that's copy / pastable, here's some Java code for the normal type order:

```java
private static final TypeCode[] NORMAL_TYPE_ORDER = new TypeCode[] {  TypeCode.HEADER_ITEM  , TypeCode.STRING_ID_ITEM  , TypeCode.TYPE_ID_ITEM  , TypeCode.PROTO_ID_ITEM  , TypeCode.FIELD_ID_ITEM  , TypeCode.METHOD_ID_ITEM  , TypeCode.CLASS_DEF_ITEM  , TypeCode.ANNOTATION_SET_REF_LIST  , TypeCode.ANNOTATION_SET_ITEM  , TypeCode.CODE_ITEM  , TypeCode.ANNOTATIONS_DIRECTORY_ITEM  , TypeCode.TYPE_LIST  , TypeCode.STRING_DATA_ITEM  , TypeCode.DEBUG_INFO_ITEM  , TypeCode.ANNOTATION_ITEM  , TypeCode.ENCODED_ARRAY_ITEM  , TypeCode.CLASS_DATA_ITEM  , TypeCode.MAP_LIST};
```

This is for dexmerge type order and includes links to the code that I looked at to help me understand why it's different than dx ordering:

```java// Merge type order derived from:// http://osxr.org/android/source/dalvik/dx/src/com/android/dx/merge/DexMerger.java#0111// typeIds sort is from:// http://osxr.org/android/source/dalvik/dx/src/com/android/dx/merge/DexMerger.java#0904private static final TypeCode[] DEXMERGE_TYPE_ORDER = new TypeCode[] {  TypeCode.HEADER_ITEM  , TypeCode.STRING_ID_ITEM  , TypeCode.TYPE_ID_ITEM  , TypeCode.PROTO_ID_ITEM  , TypeCode.FIELD_ID_ITEM  , TypeCode.METHOD_ID_ITEM  , TypeCode.CLASS_DEF_ITEM  , TypeCode.MAP_LIST  , TypeCode.TYPE_LIST  , TypeCode.ANNOTATION_SET_REF_LIST  , TypeCode.ANNOTATION_SET_ITEM  , TypeCode.CLASS_DATA_ITEM  , TypeCode.CODE_ITEM  , TypeCode.STRING_DATA_ITEM  , TypeCode.DEBUG_INFO_ITEM  , TypeCode.ANNOTATION_ITEM  , TypeCode.ENCODED_ARRAY_ITEM  , TypeCode.ANNOTATIONS_DIRECTORY_ITEM};
```

In general, the format of a DEX file and the items inside are like this:

```
header  HEADER_ITEMstringIds  STRING_ID_ITEMtypeIds  TYPE_ID_ITEMprotoIds  PROTO_ID_ITEMfieldIds  FIELD_ID_ITEMmethodIds  METHOD_ID_ITEMclassDefs  CLASS_DEF_ITEMwordData (sort by TYPE)  ANNOTATION_SET_REF_LIST  ANNOTATION_SET_ITEM  CODE_ITEM  ANNOTATIONS_DIRECTORY_ITEMtypeLists (no sort)  TYPE_LISTstringData (sort by INSTANCE)  STRING_DATA_ITEMbyteData (sort by TYPE)  DEBUG_INFO_ITEM  ANNOTATION_ITEM  ENCODED_ARRAY_ITEMclassData (no sort)  CLASS_DATA_ITEMmap (no sort)  MAP_LIST
```

This list may be handy for ongoing research into fingerprinting different compilers.

## dexlib 1.x detection

This is the first library that allowed disassembling and compiling of DEX files without the source code. It was created by Ben "Jesus Freke" Gruver. It's detected primarily by looking at the physical sorting of the strings.

![](/images/detecting_pirated_and_malicious_android_apps_with_apkid/abnormal_string_sort.png)

The DEX format requires that the string table, which list all the strings and their offset into the file, must be sorted alphabetically, but the actual physical ordering of the strings in the file are not necessarily sorted. So while dx sorts strings alphabetically, even though it doesn't have to, dexlib seems to sort them physically based on when they're encountered during compilation.

A lot of commercial packers and obfuscators and certain malware families still use dexlib 1.x under the hood because it's pretty solid and they're too lazy to update.

## dexlib 2.x beta detection

Dexlib 1.x was rewrriten into dexlib 2, and while it was in a beta release, we noticed that it did something weird with how it marked class interfaces.

![](/images/detecting_pirated_and_malicious_android_apps_with_apkid/abnormal_class_interfaces.png)

You can see `AC 27 00 00` all over the file. That's the offset to the "null" interface for classes which don't implement any interface. It's a good example of how flexible the DEX format is, because I would figure this wouldn't run at all, but it does. The dx compiler just uses `00`s to indicate that there's no interface.

This was removed before dexlib 2.x was moved out of beta.

## dexlib 2.x detection

This compiler is also detected by also looking at the map type order. Assembling a DEX file is complex and there are a lot of tiny little details you need to mimic to create an absolutely perfect facsimile. That's a lot of extra work most devs don't want to do.

As an aside, I spend a lot of time using this library and looking at it's code while working on a generic Android deobfuscator called [Simplify](https://travis-ci.org/CalebFenton/simplify). And I've got to say, it's some really impressive and _clean_ code that I've learned a lot from. Kudos to [Ben](https://github.com/JesusFreke).


## Ideas for the Future

This post leaves out all of the stuff [Tim](https://github.com/strazzere) found out about how Android XML files are changed by different compilers, e.g. Apktool. We still need to add these fingerprints into APKiD.

There is also a library called ASMDEX which looks capable of creating DEX files. At the time of this original research a few years ago, I didn't have time to look into it, and no one was talking about how to use it. A lot of the stuff was over my head, but I've since had a lot of practice using ASM to create Java class files, so I think I can manage now. It would be nice to add fingerprints for ASMDEX. Anything created by that would probably be pretty weird.