#!/bin/bash

chmod +x macos/*


: ${1?"1st argument: ipsw link"}
: ${2?"2nd argument: board cfg, can be iphone6 for example too (no AP part, lowercase)"}
: ${3?"3rd argument: can be any shsh blob, just make sure it's from the same ecid as your phone"}
: ${4?"4th argument: iv and key combined together for the ibss from the ipsw link you provided. You can get them from the iphonewiki"}
: ${5?"5th argument: iv and key combined together for the ibec from the ipsw link you provided. You can get them from the iphonewiki"}
: ${6?"6th argument: due to the fact i have no idea how to parse a BuildManifest in a shell script, please provide the filename of the restore ramdisk dmg here"}


macos/pzb -g BuildManifest.plist $1 1> /dev/null
macos/pzb -g Firmware/dfu/iBSS.$2.RELEASE.im4p $1
macos/pzb -g Firmware/dfu/iBEC.$2.RELEASE.im4p $1
macos/pzb -g $6 $1