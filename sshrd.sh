#!/usr/bin/env sh

set -e
oscheck="Windows-x64"

ERR_HANDLER () {
    [ $? -eq 0 ] && exit
    echo "[-] An error occurred"
    #rm -rf work

}

trap ERR_HANDLER EXIT

if [ ! -e sshtars/README.md ]; then
    git submodule update --init --recursive
fi

if [ -e sshtars/ssh.tar.gz ]; then
    if [ "$oscheck" = 'Windows-x64' ]; then
        gzip -d sshtars/ssh.tar.gz
    fi
fi

if [ ! -e "$oscheck"/gaster.exe ]; then
    curl -sLO https://nightly.link/verygenericname/gaster/workflows/makefile/main/gaster-"$oscheck".zip
    unzip gaster-"$oscheck".zip
    mv gaster "$oscheck"/
   # rm -rf gaster gaster-"$oscheck".zip
fi

chmod +x "$oscheck"/*

if [ "$1" = 'clean' ]; then
    #rm -rf sshramdisk work
    echo "[*] Removed the current created SSH ramdisk"
    exit
elif [ "$1" = 'dump-blobs' ]; then
    "$oscheck"/iproxy.exe 2222 22 &>/dev/null &
    "$oscheck"/plink.exe -ssh -pw alpine -P 2222 -batch -l root 127.0.0.1 "cat /dev/rdisk1" | dd of=dump.raw bs=256 count=$((0x4000))
    "$oscheck"/img4tool.exe --convert -s dumped.shsh dump.raw
    echo "[*] Onboard blobs should have dumped to the dumped.shsh file"
    exit
	PID=$(ps aux | grep iproxy | awk '{print $2}')
kill $PID
elif [ "$1" = 'reboot' ]; then
    "$oscheck"/iproxy.exe 2222 22 &>/dev/null &
    "$oscheck"/plink.exe -ssh -pw alpine -P 2222 -batch -l root 127.0.0.1 "/sbin/reboot"
    echo "[*] Device should now reboot"
	PID=$(ps aux | grep iproxy | awk '{print $2}')
kill $PID
    exit
elif [ "$1" = 'ssh' ]; then
    "Windows-x64"/iproxy.exe 2222 22 &>/dev/null & 
    "Windows-x64"/plink.exe -ssh -pw alpine -P 2222 -batch -l root 127.0.0.1
PID=$(ps aux | grep iproxy | awk '{print $2}')
kill $PID
exit
elif [ "$oscheck" = 'Darwin' ]; then
    if ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); then
        echo "[*] Waiting for device in DFU mode"
    fi
    
    while ! (system_profiler SPUSBDataType 2> /dev/null | grep ' Apple Mobile Device (DFU Mode)' >> /dev/null); do
        sleep 1
    done
else

	if ! (wmic path Win32_PnPEntity where "Name like '%Apple Mobile Device (DFU Mode)%'" get PNPDeviceID | grep -oP 'PID_\K\d+'>> /dev/null) ; then
        echo "[*] Waiting for device in DFU mode"
		echo "[!!!]must use libusbk on dfu mode over device manager"
    fi

    #while ! (wmic path Win32_PnPEntity where "Name like '%Apple%'" get PNPClass | #findstr "libusbk" >> /dev/null) ; do
        #sleep 1
	#done

	#while ! (wmic path Win32_PnPEntity where "Name like '%Apple%'" get Service | findstr "USBAAPL64" >> /dev/null) ; do
        #sleep 1
    #done
output=$(wmic path Win32_PnPEntity where "Name like '%Apple%'" get PNPClass)

if echo "$output" | grep -q 'PWND:[GASTER]'; then
  # "PWND:[GASTER]" is in the output, run second loop
  while ! (wmic path Win32_PnPEntity where "Name like '%Apple%'" get Service | findstr "USBAAPL64" >> /dev/null) ; do
    sleep 1
  done
fi

output=$(wmic path Win32_PnPEntity where "Name like '%Apple%'" get Service)

if echo "$output" | grep -q 'PWND:[GASTER]'; then
  # "PWND:[GASTER]" is in the output, run first loop
  while ! (wmic path Win32_PnPEntity where "Name like '%Apple%'" get PNPClass | findstr "libusbk" >> /dev/null) ; do
    sleep 1
  done
fi



fi

echo "[*] Getting device info and pwning... this may take a second"
check="0x"$(wmic path Win32_PnPEntity where "Name like '%Apple%'" get PNPDeviceID | grep -oP 'CPID:\K\d+')
#echo $check
replace=$(wmic path Win32_PnPEntity where "Name like '%Apple%'" get PNPDeviceID | grep -oP 'BDID:\K\w+' | cut -d'_' -f1)
echo "[!!!]must use libusbk on dfu mode over device manager"
declare -A replaceMap
declare -A deviceIdMap

replaceMap["0E:0x8015"]="d221ap"
deviceIdMap["0E:0x8015"]="iPhone10,6"

replaceMap["06:0x8015"]="d22ap"
deviceIdMap["06:0x8015"]="iPhone10,3"

replaceMap["02:0x8015"]="d20ap"
deviceIdMap["02:0x8015"]="iPhone10,1"

replaceMap["04:0x8015"]="d21ap"
deviceIdMap["04:0x8015"]="iPhone10,2"

replaceMap["0A:0x8015"]="d201ap"
deviceIdMap["0A:0x8015"]="iPhone10,4"

replaceMap["0C:0x8015"]="d211ap"
deviceIdMap["0C:0x8015"]="iPhone10,5"

replaceMap["08:0x8010"]="d10ap"
deviceIdMap["08:0x8010"]="iPhone9,1"

replaceMap["0A:0x8010"]="d11ap"
deviceIdMap["0A:0x8010"]="iPhone9,2"

replaceMap["0C:0x8010"]="d101ap"
deviceIdMap["0C:0x8010"]="iPhone9,3"

replaceMap["0E:0x8010"]="d111ap"
deviceIdMap["0E:0x8010"]="iPhone9,4"

replaceMap["04:0x8000"]="n71ap"
deviceIdMap["04:0x8000"]="iPhone8,1"

replaceMap["04:0x8003"]="n71map"
deviceIdMap["04:0x8003"]="iPhone8,1"

replaceMap["06:0x8000"]="n66ap"
deviceIdMap["06:0x8000"]="iPhone8,2"

replaceMap["06:0x8003"]="n66map"
deviceIdMap["06:0x8003"]="iPhone8,2"

replaceMap["02:0x8000"]="n69uap"
deviceIdMap["02:0x8000"]="iPhone8,4"

replaceMap["02:0x8003"]="n69ap"
deviceIdMap["02:0x8003"]="iPhone8,4"

replaceMap["04:0x7000"]="n56ap"
deviceIdMap["04:0x7000"]="iPhone7,1"

replaceMap["06:0x7000"]="n61ap"
deviceIdMap["06:0x7000"]="iPhone7,2"

replaceMap["06:0x8011"]="j208ap"
deviceIdMap["06:0x8011"]="iPad7,4"

key="$replace:$check"

if [[ -n "${replaceMap[$key]}" ]]; then
    replace=${replaceMap[$key]}
    deviceid=${deviceIdMap[$key]}
fi
#echo $replace
#echo $deviceid

ipswurl=$(curl -sL "https://api.ipsw.me/v4/device/$deviceid?type=ipsw" | "Windows-x64"/jq '.firmwares | .[] | select(.version=="'$1'")' | "$oscheck"/jq -s '.[0] | .url' --raw-output)
#ipswurl="https://updates.cdn-apple.com/2022SummerFCS/fullrestores/012-41672/846D04AF-17E5-4EE5-97D5-143CF58C74DB/iPhone10,3,iPhone10,6_15.6_19G71_Restore.ipsw"
#echo $ipswurl
#if [ -e work ]; then
    #rm -rf work
#fi

if [ ! -e sshramdisk ]; then
    mkdir sshramdisk
fi

if [ "$1" = 'reset' ]; then
    if [ ! -e sshramdisk/iBSS.img4 ]; then
        echo "[-] Please create an SSH ramdisk first!"
        exit
    fi

    "$oscheck"/gaster.exe pwn > /dev/null
	echo "[!!]when booting must switch to itunes driver over device manager"
    #"$oscheck"/gaster.exe reset > /dev/null
    "$oscheck"/irecovery.exe -f sshramdisk/iBSS.img4
	"$oscheck"/irecovery.exe -f sshramdisk/iBSS.img4
    sleep 2
    "$oscheck"/irecovery.exe -f sshramdisk/iBEC.img4

    if [ "$check" = '0x8010' ] || [ "$check" = '0x8015' ] || [ "$check" = '0x8011' ] || [ "$check" = '0x8012' ]; then
        "$oscheck"/irecovery.exe -c go
    fi

    sleep 2
    "$oscheck"/irecovery.exe -c "setenv oblit-inprogress 5"
    "$oscheck"/irecovery.exe -c saveenv
    "$oscheck"/irecovery.exe -c reset

    echo "[*] Device should now show a progress bar and erase all data"
    exit
fi

if [ "$2" = 'TrollStore' ]; then
    if [ -z "$3" ]; then
        echo "[-] Please pass an uninstallable system app to use (Tips is a great choice)"
        exit
    fi
fi

if [ "$1" = 'boot' ]; then
    if [ ! -e sshramdisk/iBSS.img4 ]; then
        echo "[-] Please create an SSH ramdisk first!"
        exit
    fi


	"$oscheck"/irecovery.exe -f sshramdisk/iBSS.img4
	"$oscheck"/irecovery.exe -f sshramdisk/iBSS.img4
    sleep 1
    "$oscheck"/irecovery.exe -f sshramdisk/iBEC.img4

    if [ "$check" = '0x8010' ] || [ "$check" = '0x8015' ] || [ "$check" = '0x8011' ] || [ "$check" = '0x8012' ]; then
        "$oscheck"/irecovery.exe -c go
    fi
    sleep 2
    "$oscheck"/irecovery.exe -f sshramdisk/logo.img4
    "$oscheck"/irecovery.exe -c "setpicture 0x1"
    "$oscheck"/irecovery.exe -f sshramdisk/ramdisk.img4
    "$oscheck"/irecovery.exe -c ramdisk
    "$oscheck"/irecovery.exe -f sshramdisk/devicetree.img4
    "$oscheck"/irecovery.exe -c devicetree
    "$oscheck"/irecovery.exe -f sshramdisk/trustcache.img4
    "$oscheck"/irecovery.exe -c firmware
	"$oscheck"/irecovery.exe -f sshramdisk/sep.img4
    "$oscheck"/irecovery.exe -c rsepfirmware
    "$oscheck"/irecovery.exe -f sshramdisk/kernelcache.img4
    "$oscheck"/irecovery.exe -c bootx

    echo "[*] Device should now show text on screen"
    exit
fi

if [ -z "$1" ]; then
    printf "1st argument: iOS version for the ramdisk\nExtra arguments:\nreset: wipes the device, without losing version.\nTrollStore: install trollstore to system app\n"
    exit
fi

if [ ! -e work ]; then
    mkdir work
fi

"$oscheck"/gaster.exe pwn > /dev/null
"$oscheck"/img4tool.exe -e -s other/shsh/"${check}".shsh -m work/IM4M

cd work
cp ../"$oscheck"/ca-bundle.crt .
../"$oscheck"/pzb.exe -g BuildManifest.plist "$ipswurl"
echo "$(awk "/""${replace}""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" "$ipswurl"
../"$oscheck"/pzb.exe -g "$(awk "/""${replace}""/{x=1}x&&/iBSS[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" "$ipswurl"
../"$oscheck"/pzb.exe -g "$(awk "/""${replace}""/{x=1}x&&/iBEC[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" "$ipswurl"
../"$oscheck"/pzb.exe -g "$(awk "/""${replace}""/{x=1}x&&/sep-firmware[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" "$ipswurl"
../"$oscheck"/pzb.exe -g "$(awk "/""${replace}""/{x=1}x&&/DeviceTree[.]/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" "$ipswurl"

if [ "$oscheck" = 'Darwin' ]; then
    ../"$oscheck"/pzb -g Firmware/"$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)".trustcache "$ipswurl" 
else
    ../"$oscheck"/pzb.exe -g Firmware/"$(../Windows-x64/PlistBuddy BuildManifest.plist -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" | sed 's/"//g')".trustcache "$ipswurl"
fi

../"$oscheck"/pzb.exe -g "$(awk "/""${replace}""/{x=1}x&&/kernelcache.release/{print;exit}" BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" "$ipswurl"

if [ "$oscheck" = 'Darwin' ]; then
    ../"$oscheck"/pzb -g "$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)" "$ipswurl"
else
    ../"$oscheck"/pzb.exe -g "$(../Windows-x64/PlistBuddy.exe BuildManifest.plist -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" | sed 's/"//g')" "$ipswurl"
fi

cd ..

"$oscheck"/gaster.exe decrypt work/"$(awk "/""${replace}""/{x=1}x&&/iBSS[.]/{print;exit}" work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')" work/iBSS.dec
"$oscheck"/gaster.exe decrypt work/"$(awk "/""${replace}""/{x=1}x&&/iBEC[.]/{print;exit}" work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]dfu[/]//')" work/iBEC.dec
"$oscheck"/iBoot64Patcher.exe work/iBSS.dec work/iBSS.patched
"$oscheck"/img4 -i work/iBSS.patched -o sshramdisk/iBSS.img4 -M work/IM4M -A -T ibss
"$oscheck"/iBoot64Patcher.exe work/iBEC.dec work/iBEC.patched -b "rd=md0 debug=0x2014e -v wdt=-1 `if [ -z "$2" ]; then :; else echo "$2=$3"; fi` `if [ "$check" = '0x8960' ] || [ "$check" = '0x7000' ] || [ "$check" = '0x7001' ]; then echo "-restore"; fi`" -n
"$oscheck"/img4.exe -i work/iBEC.patched -o sshramdisk/iBEC.img4 -M work/IM4M -A -T ibec

"$oscheck"/img4.exe -i work/"$(awk "/""${replace}""/{x=1}x&&/kernelcache.release/{print;exit}" work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" -o work/kcache.raw
"$oscheck"/Kernel64Patcher.exe work/kcache.raw work/kcache.patched -a
"$oscheck"/kerneldiff.exe work/kcache.raw work/kcache.patched work/kc.bpatch
"$oscheck"/img4.exe -i work/"$(awk "/""${replace}""/{x=1}x&&/kernelcache.release/{print;exit}" work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1)" -o sshramdisk/kernelcache.img4 -M work/IM4M -T rkrn -P work/kc.bpatch
"$oscheck"/img4.exe -i work/"$(awk "/""${replace}""/{x=1}x&&/DeviceTree[.]/{print;exit}" work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]//')" -o sshramdisk/devicetree.img4 -M work/IM4M -T rdtr
"$oscheck"/img4.exe -i work/"$(awk "/""${replace}""/{x=1}x&&/sep-firmware[.]/{print;exit}" work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | sed 's/Firmware[/]all_flash[/]//')" -o sshramdisk/sep.img4 -M work/IM4M


if [ "$oscheck" = 'Darwin' ]; then
    "$oscheck"/img4 -i work/"$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)".trustcache -o sshramdisk/trustcache.img4 -M work/IM4M -T rtsc
    "$oscheck"/img4 -i work/"$(/usr/bin/plutil -extract "BuildIdentities".0."Manifest"."RestoreRamDisk"."Info"."Path" xml1 -o - work/BuildManifest.plist | grep '<string>' |cut -d\> -f2 |cut -d\< -f1 | head -1)" -o work/ramdisk.dmg
else
    "$oscheck"/img4.exe -i work/"$(Windows-x64/PlistBuddy.exe work/BuildManifest.plist -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" | sed 's/"//g')".trustcache -o sshramdisk/trustcache.img4 -M work/IM4M -T rtsc
    "$oscheck"/img4.exe -i work/"$(Windows-x64/PlistBuddy.exe work/BuildManifest.plist -c "Print BuildIdentities:0:Manifest:RestoreRamDisk:Info:Path" | sed 's/"//g')" -o work/ramdisk.dmg
fi

if [ "$oscheck" = 'Darwin' ]; then
    hdiutil resize -size 210MB work/ramdisk.dmg
    hdiutil attach -mountpoint /tmp/SSHRD work/ramdisk.dmg

    if [ "$replace" = 'j42dap' ]; then
        "$oscheck"/gtar -x --no-overwrite-dir -f sshtars/atvssh.tar.gz -C /tmp/SSHRD/
    elif [ "$check" = '0x8012' ]; then
        "$oscheck"/gtar -x --no-overwrite-dir -f sshtars/t2ssh.tar.gz -C /tmp/SSHRD/
        echo "[!] WARNING: T2 MIGHT HANG AND DO NOTHING WHEN BOOTING THE RAMDISK!"
    else
        "$oscheck"/gtar -x --no-overwrite-dir -f sshtars/ssh.tar.gz -C /tmp/SSHRD/
    fi

    hdiutil detach -force /tmp/SSHRD
    hdiutil resize -sectors min work/ramdisk.dmg
else
    "$oscheck"/patchtools/hfsplus.exe work/ramdisk.dmg grow 210000000

    if [ "$replace" = 'j42dap' ]; then
        "$oscheck"/patchtools/hfsplus.exe work/ramdisk.dmg untar sshtars/atvssh.tar > /dev/null
    elif [ "$check" = '0x8012' ]; then
        "$oscheck"/patchtools/hfsplus.exe work/ramdisk.dmg untar sshtars/t2ssh.tar > /dev/null
        echo "[!] WARNING: T2 MIGHT HANG AND DO NOTHING WHEN BOOTING THE RAMDISK!"
    else
        "$oscheck"/patchtools/hfsplus.exe work/ramdisk.dmg untar sshtars/ssh.tar > /dev/null
    fi
fi
#"$oscheck"/lzfse.exe -encode -i work/ramdisk.dmg -o work/ramdisk.enc
"$oscheck"/img4.exe -i work/ramdisk.dmg -o sshramdisk/ramdisk.img4 -M work/IM4M -A -T rdsk
"$oscheck"/img4.exe -i other/bootlogo.im4p -o sshramdisk/logo.img4 -M work/IM4M -A -T rlgo
echo ""
echo "[*] Cleaning up work directory"
#rm -rf work

# echo "[*] Uploading logs. If this fails, your ramdisk is still created."
# set +e
# for file in *.log; do
#    mv "$file" SUCCESS_${file}
# done
# $(curl -A SSHRD_Script -F "fileToUpload=@$(ls *.log)" http://nathan4s.lol/SSHRD_Script/log_upload.php > /dev/null)
# set -e
# echo "[*] Done uploading logs!"

echo ""
echo "[*] Finished! Please use ./sshrd.sh boot to boot your device"

# } | tee "$(date +%T)"-"$(date +%F)"-"$(uname)"-"$(uname -r)".log
