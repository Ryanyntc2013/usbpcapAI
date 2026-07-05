# USBPcap 驱动文件目录
#
# 将编译好的驱动文件放到对应子目录中：
#   drivers/win10/x64/  → USBPcap.inf, USBPcap.sys, USBPcapamd64.cat
#   drivers/win10/x86/  → USBPcap.inf, USBPcap.sys, USBPcapx86.cat
#   drivers/win8/x64/   → USBPcap.inf, USBPcap.sys, USBPcapamd64.cat
#   drivers/win8/x86/   → USBPcap.inf, USBPcap.sys, USBPcapx86.cat
#   drivers/win7/x64/   → USBPcap.inf, USBPcap.sys, USBPcapamd64.cat
#   drivers/win7/x86/   → USBPcap.inf, USBPcap.sys, USBPcapx86.cat
#
# 编译驱动需要使用 Windows Driver Kit (WDK)：
#   - Win7:  driver_build.bat / driver_build_win7_64bit.bat
#   - Win8+: driver_build_win8.bat
# 编译完成后从 obj 或 Win8Release 目录复制产物到此。
#
# 注意：驱动需要签名才能在 64 位 Windows 上加载。
#       测试签名：bcdedit /set testsigning on && 重启
