移植
1.添加到
service webad /system/bin/webad
    class late_start
    user root
    group system shell inet wifi net_admin net_raw
文件/device/mediatek/mt6582/init.mt6582.rc

2.修改文件device/mediatek/common/BoardConfig.mk
在BOARD_SEPOLICY_UNION下添加webad.te

3.添加
/system/bin/webad u:object_r:webad_exec:s0
到device/mediatek/common/sepolicy/file_contexts

4.将本目录下webad.te文件拷贝到device/mediatek/common/sepolicy

5.本目录放置在external目录中

编译安装
1.可以在根目录执行make整体编译，也可以使用mmm命令单独编译
2.刷机或者单独更新编译出来的可执行程序