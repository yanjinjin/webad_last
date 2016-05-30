依赖
netfilter

注意
如果内核不支持netfilter
	执行make memuconfig，开启netfilter选项
	Networking-->Networking Options-->Network Packet Filtering Framework-->
	Core Netfilter Configuration(核心Netfilter配置)和IP：Netfilter Configuration （IP：Netfilter配置）

移植
1、将nf_conntrack_webad.c放到kernel-3.10/net/netfilter目录中
2、添加config NF_CONNTRACK_WEBAD
        bool "webad backup protocol support"
        default y
        depends on NETFILTER_ADVANCED
        select TEXTSEARCH
        select TEXTSEARCH_KMP
        help
           this is a andriod driver.到
	kernel-3.10/net/netfilter/Kconfig
3、添加obj-$(CONFIG_NF_CONNTRACK_WEBAD) += nf_conntrack_webad.o 到 kernel-3.10/net/netfilter/Makefile

考虑到知识产权的移植
1、上一移植方法不变
2、将编译好的nf_conntrack_webad.o文件重命名为nf_conntrack_webad.o_shipped
3、将nf_conntrack_webad.o_shipped文件替换nt_conntrack_webad.c文件

编译安装
1、在android根目录执行make命令
2、将编译出来的文件进行刷机