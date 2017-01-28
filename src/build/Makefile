export DEV_NAME=wr1043ndv4_un
all:

ifndef DEV_NAME
$(error "You have to define Dev name to use this Makefile")
endif

export TOPDIR=$(PWD)/..
export INSTALL_ROOT=$(TOPDIR)/rootfs.build.$(KERNELVER)
export INSTALL_ROOT_FOR_BOARD=$(TOPDIR)/rootfs.$(DEV_NAME)
export IMAGE_ROOT=$(TOPDIR)/rootfs-$(BOARD_TYPE).optbuild
temp_BOARD_TYPE = $(strip $(subst fus, , $(BOARD_TYPE)))
export GPL_DIR=$(TOPDIR)/$(GPL_PACKAGE_NAME)
export GPL_INSTALL_ROOT=$(GPL_DIR)/rootfs.build.$(KERNELVER)
export TMP_INSTALL_ROOT=$(TOPDIR)/rootfs.$(DEV_NAME).tmp
export GPL_TMP_INSTALL_ROOT=$(GPL_DIR)/rootfs.$(DEV_NAME).tmp
export GPL_INSTALL_ROOT_FOR_BOARD=$(GPL_DIR)/rootfs.$(DEV_NAME)
export GPL_PRODUCT_CONFIG_DIR=$(GPL_DIR)/build/products_config/$(DEV_NAME)/


#config file dirs
export PRODUCT_CONFIG_DIR=$(TOPDIR)/build/products_config/$(DEV_NAME)/
export KERNEL_CONFIG_FILE=$(PRODUCT_CONFIG_DIR)/kernel.config
export BUSYBOX_CONFIG_FILE=$(PRODUCT_CONFIG_DIR)/busybox.config
export MODEL_CONFIG_FILE=$(PRODUCT_CONFIG_DIR)/model.conf
export EMULATOR_DIR=$(TOPDIR)/EMULATOR_$(DEV_NAME)

ifeq ($(CONFIG_GUESTNETWORK),y)
BOARD_KERNEL_MODULES += br_guest_filter br_guest_mark
endif



# modules used by all boards
export BOARD_KERNEL_MODULES = stats netfilter wlan_warn ethernet br_filter ts_kmp pppol2tp pptp_module tp_domain ap_vlan art
# applications used by all board types 
export BOARD_APPLICATIONS = busybox pppoe l2tp bpa iptables tc_build net_ioctl arp


# include all necessary config files 
# include basic config file, it will give basic info
# such as toolchain,kernel version,flash size and so on 
#include scripts/$(DEV_NAME)/basic.config
include $(PRODUCT_CONFIG_DIR)/basic.config
include Makefile.modules
include Makefile.image
include snmp.mk

ifneq ($(FEATURE_FS_SIZE_CUT), y)
BOARD_KERNEL_MODULES += netsched
BOARD_APPLICATIONS += lltd
endif

ifndef BOARD_TYPE
$(error "You have to define Board type to use this Makefile")
endif

ifndef BUILD_TYPE
export BUILD_TYPE=squashfs
endif

ifndef TOOLCHAIN
$(error "Must specify TOOLCHAIN value")
endif

ifndef TOOLARCH
$(error "Must specify TOOLARCH value")
endif

ifndef KERNEL
$(error "Must specify KERNEL value")
endif

ifndef KERNELVER
$(error "Must specify KERNELVER value")
endif

ifndef KERNELTARGET
$(error "Must specify KERNELTARGET value")
endif

ifndef KERNELARCH
$(error "Must specify KERNELARCH value")
endif

ifndef TFTPPATH
export TFTPPATH=$(TOPDIR)/tftpboot/$(DEV_NAME)/
ifeq ($(GPL_BUILD), y)
export GPL_TFTPPATH=$(GPL_DIR)/tftpboot/$(DEV_NAME)/
endif
endif

# To enable library optimization (removing unused object code from
# shared libraries) set BUILD_LIBRARYOPT to 'y' else 'n'
BUILD_LIBRARYOPT := n

ifndef  BUILD_OPTIMIZED
export BUILD_OPTIMIZED=n
export STRIP=$(TOOLPREFIX)strip
endif

ifeq ($(BUILD_OPTIMIZED), y)
export OLDSTRIP=$(TOOLPREFIX)strip
export STRIP=$(TOOLPREFIX)sstrip
endif

ifndef COMPRESSED_UBOOT
export COMPRESSED_UBOOT=0
endif

ifndef FLASH_CUT_KERNEL_BLK
export FLASH_CUT_KERNEL_BLK=0
endif

ifndef ATH_CONFIG_NVRAM
export ATH_CONFIG_NVRAM=0
endif

ifndef ATH_SINGLE_CFG
export ATH_SINGLE_CFG=0
endif

ifndef INSTALL_BLACKLIST
export INSTALL_BLACKLIST="None"
endif

ifeq ($(BOOT_FROM_NAND),1)
export NAND=-nand
else
export NAND=
endif

ifeq ($(SPECIAL_ISP_DNS), y)
export SPECIAL_ISP_DNS=y
else
export SPECIAL_ISP_DNS=n
endif

ifeq ($(MODULE_IPV6_6IN4), y)
export MODULE_IPV6_6IN4=y
endif

#export IMAGEPATH=$(TOPDIR)/images/$(BOARD_TYPE)$(BUILD_CONFIG)$(BUILD_EXT)$(NAND)
export IMAGEPATH=$(TOPDIR)/images/$(DEV_NAME)
export GPL_IMAGEPATH=$(GPL_DIR)/images/$(DEV_NAME)

ifeq ($(strip $(BUILD_SQUASHFS)),1)
KERNEL_BUILD_CONFIG=_squashfs$(BUILD_CONFIG)
else
KERNEL_BUILD_CONFIG=$(BUILD_CONFIG)
endif
export FS_NAME=$(DEV_NAME)-squashfs

ifeq ($(strip $(BOARD_TYPE)),ap124)
export MAKE_SQUASHFS_TOOL=$(TOPDIR)/util/mksquashfs4-ap124
else ifneq ($(findstring $(BOARD_TYPE), ap143 ap143-2.0 db12x), )
export MAKE_SQUASHFS_TOOL=$(TOPDIR)/util/mksquashfs4-ap143
else
export MAKE_SQUASHFS_TOOL=$(TOPDIR)/util/mksquashfs4
endif

ifneq ($(findstring $(BOARD_TYPE), ap151 ap143-2.0), )
#external header include
export ACFGAPPDIR=$(TOPDIR)/$(BOARD_TYPE)/apps/acfg/common-include
export ACFGDIR=$(TOPDIR)/$(BOARD_TYPE)/apps/acfg
endif

ifeq ($(strip $(BOARD_TYPE)),ap151)
export CFG_BOARD_TYPE := $(BOARD_TYPE)
endif

ifndef MAKE_FLASH
ifeq ($(FLASH_SIZE),16)
export MAKE_FLASH=make_flash-16M
else
ifeq ($(FLASH_CUT_KERNEL_BLK),1)
export MAKE_FLASH=make_flash_ck
else
export MAKE_FLASH=make_flash
endif
endif
ifeq ($(FEATURE_USE_MAKEFLASHV3),y)
export MAKE_FLASH=make_flash_v3
endif
ifeq ($(FEATURE_UN_VERSION_CHECK),y)
export MAKE_FLASH=make_flash_v4
endif
else
endif

export MAKE_FLASH_TOOL=$(TOPDIR)/util/$(MAKE_FLASH)

export INFOFILE=vmlinux.info
export KTFILE=$(KERNELTARGET)

ifneq ($(COMPRESSED_UBOOT),1)
export UBOOTFILE=u-boot.bin
export UBOOT_BINARY=u-boot.bin
else
export UBOOTFILE=tuboot.bin
export UBOOT_BINARY=tuboot.bin
endif
export UBOOT_FILE=u-boot.bin

#
# Other environmental variables that are configured as per the configuration file
# specified above.  These contain all platform specific configuration items.
#

ifeq ($(strip $(ATH_CARR_DIR)),)
export KERNELPATH=$(TOPDIR)/$(BOARD_TYPE)/linux/kernels/$(KERNEL)
export MAKEARCH=$(MAKE) ARCH=$(KERNELARCH) CROSS_COMPILE=$(TOOLPREFIX)

export TOOLPATH=$(TOPDIR)/build/$(TOOLCHAIN)/$(TOOLARCH)/
export BOOTLOADERDIR=$(TOPDIR)/$(BOARD_TYPE)/boot/u-boot

export UBOOTDIR=$(TOPDIR)/$(BOARD_TYPE)/boot/u-boot
endif

# Save PATH for later use for compiling host-only tools etc.
#~export ORIGINAL_PATH:=$(PATH)
# Set PATH so we find target compiler when say "gcc", etc.
# as well as other tools we expect to find.
export PATH:=$(TOOLPATH)/bin:${PATH}

# madwifi
export HAL=$(TOPDIR)/$(BOARD_TYPE)/wlan/hal
export ATH_PHYERR=$(TOPDIR)/$(BOARD_TYPE)/wlan/madwifi/dfs
export ATH_RATE=$(TOPDIR)/$(BOARD_TYPE)/wlan/madwifi/ratectrl11n/
# this path is use for hostapd and wpa_supplicant, so must define this val
export ATHEROSPATH=$(TOPDIR)/$(BOARD_TYPE)/wlan
export MODULEPATH=$(INSTALL_ROOT)/lib/modules/$(KERNELVER)/net

KERNEL_MODULE_PATH=$(TOPDIR)/images/$(DEV_NAME)/kernel_modules/
GPL_KERNEL_MODULE_PATH=$(GPL_DIR)/images/$(DEV_NAME)/kernel_modules/
KERNEL_MODULES_IMAGE=$(IMAGEPATH)/kernel_modules

###new mksquashfs4.0 from LSDK9.4####
mksquashfs-ap124:
	@echo ======= Compiling $@ ========
	cd $(TOPDIR)/util/squashfs-lzma-LSDK9.4/squashfs4.0/squashfs-tools/ && make clean && make
	@echo ======= Copying $@ ========
	cp $(TOPDIR)/util/squashfs-lzma-LSDK9.4/squashfs4.0/squashfs-tools/mksquashfs $(TOPDIR)/util/mksquashfs4-ap124
	cp $(TOPDIR)/util/squashfs-lzma-LSDK9.4/squashfs4.0/squashfs-tools/mksquashfs $(TOPDIR)/util/mkfirmware/bin/mksquashfs4-ap124
	cp $(TOPDIR)/util/squashfs-lzma-LSDK9.4/squashfs4.0/squashfs-tools/unsquashfs $(TOPDIR)/util/mkfirmware/bin/unsquashfs4-ap124


######## build fakeroot host tool ########
fakeroot_build:
ifneq ($(OPENSOURCE_BUILD), y)
	cd $(TOPDIR)/util/fakeroot/fakeroot-1.18.2 && \
	if test -e Makefile; then make distclean; fi ;
	cd $(TOPDIR)/util/fakeroot/fakeroot-1.18.2 && ./configure --prefix=$(TOPDIR)/util/fakeroot/install
	cd $(TOPDIR)/util/fakeroot/fakeroot-1.18.2 && make
	cd $(TOPDIR)/util/fakeroot/fakeroot-1.18.2 && make install
ifeq ($(GPL_BUILD), y)
	mkdir -p $(GPL_DIR)/util/fakeroot
	cp -fr $(TOPDIR)/util/fakeroot/install $(GPL_DIR)/util/fakeroot
endif
endif
	
######## prepare toolchain ########
toolchain_prep:
ifneq ($(OPENSOURCE_BUILD), y)
	@echo Uncompressing toolchain, please wait for a few minutes ...
	cd $(TOPDIR)/toolchain && \
	tar -jxf gcc-4.3.3.tar.bz2 && \
	mv gcc-4.3.3 $(TOPDIR)/build
ifeq ($(GPL_BUILD), y)
	mkdir -p $(GPL_DIR)/build
	cp -fr $(TOPDIR)/build/gcc-4.3.3 $(GPL_DIR)/build/
endif
endif


#
# common build
#
fs_prep:install_root_clean util_chmod check_tftp libs_copy etc_prep empty_dir_prep modify_configs

#added by ZQQ, 2015.5.29, for some special software which need to modify the config files#
modify_configs:
ifneq ($(OPENSOURCE_BUILD), y)
#for hardware engineer to do Radio frequency certification.
ifeq ($(CONFIG_WIRELESS_RF_CERT), 1) 
	cd $(PRODUCT_CONFIG_DIR) && \
	if ! test -e modules.config.bak; then cp modules.config modules.config.bak; else echo "modules.config.bak is exist"; fi ; \
	sed -i '/MODULE_TPAPP/d' modules.config && \
	sed -i '/MODULE_TMP/d' modules.config && \
	sed -i '/MODULE_DROPBEAR/d' modules.config && \
	sed -i '/FEATURE_ENCRYPT_MD5/d' modules.config && \
	sed -i '/MODULE_HTTP_SESSION/d' modules.config && \
	sed -i '/MODULE_WIRELESS_AUTH/d' modules.config && \
	echo -e "\nMODULE_WIRELESS_AUTH=y" >> modules.config
else
	cd $(PRODUCT_CONFIG_DIR) && \
	if test -e modules.config.bak; then mv modules.config.bak modules.config; fi ;
endif
endif
	

install_root_clean:
ifneq ($(OPENSOURCE_BUILD), y)
	-rm -rf $(INSTALL_ROOT)/*
ifeq ($(GPL_BUILD), y)
	-rm -rf $(GPL_TMP_INSTALL_ROOT)/*
endif
endif
	
util_chmod:
	-cd $(TOPDIR)/util && chmod 777 cplibs md5_des mkdev mksquashfs pad $(MAKE_FLASH)
	-chmod 777 $(WEBDIR)/utils/getini/gather
	-chmod 777 $(WEBDIR)/utils/mkrc/mkrc
	-chmod 777 $(WEBDIR)/utils/mkrc/rmtag
	-chmod 777 $(WEBDIR)/utils/web_collector/webc
ifeq ($(FEATURE_WEB_NEWUI), y)
	-chmod 777 $(TOPDIR)/util/webCompress/yuicompressor.sh

ifeq ($(lang), lo)
	-chmod 777 $(TOPDIR)/util/webCompress/compressTrans.sh
endif

endif

ifeq ($(FEATURE_COMPRESSED_WEBPAGE), y)
	-chmod 777 $(TOPDIR)/util/webCompress/yuicompressor.sh
endif
	
check_tftp:
	mkdir -p $(IMAGEPATH)
	if test -d $(TFTPPATH); then echo $(TFTPPATH) exists; else mkdir -p $(TFTPPATH); fi;
ifeq ($(GPL_BUILD), y)
	mkdir -p $(GPL_IMAGEPATH)
	if test -d $(GPL_TFTPPATH); then echo $(GPL_TFTPPATH) exists; else mkdir -p $(GPL_TFTPPATH); fi;
endif

libs_copy:
	$(TOPDIR)/util/cplibs
	
dev_create:
	rm -rf $(INSTALL_ROOT)/dev/*
	$(TOPDIR)/util/mkdev

etc_prep:
	rm -rf $(INSTALL_ROOT)/etc
	cp -r $(TOPDIR)/filesystem/ap93fus/etc $(INSTALL_ROOT)/

empty_dir_prep:
	if test -d $(INSTALL_ROOT)/mnt; then echo $(INSTALL_ROOT)/mnt exists; else mkdir $(INSTALL_ROOT)/mnt; fi;
	if test -d $(INSTALL_ROOT)/proc; then echo $(INSTALL_ROOT)/proc exists; else mkdir $(INSTALL_ROOT)/proc; fi;
	if test -d $(INSTALL_ROOT)/root; then echo $(INSTALL_ROOT)/root exists; else mkdir $(INSTALL_ROOT)/root; fi;
	if test -d $(INSTALL_ROOT)/tmp; then echo $(INSTALL_ROOT)/mnt exists; else mkdir $(INSTALL_ROOT)/tmp; fi;
	if test -d $(INSTALL_ROOT)/var; then echo $(INSTALL_ROOT)/var exists; else mkdir -p $(INSTALL_ROOT)/var/run; fi;
# added by tf, /sys for mounting sysfs
	if test -d $(INSTALL_ROOT)/sys; then echo $(INSTALL_ROOT)/sys exists; else mkdir $(INSTALL_ROOT)/sys; fi;
	if test -d $(INSTALL_ROOT)/sbin; then echo $(INSTALL_ROOT)/sbin exists; else mkdir $(INSTALL_ROOT)/sbin; fi;
ifeq ($(GPL_BUILD), y)
	#if test -d $(GPL_INSTALL_ROOT)/mnt; then echo $(GPL_INSTALL_ROOT)/mnt exists; else mkdir $(GPL_INSTALL_ROOT)/mnt; fi;
	#if test -d $(GPL_INSTALL_ROOT)/proc; then echo $(GPL_INSTALL_ROOT)/proc exists; else mkdir $(GPL_INSTALL_ROOT)/proc; fi;
	#if test -d $(GPL_INSTALL_ROOT)/root; then echo $(GPL_INSTALL_ROOT)/root exists; else mkdir $(GPL_INSTALL_ROOT)/root; fi;
	#if test -d $(GPL_INSTALL_ROOT)/tmp; then echo $(GPL_INSTALL_ROOT)/mnt exists; else mkdir $(GPL_INSTALL_ROOT)/tmp; fi;
	#if test -d $(GPL_INSTALL_ROOT)/var; then echo $(GPL_INSTALL_ROOT)/var exists; else mkdir -p $(GPL_INSTALL_ROOT)/var/run; fi;
	#if test -d $(GPL_INSTALL_ROOT)/sys; then echo $(GPL_INSTALL_ROOT)/sys exists; else mkdir $(GPL_INSTALL_ROOT)/sys; fi;
	#if test -d $(GPL_INSTALL_ROOT)/sbin; then echo $(GPL_INSTALL_ROOT)/sbin exists; else mkdir $(GPL_INSTALL_ROOT)/sbin; fi;
	if test -d $(GPL_TMP_INSTALL_ROOT)/sbin; then echo $(GPL_TMP_INSTALL_ROOT)/sbin exists; else mkdir -p $(GPL_TMP_INSTALL_ROOT)/sbin; fi;
endif
ifeq ($(OPENSOURCE_BUILD), y)
	cp $(TMP_INSTALL_ROOT)/sbin/* $(INSTALL_ROOT)/sbin
endif
	
CLEANDIR=ap121 ap123 ap123-dsa ap124 ap143 db12x ap143-2.0 pb92 ap151 ap135_hnat apps kernel_modules debug_tools 

tpclean:
	@echo clean build environment
	if ! test -d $(TOPDIR)/build/allimages; then rm -rf $(TFTPPATH) && rm -rf $(IMAGEPATH); else echo "build all products"; fi;
	rm -rf $(INSTALL_ROOT_FOR_BOARD)
	rm -rf $(INSTALL_ROOT)
	for dir in $(CLEANDIR); do \
		if test -d $(TOPDIR)/$$dir; then find $(TOPDIR)/$$dir -name "*.o" | xargs rm -rf; fi; \
	done

#build kernel
kernel_clean: 
	cd $(KERNELPATH) &&  $(MAKEARCH) mrproper 

kernel_build:
ifeq ($(GPL_BUILD), y)
	$(MAKE) kernel_clean
	mkdir -p $(GPL_DIR)/$(BOARD_TYPE)/linux
	cp -fr $(TOPDIR)/$(BOARD_TYPE)/linux/kernels $(GPL_DIR)/$(BOARD_TYPE)/linux/
endif
	@echo " Making Kernel Build Version $(EXTRAVERSION)" at `date`
	cd $(KERNELPATH) && find . -name "*.ko" |xargs rm -rf 
	cd $(KERNELPATH) && $(MAKEARCH) TP_CONFIG_FILE=$(KERNEL_CONFIG_FILE) $(DEV_NAME)_defconfig
	cd $(KERNELPATH) && $(MAKEARCH) $(KERNELTARGET)
	cd $(KERNELPATH) && $(MAKEARCH) modules
	cd $(KERNELPATH)/arch/$(KERNELARCH)/boot && \
	cp $(KERNELTARGET) $(TFTPPATH)/$(KTFILE) && \
	cp $(KERNELTARGET) $(IMAGEPATH)/$(KTFILE) && \
	rm -rf $(KERNELTARGET).lzma && \
	$(TOPDIR)/util/lzma/bin/lzma --best --keep $(KERNELTARGET) && \
	cp $(KERNELTARGET).lzma $(TFTPPATH)/$(KTFILE).gz && \
	cp $(KERNELTARGET).lzma $(IMAGEPATH)/$(KTFILE).gz && \
	cp $(KERNELPATH)/vmlinux $(IMAGEPATH)/vmlinux

#build ethernet driver
export ENETDIR=$(TOPDIR)/$(BOARD_TYPE)/linux/drivers/ethernet/
ifeq ($(strip $(BOARD_TYPE)),ap143-2.0) 
export SSDK_DIR=$(TOPDIR)/$(BOARD_TYPE)/linux/drivers/s17_ssdk
else
export SSDK_DIR=$(ENETDIR)/s17_ssdk
endif
export ENET_COPY_DIR=$(TOPDIR)/$(BOARD_TYPE)/binary/ethernet/$(DEV_NAME)

#if you have ethernet dirver code,then will execute enet_build_copy rule
#it will compile driver and copy it to your image directory
ifeq ($(strip $(ETH_CONFIG)), _s17_hwaccel)
ifeq ($(strip $(BOARD_TYPE)),ap152)
enet_build_copy: ssdk_build ssdk_shell_build
else
enet_build_copy: ssdk_build
endif
else
enet_build_copy: 
endif
	cd $(ENETDIR) && rm -f *.o *.ko *.mod.* && make -f Makefile.inc enet_config.h 
	cd $(ENETDIR) && rm -f *.o *.ko *.mod.*
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(ENETDIR) modules
	test -d $(MODULEPATH) || mkdir -p $(MODULEPATH)
	cp $(ENETDIR)/athrs_gmac.ko $(KERNEL_MODULE_PATH)/ag7240_mod.ko
ifeq ($(GPL_BUILD), y)
	cp $(ENETDIR)/athrs_gmac.ko $(GPL_KERNEL_MODULE_PATH)/ag7240_mod.ko
endif

#if you have no ethernet dirver code,then will execute enet_copy rule 
#it will just copy dirver from svn for you
enet_copy:
	@echo "Just copy ethernet driver for you"
	cp $(ENET_COPY_DIR)/ag7240_mod.ko $(KERNEL_MODULE_PATH)/ag7240_mod.ko
	@echo "End copy ethernet driver for you"

ifeq ($(strip $(BOARD_TYPE)),ap152)
#for hardware NAT
ssdk_build:
	@echo making SSDK....
	cd $(SSDK_DIR) && \
	$(MAKE) clean; $(MAKE) && \
	cp build/bin/ssdk_ks_km.a $(ENETDIR)/phys/
	@echo end of making SSDK

SSDK_SHELL_DIR=$(TOPDIR)/$(BOARD_TYPE)/linux/drivers/s17_ssdk_shell
ssdk_shell_build:
	@echo making SSDK_SHELL....
	cd $(SSDK_SHELL_DIR) && \
	$(MAKE) clean; $(MAKE); \
	cp build/bin/ssdk_sh $(INSTALL_ROOT)/sbin/ssdk_sh
	@echo end of making SSDK_SHELL
else
#for hardware NAT
ssdk_build:
	@echo making SSDK....
	cd $(SSDK_DIR) && \
	$(MAKE) clean; $(MAKE) && \
	cp build/bin/ssdk_ks_km.a $(ENETDIR)/phys/ && \
	cp build/bin/ssdk_sh $(INSTALL_ROOT)/sbin/ssdk_sh
	@echo end of making SSDK

endif

#new ethernet rule for somebody may have no ethernet driver code 
ethernet:
ifneq ($(OPENSOURCE_BUILD), y)
	@if test -f $(ENETDIR)/Makefile;then \
	$(MAKE) enet_build_copy; \
	else $(MAKE) enet_copy; \
	fi
endif

ethernet_clean:
	@if test -f $(ENETDIR)/Makefile;then \
	cd $(ENETDIR) && rm -f *.o *.ko *.mod.*  && make clean; \
	else echo "Do nothing for ethernet clean"; \
	fi

#build bootloader
uboot_clean:
	@if test -f $(UBOOTDIR)/Makefile;then \
	echo Making uboot clean; \
	cd $(UBOOTDIR) && $(MAKEARCH) distclean; \
	else echo "Do nothing for clean uboot"; \
	fi

#if you have no uboot code,then you will execute uboot_copy
#this rule will just copy uboot from svn for you 
UBOOT_COPY_DIR=$(TOPDIR)/$(BOARD_TYPE)/binary/u-boot/$(DEV_NAME)/
uboot_copy:
	@echo "Just copy uboot for your"
	cp -f $(UBOOT_COPY_DIR)/$(UBOOT_FILE) ${IMAGEPATH}/$(UBOOT_FILE)
	cp -f $(UBOOT_COPY_DIR)/$(UBOOT_FILE) $(TFTPPATH)/$(UBOOT_FILE)
	@echo "End copy uboot for your"

#if you have uboot code,then you will execute uboot_build_copy
#this rule will compile your uboot code and copy uboot to your image direcory
uboot_build_copy:
	@echo Making uboot at `date`
	cd $(UBOOTDIR) && $(MAKEARCH) mrproper
	cd $(UBOOTDIR) && $(MAKEARCH) $(BOARD_TYPE)_config
	@echo ========= build dir: $(TOPDIR)/build ============
	cd $(UBOOTDIR) && $(MAKEARCH) all BUILD_DIR=$(TOPDIR)/build
	cp -f $(UBOOTDIR)/${UBOOT_BINARY} ${IMAGEPATH}/$(UBOOT_FILE)
	cp -f $(UBOOTDIR)/${UBOOT_BINARY} $(TFTPPATH)/$(UBOOT_FILE)
	@echo End Making uboot at `date`

#new uboot rule for somebody may have no uboot code
uboot:
ifeq ($(GPL_BUILD), y)
	$(MAKE) uboot_clean
	cp -fr $(UBOOTDIR) $(GPL_DIR)/$(BOARD_TYPE)/boot/
endif
	@if test -f $(UBOOTDIR)/Makefile;then \
	$(MAKE) uboot_build_copy;\
	else $(MAKE) uboot_copy; \
	fi

####################################### wireless ##########################################
#building hostapd and supplicant 8.0 versions for WPS 2.0
ATHR_HOSTAPD_PATH=$(TOPDIR)/ap136/apps/athr-hostap/hostapd

athr-hostapd:
ifneq ($(OPENSOURCE_BUILD), y)
	@echo Making athr-hostapd  at `date`
	cp -f $(TOPDIR)/build/scripts/ap136/athr_hostapd.conf $(TOPDIR)/$(BOARD_TYPE)/apps/athr-hostap/hostapd/.config; \
	cd $(ATHR_HOSTAPD_PATH); make clean; make CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld; \
	cp hostapd hostapd_cli $(WIRELESSPACKAGEPATH)
ifeq ($(GPL_BUILD), y)
	cd $(ATHR_HOSTAPD_PATH) && cp hostapd hostapd_cli $(GPL_WIRELESSPACKAGEPATH)
endif
endif

ATHR_WPA_SUPPLICANT_PATH=$(TOPDIR)/ap136/apps/athr-hostap/wpa_supplicant
athr-wpa_supplicant:
ifneq ($(OPENSOURCE_BUILD), y)
	@echo Making athr wpa_supplicant  at `date`
	cp -f $(TOPDIR)/build/scripts/ap136/athr_supplicant.conf $(TOPDIR)/$(BOARD_TYPE)/apps/athr-hostap/wpa_supplicant/.config; \
	cd $(ATHR_WPA_SUPPLICANT_PATH); make clean; make CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld; \
	cp wpa_supplicant $(WIRELESSPACKAGEPATH)
ifeq ($(GPL_BUILD), y)
	cd $(ATHR_WPA_SUPPLICANT_PATH) && cp wpa_supplicant $(GPL_WIRELESSPACKAGEPATH)
endif
endif

athr-hostapd_clean:
	@echo Making athr-hostapd  clean
	cp -f $(TOPDIR)/build/scripts/ap136/athr_hostapd.conf $(TOPDIR)/$(BOARD_TYPE)/apps/athr-hostap/hostapd/.config; \
	cd $(ATHR_HOSTAPD_PATH); make clean

athr-wpa_supplicant_clean:
	@echo Making athr wpa_supplicant  at `date`
	cp -f $(TOPDIR)/build/scripts/ap136/athr_supplicant.conf $(TOPDIR)/$(BOARD_TYPE)/apps/athr-hostap/wpa_supplicant/.config; \
	cd $(ATHR_WPA_SUPPLICANT_PATH); make clean

WPA_COMMON_LIB_PATH=$(TOPDIR)/$(BOARD_TYPE)/apps/common
wpa_common_lib:
	cd $(WPA_COMMON_LIB_PATH) && make clean && make CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld all
	cp $(WPA_COMMON_LIB_PATH)/libwpa_common.so $(WIRELESSPACKAGEPATH)
	cp $(WPA_COMMON_LIB_PATH)/libwpa_ctrl.so $(WIRELESSPACKAGEPATH)
	
WPA2_COMMON_LIB_PATH=$(TOPDIR)/ap136/apps/athr-hostap/src/common
wpa2_common_lib:
ifneq ($(OPENSOURCE_BUILD), y)
	cd $(WPA2_COMMON_LIB_PATH) && make --file=Makefile.common common_clean && make --file=Makefile.common CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld common_lib
	cp $(WPA2_COMMON_LIB_PATH)/libwpa_ctrl.so $(WIRELESSPACKAGEPATH)
ifeq ($(GPL_BUILD), y)
	cp $(WPA2_COMMON_LIB_PATH)/libwpa_ctrl.so $(GPL_WIRELESSPACKAGEPATH)
endif
endif

wpa2_common_lib_clean:
	cd $(WPA2_COMMON_LIB_PATH) && make --file=Makefile.common common_clean
#end building hostapd and supplicant 8.0 versions for WPS 2.0

############### spectral app ################################
SPECTRAL_APP_PATH=$(TOPDIR)/$(BOARD_TYPE)/apps/spectral
spectral_app_clean:
	@echo Cleaning spectral
	cd $(SPECTRAL_APP_PATH) && make clean;

spectral_app_build: spectral_app_clean
	@echo making Spectral tools
	cd $(SPECTRAL_APP_PATH) && make CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld -f Makefile
	cp $(SPECTRAL_APP_PATH)/ssd $(WIRELESSPACKAGEPATH)
	cp $(SPECTRAL_APP_PATH)/athssd $(WIRELESSPACKAGEPATH)
############### END spectral app ##############################

############### AC CFG ########################################
ACFGDIR=$(TOPDIR)/$(BOARD_TYPE)/apps/acfg
acfg_clean:
	@echo "Cleaning the ACFG Library ..."
	cd $(ACFGDIR)/src &&  \
	$(MAKEARCH) TARGET=$(TARGETARCH) clean 

acfg_build:
	@echo "Building the ACFG Library ..."
	cd $(ACFGDIR)/src &&   \
	$(MAKEARCH) TARGET=$(TARGETARCH) && \
	$(MAKEARCH) DESTDIR=$(WIRELESSPACKAGEPATH) TARGET=$(TARGETARCH) install
	cp $(ACFGDIR)/../acfg_test_app/acfg_tool $(WIRELESSPACKAGEPATH)
################NEW ADD###############################################

hal_build: 
	@echo making hal
	if test -n "$(MADWIFITARGET)"; then \
	cd $(HAL)/linux && make TARGET=$(MADWIFITARGET) clean &&  \
	make TARGET=$(MADWIFITARGET) && make TARGET=$(MADWIFITARGET) release; \
	fi

ifeq ($(BUILD_WPA2),y)  ####################################
# apps/wpa2 provides a second generation (as compared with apps/wpa)
#       of authentication (including WPS) programs:
#       hostapd, wpa_supplicant, etc.
# 	It installs via $(INSTALL_ROOT).
# 	It depends only on header files from the driver, and linux driver
# 	(madwifi) header files specified by $(MADWIFIPATH)

wpa2: wpa2_clean #rootfs_prep
ifneq ($(OPENSOURCE_BUILD), y)
	@echo Making wpa2 at `date`
	cd ../$(BOARD_TYPE)/apps/wpa2 && $(MAKE) 	\
		CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/hostapd/hostapd $(WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/common/libwpa_common.so $(WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/common/libwpa_ctrl.so $(WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/wpa_supplicant/wpa_supplicant $(WIRELESSPACKAGEPATH)
	@echo End Making wpa2 at `date`
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/hostapd/hostapd $(GPL_WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/common/libwpa_common.so $(GPL_WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/common/libwpa_ctrl.so $(GPL_WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2/wpa_supplicant/wpa_supplicant $(GPL_WIRELESSPACKAGEPATH)
endif
endif

wpa2_clean:
ifneq ($(OPENSOURCE_BUILD), y)
	cd ../$(BOARD_TYPE)/apps/wpa2 && $(MAKE) clean
endif
clean: wpa2_clean

else  ####(BUILD_WPA2),y####
endif ####(BUILD_WPA2),y####

export WIRELESSPACKAGEPATH=$(IMAGEPATH)/wireless/
export GPL_WIRELESSPACKAGEPATH=$(GPL_IMAGEPATH)/wireless/

wireless_prep:
	test -d $(WIRELESSPACKAGEPATH) || mkdir -p $(WIRELESSPACKAGEPATH)
ifeq ($(GPL_BUILD), y)
	test -d $(GPL_WIRELESSPACKAGEPATH) || mkdir -p $(GPL_WIRELESSPACKAGEPATH)
	mkdir -p $(GPL_DIR)/$(BOARD_TYPE)/apps
	cp -fr $(TOPDIR)/$(BOARD_TYPE)/apps/$(WIRELESSTOOLS) $(GPL_DIR)/$(BOARD_TYPE)/apps/
	cp -fr $(TOPDIR)/$(BOARD_TYPE)/apps/wpa2 $(GPL_DIR)/$(BOARD_TYPE)/apps/
	mkdir -p $(GPL_DIR)/pb92/linux
	mkdir -p $(GPL_DIR)/pb92/apps
	cp -r $(TOPDIR)/pb92/apps/wpa2 $(GPL_DIR)/pb92/apps/
	rm $(GPL_DIR)/pb92/apps/wpa2/Atheros*
	cp -r $(TOPDIR)/pb92/apps/$(WIRELESSTOOLS) $(GPL_DIR)/pb92/apps/
	cp -r $(TOPDIR)/pb92/boot $(GPL_DIR)/pb92/
	cp -r $(TOPDIR)/pb92/linux/kernels $(GPL_DIR)/pb92/linux/
endif
	

ifeq ($(strip $(BOARD_TYPE)),ap135_hnat)
export HOSTAPD_VERSION=ATHR_HOSTAPD
endif

ifeq ($(strip $(HOSTAPD_VERSION)),ATHR_HOSTAPD)
wireless:wireless_prep madwifi_build athr-hostapd athr-wpa_supplicant wpa2_common_lib
else
wireless:wireless_prep madwifi_build wpa2
endif

ifeq ($(strip $(HOSTAPD_VERSION)),ATHR_HOSTAPD)
wireless_clean:madwifi_clean athr-hostapd_clean athr-wpa_supplicant_clean wpa2_common_lib_clean
else
wireless_clean:madwifi_clean wpa2_clean
endif


hal_build_main:
ifneq ($(OPENSOURCE_BUILD), y)
	@echo making Mainline hal
	if test -n "$(TARGETARCH)"; then \
	cd $(HAL)/linux && make TARGET=$(TARGETARCH) clean &&  \
	make TARGET=$(TARGETARCH) && make TARGET=$(TARGETARCH) release; \
	fi
endif
	
hal_clean:
	@echo making Mainline hal clean
	if test -n "$(TARGETARCH)"; then \
	cd $(HAL)/linux && make TARGET=$(TARGETARCH) clean; \
	fi
	
wireless_tools:
	@echo making wireless_tools 
ifeq ($(GPL_BUILD), y)
	if test -n "$(WIRELESSTOOLS)"; then \
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/$(WIRELESSTOOLS) &&  make clean && make; \
	mkdir -p $(INSTALL_ROOT)/sbin; \
	cp -f $(WIRELESSTOOLSLIB) $(WIRELESSPACKAGEPATH); \
	cp -f iwpriv $(WIRELESSPACKAGEPATH); \
	cp -f iwconfig $(WIRELESSPACKAGEPATH); \
	cp -f iwlist $(WIRELESSPACKAGEPATH); \
	cd $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/tools && make clean; \
	make BUILD_STATIC=$(BUILD_STATIC) wlanconfig; \
	cp -f wlanconfig $(WIRELESSPACKAGEPATH) && \
	cp -f wlanconfig $(GPL_WIRELESSPACKAGEPATH) && \
	mkdir -p $(GPL_TMP_INSTALL_ROOT)/sbin; \
	for file in $(WIRELESSTOOLNAMES) ; do \
		if [ -f $$file ] ; then \
			cp -f $$file $(INSTALL_ROOT)/sbin/.; \
			cp -f $$file $(GPL_TMP_INSTALL_ROOT)/sbin/.; \
		fi; \
	done; \
	fi
else
ifneq ($(OPENSOURCE_BUILD), y)
	if test -n "$(WIRELESSTOOLS)"; then \
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/$(WIRELESSTOOLS) &&  make clean && make; \
	mkdir -p $(INSTALL_ROOT)/sbin; \
	cp -f $(WIRELESSTOOLSLIB) $(WIRELESSPACKAGEPATH); \
	cp -f iwpriv $(WIRELESSPACKAGEPATH); \
	cp -f iwconfig $(WIRELESSPACKAGEPATH); \
	cp -f iwlist $(WIRELESSPACKAGEPATH); \
	cd $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/tools && make clean; \
	make BUILD_STATIC=$(BUILD_STATIC) wlanconfig; \
	cp -f wlanconfig $(WIRELESSPACKAGEPATH) && \
	for file in $(WIRELESSTOOLNAMES) ; do \
		if [ -f $$file ] ; then \
			cp -f $$file $(INSTALL_ROOT)/sbin/.; \
		fi; \
	done; \
	fi
else
	if test -n "$(WIRELESSTOOLS)"; then \
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/$(WIRELESSTOOLS) &&  make clean && make; \
	mkdir -p $(INSTALL_ROOT)/sbin; \
	cp -f $(WIRELESSTOOLSLIB) $(WIRELESSPACKAGEPATH); \
	cp -f iwpriv $(WIRELESSPACKAGEPATH); \
	cp -f iwconfig $(WIRELESSPACKAGEPATH); \
	cp -f iwlist $(WIRELESSPACKAGEPATH); \
	for file in $(WIRELESSTOOLNAMES) ; do \
		if [ -f $$file ] ; then \
			cp -f $$file $(INSTALL_ROOT)/sbin/.; \
		fi; \
	done; \
	fi
endif
endif

wireless_tools_clean:
	if test -n "$(WIRELESSTOOLS)"; then \
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/$(WIRELESSTOOLS) &&  make clean; \
	cd $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/tools && make clean; \
	fi	
	
ath_tools_build:
ifneq ($(OPENSOURCE_BUILD), y)
	@echo makeing ath tools;\
	cd $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/tools;\
	make ath_tools_clean && make ath_tools
endif
	
ath_tools_clean:
	@echo makeing ath tools clean;\
	cd $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/tools;\
	make ath_tools_clean

madwifi_build: hal_build_main wireless_tools ath_tools_build
ifneq ($(OPENSOURCE_BUILD), y)
	@echo making umac mainline
	cd $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux && \
	$(MAKEARCH) TARGET=$(TARGETARCH) clean \
	&& $(MAKEARCH) TARGET=$(TARGETARCH) && \
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/umac/*.ko $(WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/asf/*.ko $(WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/adf/*.ko $(WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/ratectrl/*.ko $(WIRELESSPACKAGEPATH)
#	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/ath_pktlog/*.ko $(WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/ath_dev/*.ko $(WIRELESSPACKAGEPATH)
ifneq ($(findstring $(BOARD_TYPE), ap124 ap135_hnat), )
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/dfs/*.ko $(WIRELESSPACKAGEPATH)
endif
ifeq ($(ATH_SUPPORT_DFS), 1)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/dfs/*.ko $(WIRELESSPACKAGEPATH)
endif
	$(TOOLPREFIX)strip -S $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/ath_hal/*.ko
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/ath_hal/*.ko $(WIRELESSPACKAGEPATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/umac/*.ko $(GPL_WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/asf/*.ko $(GPL_WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/adf/*.ko $(GPL_WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/ratectrl/*.ko $(GPL_WIRELESSPACKAGEPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/ath_dev/*.ko $(GPL_WIRELESSPACKAGEPATH)
ifneq ($(findstring $(BOARD_TYPE), ap124 ap135_hnat), )
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/dfs/*.ko $(GPL_WIRELESSPACKAGEPATH)
endif
ifeq ($(ATH_SUPPORT_DFS), 1)
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/lmac/dfs/*.ko $(GPL_WIRELESSPACKAGEPATH)
endif
	$(TOOLPREFIX)strip -S $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/ath_hal/*.ko
	cp $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux/ath_hal/*.ko $(GPL_WIRELESSPACKAGEPATH)
endif
endif

madwifi_clean: hal_clean wireless_tools_clean ath_tools_clean
	@echo making umac mainline clean
	cd $(TOPDIR)/$(BOARD_TYPE)/wlan/os/linux && \
	$(MAKEARCH) TARGET=$(TARGETARCH) clean

wireless_install:
	if [ ! -d $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/net ]; then mkdir -p $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/net; fi
	cd $(WIRELESSPACKAGEPATH) && \
	cp -f $(WIRELESSTOOLSLIB) $(INSTALL_ROOT_FOR_BOARD)/lib; \
	ln -sf $(WIRELESSTOOLSLIB) $(INSTALL_ROOT_FOR_BOARD)/lib/libiw.so; \
	cp -f *.so $(INSTALL_ROOT_FOR_BOARD)/lib; \
	cp -f iwpriv $(INSTALL_ROOT_FOR_BOARD)/sbin; \
	cp -f iwconfig $(INSTALL_ROOT_FOR_BOARD)/sbin; \
	cp -f iwlist $(INSTALL_ROOT_FOR_BOARD)/sbin; \
	cp -f wlanconfig $(INSTALL_ROOT_FOR_BOARD)/sbin; \
	cp -f hostapd $(INSTALL_ROOT_FOR_BOARD)/sbin; \
	cp -f wpa_supplicant $(INSTALL_ROOT_FOR_BOARD)/sbin; \
	cp -f *.ko $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/net
ifeq ($(strip $(BOARD_TYPE)),ap121)
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art && cp art.ko $(WIRELESSPACKAGEPATH)
endif
#ifeq ($(strip $(BOARD_TYPE)),ap124)
##for hostapd##
#	test -d $(INSTALL_ROOT_FOR_BOARD)/etc/ath || mkdir -p $(INSTALL_ROOT_FOR_BOARD)/etc/ath
#	cp ../filesystem/$(BOARD_TYPE)/etc/ath/hostapd0.7.0_conf/* $(INSTALL_ROOT_FOR_BOARD)/etc/ath
#	rm -rf $(INSTALL_ROOT_FOR_BOARD)/etc/ath/hostapd0.7.0_conf
#	test -d $(INSTALL_ROOT_FOR_BOARD)/etc/wpa2 || mkdir -p $(INSTALL_ROOT_FOR_BOARD)/etc/wpa2
#endif

#art is different between ap123 and ap124
art:
ifneq ($(OPENSOURCE_BUILD), y)
	@echo Making ART Module
ifeq ($(strip $(BOARD_TYPE)),ap124)
	@echo Making ART Module for ap124
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art && make -f makefile.artmod clean && \
	make -f makefile.artmod wasp_osprey  
else  ifeq ($(strip $(BOARD_TYPE)),ap143)
	@echo Making ART Module for ap143
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src/driver/linux && make -f makefile.artmod clean honeybee
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src && make -f makefile.nart clean all
else  ifeq ($(strip $(BOARD_TYPE)),db12x)
	@echo Making ART Module for db12x
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src/driver/linux && make -f makefile.artmod clean
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src && make -f makefile.nart clean all
else  ifeq ($(strip $(BOARD_TYPE)),ap143-2.0)
	@echo Making ART Module for ap143-2.0
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art && make -f makefile.artmod clean && \
	make -f makefile.artmod honeybee
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/art/modules/art.ko $(MODULEPATH)/art-honeybee-2.0.ko
	@echo Making NART for ap143-2.0
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2_ver_4_9_815_nart_src_rel && make -f makefile.nart clean all
else  ifeq ($(strip $(BOARD_TYPE)),ap151)
	@echo Making ART Module for ap151
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art && make -f makefile.artmod clean && \
	make -f makefile.artmod dragonfly
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/art/modules/art.ko $(TFTPPATH)/art-dragonfly.ko
	@echo Making Nart for ap151
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2_ver_4_9_804_18_nart_src_rel && make -f makefile.nart clean all
else  ifeq ($(strip $(BOARD_TYPE)),ap152)
	@echo Making ART Module for ap152
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art && make -f makefile.artmod clean && \
	make -f makefile.artmod dragonfly
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/art/modules/art.ko $(TFTPPATH)/art-dragonfly.ko
	@echo Making Nart for ap151
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2_ver_4_9_804_18_nart_src_rel && make -f makefile.nart clean all
else  ifeq ($(strip $(BOARD_TYPE)),ap135_hnat)
	@echo Making ART Module for ap135
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art && make -f makefile.artmod clean && \
	make -f makefile.artmod scorpion
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/art/modules/art.ko $(TFTPPATH)/art-scorpion.ko
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art && make -f makefile.artmod clean && \
	make -f makefile.artmod scorpion_pci
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/art/modules/art.ko $(TFTPPATH)/art-scorpion-peacock.ko	
else  ifeq ($(strip $(BOARD_TYPE)),ap121)
	@echo Making ART Module for ap121
	@echo makeing ART Module
	test -d $(WIRELESSPACKAGEPATH) || mkdir -p $(WIRELESSPACKAGEPATH)
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2_ver_2_52ap_src/driver/linux && make -f makefile.artmod clean && \
	make -f makefile.artmod hornet
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2_ver_2_52ap_src/driver/linux/modules && \
	cp art.ko $(WIRELESSPACKAGEPATH)
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2_ver_2_52ap_src/art && make -f makefile.nart.mips clean && \
	make -f makefile.nart.mips all
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2_ver_2_52ap_src/art/obj && \
	cp nart.out $(WIRELESSPACKAGEPATH)
else
	@echo Making ART Module default
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src/driver/linux && make -f makefile.artmod clean wasp
	cd $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src/art && make -f makefile.nart clean all
	 
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src/driver/linux/modules/art.ko $(TFTPPATH)
	cp $(TOPDIR)/$(BOARD_TYPE)/apps/art2/src/art/obj/nart.out $(TFTPPATH)
endif
endif
#######################################end wireless ##########################################
	

#all other kernel modules
kernel_modules: kernel_modules_prep $(BOARD_KERNEL_MODULES)

kernel_modules_prep:
ifeq ($(GPL_BUILD), y)
	test -d $(GPL_KERNEL_MODULE_PATH) || mkdir -p $(GPL_KERNEL_MODULE_PATH)
endif
	test -d $(KERNEL_MODULE_PATH) || mkdir -p $(KERNEL_MODULE_PATH)

kernel_modules_install:
	mkdir -p $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/kernel/
	cp -Rf $(KERNEL_MODULE_PATH)/*.ko $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/kernel/
	
stats:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/stats modules
	cp $(TOPDIR)/kernel_modules/stats/statistics.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/stats/statistics.ko $(GPL_KERNEL_MODULE_PATH)/
endif
endif

ct_flush:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/ct_control modules
	cp $(TOPDIR)/kernel_modules/ct_control/ct_flush.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/ct_control/ct_flush.ko $(GPL_KERNEL_MODULE_PATH)
endif

kernel_debug:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/kernel_debug modules
endif

kernel_debug_install:
	cp $(TOPDIR)/kernel_modules/kernel_debug/kernel_debug.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/kernel_debug/kernel_debug.ko $(GPL_KERNEL_MODULE_PATH)
endif

netfilter:
	if [ "$(KERNELVER)" = "2.6.15" ]; then \
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=net/ipv4/netfilter modules ; \
	else \
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=net/netfilter modules ; \
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=net/ipv4/netfilter modules ; \
	fi;
	-cp $(KERNELPATH)/net/ipv4/netfilter/*.ko $(KERNEL_MODULE_PATH)
	-cp $(KERNELPATH)/net/netfilter/*.ko $(KERNEL_MODULE_PATH)	

wlan_warn:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/wlan_warn modules
	cp $(TOPDIR)/kernel_modules/wlan_warn/wlan_warn.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/wlan_warn/wlan_warn.ko $(GPL_KERNEL_MODULE_PATH)
endif
endif
	
tp_domain:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/tp_domain clean modules
	cp $(TOPDIR)/kernel_modules/tp_domain/tp_domain.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/tp_domain/tp_domain.ko $(GPL_KERNEL_MODULE_PATH)
endif
endif

netsched:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=net/sched modules	
	cp $(KERNELPATH)/net/sched/*.ko $(KERNEL_MODULE_PATH)

ts_kmp:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=lib modules	
	-cp $(KERNELPATH)/lib/ts_kmp.ko $(KERNEL_MODULE_PATH)
	
br_filter:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/br_hook modules
	cp $(TOPDIR)/kernel_modules/br_hook/br_filter.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/br_hook/br_filter.ko $(GPL_KERNEL_MODULE_PATH)
endif
endif
	
br_guest_filter:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/br_guest_filter modules
	cp $(TOPDIR)/kernel_modules/br_guest_filter/br_guest_filter.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/br_guest_filter/br_guest_filter.ko $(GPL_KERNEL_MODULE_PATH)
endif
endif
	
br_guest_mark:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/br_guest_mark modules
	cp $(TOPDIR)/kernel_modules/br_guest_mark/br_guest_mark.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/br_guest_mark/br_guest_mark.ko $(GPL_KERNEL_MODULE_PATH)
endif
endif
	
flashid:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/flash_id modules
	cp $(TOPDIR)/kernel_modules/flash_id/flashid.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/flash_id/flashid.ko $(GPL_KERNEL_MODULE_PATH)
endif
	
antind:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/anti_nat_detect modules
	#cp $(TOPDIR)/kernel_modules/anti_nat_detect/ipt_ANTIND.ko $(KERNEL_MODULE_PATH)
	cp $(TOPDIR)/kernel_modules/anti_nat_detect/ipt_ANTIND.ko /tftpboot/tftp/
ifeq ($(GPL_BUILD), y)
#	cp $(TOPDIR)/kernel_modules/anti_nat_detect/ipt_ANTIND.ko $(GPL_KERNEL_MODULE_PATH)
endif
	
gpio:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/gpio modules
	cp $(TOPDIR)/kernel_modules/gpio/gpio.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	@cp -f $(TOPDIR)/kernel_modules/gpio $(GPL_DIR)/kernel_modules/
endif
	
cone_udp:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/cone_udp modules
	cp $(TOPDIR)/kernel_modules/cone_udp/cone_udp.ko $(KERNEL_MODULE_PATH) 
	cp $(TOPDIR)/kernel_modules/cone_udp/cone_udp.ko /tftpboot/tftp/
	
starcraft_helper:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/starcraft_helper modules
	cp $(TOPDIR)/kernel_modules/starcraft_helper/ip_conntrack_helper_starcraft.ko /tftpboot/tftp/

harmony:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/harmony modules
	
pppol2tp:	
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/kernel_modules/pppol2tp-kmod-0.17 && make clean
	cp -fr $(TOPDIR)/kernel_modules/pppol2tp-kmod-0.17 $(GPL_DIR)/kernel_modules/
endif
	if [ "$(KERNELVER)" = "2.6.15" ]; then \
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/pppol2tp-kmod-0.17 modules && \
	cp $(TOPDIR)/kernel_modules/pppol2tp-kmod-0.17/*.ko $(KERNEL_MODULE_PATH) ; \
	else \
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=drivers/net modules && \
	cp $(KERNELPATH)/drivers/net/pppol2tp.ko $(KERNEL_MODULE_PATH) ; \
	fi;

ipsec_mod:
	cp $(KERNELPATH)/net/key/af_key.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/net/xfrm/xfrm_user.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/net/netfilter/xt_mark.ko $(KERNEL_MODULE_PATH)
	
pptp_module:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/kernel_modules/pptp_driver-0.8.3 && make clean
	cp -fr $(TOPDIR)/kernel_modules/pptp_driver-0.8.3 $(GPL_DIR)/kernel_modules/
endif
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/pptp_driver-0.8.3 modules
	cp $(TOPDIR)/kernel_modules/pptp_driver-0.8.3/*.ko $(KERNEL_MODULE_PATH)

ap_vlan:
ifneq ($(OPENSOURCE_BUILD), y)
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/ap_vlan/forWard modules
#	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/ap_vlan/outPut modules
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=$(TOPDIR)/kernel_modules/ap_vlan/passUp modules
	cp $(TOPDIR)/kernel_modules/ap_vlan/forWard/*.ko $(KERNEL_MODULE_PATH)
#	comment out by TanZY 2010-03-12. As XuShouMing said, we donot need output anymore.
#	cp $(TOPDIR)/kernel_modules/ap_vlan/outPut/*.ko $(KERNEL_MODULE_PATH)
	cp $(TOPDIR)/kernel_modules/ap_vlan/passUp/*.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/ap_vlan/forWard/*.ko $(GPL_KERNEL_MODULE_PATH)
	cp $(TOPDIR)/kernel_modules/ap_vlan/passUp/*.ko $(GPL_KERNEL_MODULE_PATH)
endif
endif

NetUSB_Kcodes:
ifneq ($(OPENSOURCE_BUILD), y)
	@echo copying printer drivers
	cp $(TOPDIR)/kernel_modules/NetUSB_Kcodes/$(DEV_NAME)/*.ko $(KERNEL_MODULE_PATH)
ifeq ($(GPL_BUILD), y)
	cp $(TOPDIR)/kernel_modules/NetUSB_Kcodes/$(DEV_NAME)/*.ko $(GPL_KERNEL_MODULE_PATH)
endif
endif

# for ipv6, added by hejian, 121013 
ipv6_netfilter:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=net/ipv6/netfilter modules
	-cp $(KERNELPATH)/net/ipv6/netfilter/*.ko $(KERNEL_MODULES_IMAGE)

ipv6_modules:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=net/ipv4 modules ; \
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=net/ipv6 modules
	-cp $(KERNELPATH)/net/ipv4/*.ko $(KERNEL_MODULES_IMAGE)
	-cp $(KERNELPATH)/net/ipv6/*.ko $(KERNEL_MODULES_IMAGE)
	
usb_serial_new:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=drivers/usb/serial modules	
	cp $(KERNELPATH)/drivers/usb/serial/usbserial.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/usb/serial/option.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/usb/serial/qcserial.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/usb/class/cdc-acm.ko $(KERNEL_MODULE_PATH)
	
usb_serial:
	$(MAKEARCH) -C $(KERNELPATH) SUBDIRS=drivers/usb/serial modules	
	cp $(KERNELPATH)/drivers/usb/serial/usbserial.ko $(KERNEL_MODULE_PATH)
ifneq ($(FEATURE_FS_SIZE_CUT_FOR_RU), y)
	cp $(KERNELPATH)/drivers/usb/serial/option.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/usb/serial/qcserial.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/usb/class/cdc-acm.ko $(KERNEL_MODULE_PATH)
endif

usb_storage:
	cp $(KERNELPATH)/drivers/scsi/scsi_mod.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/scsi/sg.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/scsi/sd_mod.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/scsi/scsi_wait_scan.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/usb/storage/usb-storage.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/fs/fat/fat.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/fs/fat/vfat.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/fs/fat/msdos.ko $(KERNEL_MODULE_PATH)

usb_net:
ifneq ($(FEATURE_FS_SIZE_CUT), y)
	cp $(KERNELPATH)/drivers/net/usb/cdc_ether.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/net/usb/usbnet.ko $(KERNEL_MODULE_PATH)
ifneq ($(FEATURE_FS_SIZE_CUT_FOR_RU), y)
	cp $(KERNELPATH)/drivers/net/usb/rndis_host.ko $(KERNEL_MODULE_PATH)
endif
endif
	cp $(KERNELPATH)/drivers/net/usb/cdc_ncm.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/net/usb/lg-vl600.ko $(KERNEL_MODULE_PATH)
	#cp $(KERNELPATH)/drivers/net/usb/huawei_wwan.ko $(KERNEL_MODULE_PATH)
	cp $(KERNELPATH)/drivers/net/usb/qmi_wwan.ko $(KERNEL_MODULE_PATH)	
	cp $(KERNELPATH)/drivers/net/usb/cdc_enc.ko $(KERNEL_MODULE_PATH)
	#cp $(KERNELPATH)/drivers/net/usb/sierra_net.ko $(KERNEL_MODULE_PATH)

#
# applications
#

ifeq ($(MODULE_IGMP_V3), y)
BOARD_APPLICATIONS += igmpd
endif

ifeq ($(MODULE_VNM_FPT_PORTAL), y)
BOARD_APPLICATIONS += vnm_fpt_portal
endif

apps_build: $(BOARD_APPLICATIONS)
ifeq ($(MODULE_USB_IPAD_LITE), y)
	make usb_ipad_lite
endif

libffmpeg: # easy build for libffmpeg 
	cd $(TOPDIR)/apps/nas/media_server/ffmpeg-0.6 && \
	if test -e config.mak; then make distclean; fi ;
	cd $(TOPDIR)/apps/nas/media_server/ffmpeg-0.6 && \
	./configure --prefix=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE) \
				--libdir=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/lib \
				--enable-static --disable-ffmpeg --disable-ffserver \
				--disable-ffplay --disable-ffprobe \
				--disable-zlib --disable-bzlib \
				--disable-indev=alsa --disable-outdev=alsa \
				--enable-cross-compile --target-os=linux --arch=mips;
	cd $(TOPDIR)/apps/nas/media_server/ffmpeg-0.6 &&\
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib &&\
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib install

libdlna: libffmpeg # easy build for libdlna
	cd $(TOPDIR)/apps/nas/media_server/libdlna-0.2.3 && \
	if test -e config.mak; then make distclean; fi ;
	cp -rf $(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/include/* $(TOPDIR)/build/$(TOOLCHAIN)/build_mips/staging_dir/usr/include/;	
	cd $(TOPDIR)/apps/nas/media_server/libdlna-0.2.3 &&\
	export CC=$(TOOLPREFIX)gcc &&\
	export LD=$(TOOLPREFIX)ld &&\
	export AR=$(TOOLPREFIX)ar &&\
	export RANLIB=$(TOOLPREFIX)ranlib && \
	./configure --libdir=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/lib \
				--prefix=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE) \
				--includedir=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/include \
				--disable-shared --cross-compile && \
	make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib install
	
libupnp: libdlna # easy build for libupnp
	cd $(TOPDIR)/apps/nas/media_server/libupnp-1.6.6 &&\
	if test -e Makefile; then make distclean; fi &&\
	./configure --prefix=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE) \
				--libexecdir=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE) \
				--libdir=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/lib \
				--build=i386 --host=mips-linux && \
	make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib install

ushare: libupnp # easy build for ushare 
	cp -rf $(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/include/* $(TOPDIR)/build/$(TOOLCHAIN)/build_mips/staging_dir/usr/include/;	
	cd $(TOPDIR)/apps/nas/media_server/ushare-1.1a &&\
	if test -e config.mak; then make distclean; fi ;
	cd $(TOPDIR)/apps/nas/media_server/ushare-1.1a &&\
	export CC=$(TOOLPREFIX)gcc &&\
	export LD=$(TOOLPREFIX)ld &&\
	export AR=$(TOOLPREFIX)ar &&\
	export RANLIB=$(TOOLPREFIX)ranlib && \
	export PKG_CONFIG_PATH=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/lib/pkgconfig &&\
	./configure --prefix=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE) \
				--with-libupnp-dir=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/lib \
				--with-libdlna-dir=$(TOPDIR)/apps/nas/media_server/$(BOARD_TYPE)/lib \
				--cross-compile --enable-dlna --disable-nls && \
	make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib install;

minidlna:  # easy build for minidlna 
	@echo build minidlna-1.1.0 ...
ifeq ($(GPL_BUILD), y)
	#cd $(NAS_PATH)/media_server/minidlna-1.1.0 && make distclean
	cp -fr $(NAS_PATH)/media_server $(GPL_NAS_PATH)/
endif
	cd $(NAS_PATH)/media_server/minidlna-1.1.0 && \
	$(MAKE)  media_server

busybox_clean:
	@echo Cleaning busybox
	cd ../apps/$(BUSYBOX) && make clean;

busybox: # easy build for busybox, no clean
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/$(BUSYBOX) && make clean
	cp -fr $(TOPDIR)/apps/$(BUSYBOX) $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/$(BUSYBOX); \
	rm -f .config; \
	cp $(BUSYBOX_CONFIG_FILE) $(TOPDIR)/apps/$(BUSYBOX)/.config; \
	#added by ZQQ, 2014.8.31 for busybox, if to build a certification software, enable the ethreg in busybox
ifeq ($(CONFIG_WIRELESS_CERTIFICATION), 1) 
	sed 's/# CONFIG_ETHREG is not set/CONFIG_ETHREG=y/' $(TOPDIR)/apps/$(BUSYBOX)/.config > $(TOPDIR)/apps/$(BUSYBOX)/.config.tmp; \
	rm -f $(TOPDIR)/apps/$(BUSYBOX)/.config && mv $(TOPDIR)/apps/$(BUSYBOX)/.config.tmp $(TOPDIR)/apps/$(BUSYBOX)/.config
endif
	cd $(TOPDIR)/apps/$(BUSYBOX); \
	$(MAKE) PREFIX=$(INSTALL_ROOT) uninstall; \
	find . -name "*.o" | xargs rm -rf; \
	$(MAKE); \
	$(MAKE) PREFIX=$(INSTALL_ROOT) install
	
pppoe:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/ppp-2.4.3/pppd && make clean
	cp -fr $(TOPDIR)/apps/ppp-2.4.3 $(GPL_DIR)/apps/
endif
ifeq ($(strip $(ETH_CONFIG)), _s17_hwaccel)
	cd $(TOPDIR)/apps/ppp-2.4.3/pppd && make clean && make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar ATHRS17_HWNAT=1 && \
	cp pppd $(INSTALL_ROOT)/usr/sbin	
else
	cd $(TOPDIR)/apps/ppp-2.4.3/pppd && make clean && make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar && \
	cp pppd $(INSTALL_ROOT)/usr/sbin
endif

pptp:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/pptp-1.7.1 && make clean
	cp -fr $(TOPDIR)/apps/pptp-1.7.1 $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/pptp-1.7.1 && make clean && make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar && \
	cp pptp $(INSTALL_ROOT)/usr/sbin

l2tp:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/xl2tpd-1.1.12 && make clean
	cp -fr $(TOPDIR)/apps/xl2tpd-1.1.12 $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/xl2tpd-1.1.12 && make clean &&  make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar && \
	cp xl2tpd $(INSTALL_ROOT)/usr/sbin

bpa:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/bpalogin-2.0.2 && make clean
	cp -fr $(TOPDIR)/apps/bpalogin-2.0.2 $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/bpalogin-2.0.2 && make clean &&  make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar && \
	cp bpalogin $(INSTALL_ROOT)/usr/sbin

igmpd:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/igmpd && make clean
	cp -fr $(TOPDIR)/apps/igmpd $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/igmpd && make clean &&  make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar igmpd && \
	cp igmpd $(INSTALL_ROOT)/usr/sbin
	
vnm_fpt_portal:
	cd $(TOPDIR)/apps/vnm_fpt_portal && make clean &&  make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar && \
	cp fpt_portal_daemon $(INSTALL_ROOT)/usr/sbin

iptables:
ifeq ($(KERNELVER), 2.6.15)
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/iptables-1.3.7 && make clean
	cp -fr $(TOPDIR)/apps/iptables-1.3.7 $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/iptables-1.3.7/ && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld DO_IPV6=0 KERNEL_DIR=$(KERNELPATH) LIBDIR=/lib && \
	cp iptables $(INSTALL_ROOT)/sbin/ && \
	cd extensions && \
	test -d $(INSTALL_ROOT)/lib/iptables/ || mkdir -p $(INSTALL_ROOT)/lib/iptables/ && \
	mv -f libipt_DNAT.so libipt_MASQUERADE.so libipt_SNAT.so libipt_TCPMSS.so libipt_TRIGGER.so \
	libipt_comment.so libipt_icmp.so libipt_iprange.so libipt_mac.so \
	libipt_multiport.so libipt_standard.so libipt_state.so libipt_string.so \
	libipt_tcp.so libipt_time.so libipt_udp.so libipt_MARK.so libipt_multiurl.so libipt_wlanwarn.so $(INSTALL_ROOT)/lib/iptables/
else ifeq ($(KERNELVER), 2.6.31)
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/iptables-1.4.5 && make clean
	cp -fr $(TOPDIR)/apps/iptables-1.4.5 $(GPL_DIR)/apps/
endif
ifneq ($(FEATURE_PPPOEV6_SETMSS),y)
	cd $(TOPDIR)/apps/iptables-1.4.5 && \
	if test -e Makefile ; then make distclean ; fi && \
	./configure --prefix=$(INSTALL_ROOT) \
	--build=i386 --host=mips-linux  \
	--with-ksource=$(KERNELPATH) \
	--disable-devel --disable-libipq \
	--disable-ipv6 && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib install && \
	./rm_ext.sh
else
	cd $(TOPDIR)/apps/iptables-1.4.5 && \
	if test -e Makefile ; then make distclean ; fi && \
	./configure --prefix=$(INSTALL_ROOT) \
	--build=i386 --host=mips-linux  \
	--with-ksource=$(KERNELPATH) \
	--disable-devel --disable-libipq &&\
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib install && \
	./rm_ext.sh
endif
endif
	rm -rf $(INSTALL_ROOT)/lib/libexec
	-mv $(INSTALL_ROOT)/libexec $(INSTALL_ROOT)/lib
	rm -rf $(INSTALL_ROOT)/share
	rm -rf $(INSTALL_ROOT)/man
	
tc_build:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/iproute2-$(KERNELVER) && make clean
	cp -fr $(TOPDIR)/apps/iproute2-$(KERNELVER) $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/iproute2-$(KERNELVER) && make CC=$(TOOLPREFIX)gcc && \
	cp $(TOPDIR)/apps/iproute2-$(KERNELVER)/tc/tc $(INSTALL_ROOT)/sbin
	
lltd:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/lltd/wr841n-linux && make clean
	cp -fr $(TOPDIR)/apps/lltd $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/lltd/wr841n-linux && \
	make clean && $(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)gcc && \
	cp lld2d $(INSTALL_ROOT)/usr/bin/

net_ioctl:
ifneq ($(OPENSOURCE_BUILD), y)
	cd $(TOPDIR)/debug_tools/net_ioctl && \
	$(TOOLPREFIX)gcc  -o net_ioctl net_ioctl.c && cp net_ioctl $(INSTALL_ROOT)/usr/
ifeq ($(GPL_BUILD), y)
	mkdir -p $(GPL_TMP_INSTALL_ROOT)/usr
	cd $(TOPDIR)/debug_tools/net_ioctl && cp net_ioctl $(GPL_TMP_INSTALL_ROOT)/usr/
endif
else
	cp $(TMP_INSTALL_ROOT)/usr/net_ioctl $(INSTALL_ROOT)/usr/
endif
	
wlanreg:
	cd $(MADWIFIPATH)/tools/hal_diag && make && cp -f reg $(INSTALL_ROOT)/usr/bin/wlanreg

arp:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/arp && make clean
	cp -fr $(TOPDIR)/apps/arp $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/arp && \
	$(TOOLPREFIX)gcc -o arp arp.c && cp arp $(INSTALL_ROOT)/usr/
	
ftpserver:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/vsftpd-2.3.2 && make clean
	cp -fr $(TOPDIR)/apps/vsftpd-2.3.2 $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/vsftpd-2.3.2 && \
	$(MAKE) clean && $(MAKE) vsftpd CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar && \
	cp vsftpd $(IMAGEPATH)

dropbear_build:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/dropbear && make clean
	cp -fr $(TOPDIR)/apps/dropbear $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/dropbear &&\
	if test -e Makefile ; then $(MAKE) distclean ; fi && \
	./configure --prefix=/usr --build=i386 --host=mips-linux --enable-static --disable-zlib && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar \
	PROGRAMS="dropbear dbclient scp dropbearkey dropbearconvert" MULTI=1 &&\
	cp dropbearmulti $(INSTALL_ROOT)/usr/sbin/ &&\
	cd  $(INSTALL_ROOT)/usr/bin &&\
	ln -sf ../../usr/sbin/dropbearmulti dropbear &&\
	ln -sf ../../usr/sbin/dropbearmulti dbclient &&\
	ln -sf ../../usr/sbin/dropbearmulti scp  &&\
	ln -sf ../../usr/sbin/dropbearmulti dropbearkey  &&\
	ln -sf ../../usr/sbin/dropbearmulti dropbearconvert  &&\
	chmod +x  dropbear dbclient scp dropbearkey dropbearconvert &&\
	cd $(INSTALL_ROOT)/etc && ln -sf ../tmp/passwd passwd 

ifeq ($(MODULE_3G), y)
3gtools_build:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/3g_tools && make clean
	cp -fr $(TOPDIR)/apps/3g_tools $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/3g_tools && \
	$(MAKE) clean && $(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar
endif

####### vpn -- libssl + flex + ipsec-tools ##########################
libssl:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/openssl-0.9.8a && \
	if test -e Makefile ; then touch Makefile; fi && \
	make clean
	cp -fr $(TOPDIR)/apps/openssl-0.9.8a $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/openssl-0.9.8a && \
	if test -e Makefile ; then touch Makefile; fi && \
	make clean && make && \
	cp libcrypto.so.0.9.8 $(INSTALL_ROOT)/lib && \
	cp libssl.so.0.9.8 $(INSTALL_ROOT)/lib && \
	cd $(INSTALL_ROOT)/lib && \
	ln -sf libcrypto.so.0.9.8 libcrypto.so && \
	ln -sf libssl.so.0.9.8 libssl.so

flex:
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/flex-2.5.4 && \
	if test -e Makefile ; then make distclean ; fi 
	cp -fr $(TOPDIR)/apps/flex-2.5.4 $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/flex-2.5.4 && \
	if test -e Makefile ; then make distclean ; fi && \
	./configure --prefix=/usr --build=i386 --host=mips-linux && \
	make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib

IPSEC_LDFLAGS=-ldl
ipsec: #flex libssl
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/ipsec-tools-0.6.6 && \
	if test -e Makefile ; then make distclean ; fi
	cp -fr $(TOPDIR)/apps/ipsec-tools-0.6.6 $(GPL_DIR)/apps/
endif
	cd $(TOPDIR)/apps/ipsec-tools-0.6.6 && \
	if test -e Makefile ; then make distclean ; fi && \
	touch configure && \
	./configure --prefix=/usr --build=i386 --host=mips-linux \
		--disable-ipv6 \
		--enable-dpd \
		--enable-natt \
		--with-kernel-headers=$(KERNELPATH)/include \
		--with-flexlib=$(TOPDIR)/apps/flex-2.5.4/libfl.a \
		--with-openssl=$(TOPDIR)/apps/openssl-0.9.8a &&\
	make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld LDFLAGS=$(IPSEC_LDFLAGS) AR=$(TOOLPREFIX)ar RANLIB=$(TOOLPREFIX)ranlib && \
	test -d $(INSTALL_ROOT)/usr/sbin/ || mkdir -p $(INSTALL_ROOT)/usr/sbin/ && \
	cp $(TOPDIR)/apps/ipsec-tools-0.6.6/src/setkey/setkey $(INSTALL_ROOT)/usr/sbin && \
	cp $(TOPDIR)/apps/ipsec-tools-0.6.6/src/racoon/racoon $(INSTALL_ROOT)/usr/sbin

# added by gengxianhu for NAS
# modify this path info for your environment
# path setting
# modify this path info for your environment
NAS_PATH=$(TOPDIR)/apps/nas
GPL_NAS_PATH=$(GPL_DIR)/apps/nas
NASPACKAGE_PATH=$(NAS_PATH)/naspackage/$(BOARD_TYPE)
GPL_NASPACKAGE_PATH=$(GPL_NAS_PATH)/naspackage/$(BOARD_TYPE)
ROOTFS_PATH=$(INSTALL_ROOT)
GPL_ROOTFS_PATH=$(GPL_INSTALL_ROOT)

# NAS build rule, don't copy NAS file to filesystem
usbp_build : 
ifeq ($(GPL_BUILD), y)
	cd $(NAS_PATH)/usbp && make clean
	mkdir -p $(GPL_NAS_PATH)
	cp -fr $(NAS_PATH)/usbp $(GPL_NAS_PATH)/
endif
	@echo making usbp ...
	cd $(NAS_PATH)/usbp && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld 

fuse_build:
	@echo making fuse kernel module ...
	cd $(NAS_PATH)/fuse-2.7.4 && \
	./configure --enable-kernel-module --with-kernel=$(KERNELPATH) --build=i686-linux --host=mips-linux CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	cd $(NAS_PATH)/fuse-2.7.4/kernel && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld

ntfs_build:
	@echo making ntfs ...
ifeq ($(GPL_BUILD), y)
	cp -fr $(NAS_PATH)/ntfs-3g_ntfsprogs-2012.1.15 $(GPL_NAS_PATH)/
endif
	cd $(NAS_PATH)/ntfs-3g_ntfsprogs-2012.1.15 && \
	./configure --build=i686-linux --host=mips-linux CC=$(TOOLPREFIX)gcc CXX=$(TOOLPREFIX)g++ AR=$(TOOLPREFIX)ar ac_cv_func_mbsinit=no ac_cv_header_syslog_h=no && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld 

#use new samba
samba_build:
	@echo build samba-TP...
ifeq ($(GPL_BUILD), y)
	cd $(NAS_PATH)/samba-TP/source && make clean
	cp -fr $(NAS_PATH)/samba-TP $(GPL_NAS_PATH)/
endif
	cd $(NAS_PATH)/samba-TP/source && make clean && \
	$(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld min

nas_build: ntfs_build samba_build #fuse_build usbp_build  
	@echo build nas over ...


# clean target for NAS
nas_clean: NAS_CLEAN = $(MAKE) clean 
nas_clean: NAS_DISTCLEAN = $(MAKE) distclean

samba_clean:
	cd $(NAS_PATH)/samba-TP/source && $(NAS_CLEAN)

# just clean file which is produced by nas_build
nas_clean: 
	@echo clean nas ...
#	cd $(NAS_PATH)/usbp && $(NAS_CLEAN) 
#	-cd $(NAS_PATH)/fuse-2.7.4 && $(NAS_DISTCLEAN)
	-cd $(NAS_PATH)/ntfs-3g_ntfsprogs-2012.1.15 && \
	if test -e Makefile; then $(NAS_CLEAN); fi
	cd $(NAS_PATH)/samba-TP/source && $(NAS_CLEAN)

# copy NAS file to naspackage
nas_copy: 
ifeq ($(GPL_BUILD), y)
	cp -r $(NAS_PATH)/naspackage $(GPL_NAS_PATH)
	mkdir -p $(GPL_TMP_INSTALL_ROOT)/tphotplug
	cp $(NAS_PATH)/tphotplug/tphotplug $(GPL_TMP_INSTALL_ROOT)/tphotplug/
endif
	@echo make sure target dir exists in naspackage
	rm -rf $(NASPACKAGE_PATH)
	if test ! -d $(NASPACKAGE_PATH); then mkdir -p $(NASPACKAGE_PATH); fi
	if test ! -d $(NASPACKAGE_PATH)/tphotplug ; then mkdir $(NASPACKAGE_PATH)/tphotplug; fi
#	if test ! -d $(NASPACKAGE_PATH)/usbp ; then mkdir $(NASPACKAGE_PATH)/usbp; fi
	if test ! -d $(NASPACKAGE_PATH)/ntfs-3g; then mkdir $(NASPACKAGE_PATH)/ntfs-3g; fi
	if test ! -d $(NASPACKAGE_PATH)/module; then mkdir $(NASPACKAGE_PATH)/module; fi
	@echo copy nas binary file to package directory ...
	@echo copy tphotplug
ifneq ($(OPENSOURCE_BUILD), y)
	cp -f $(NAS_PATH)/tphotplug/tphotplug $(NASPACKAGE_PATH)/tphotplug/tphotplug
else
	cp -f $(TMP_INSTALL_ROOT)/tphotplug/tphotplug $(NASPACKAGE_PATH)/tphotplug/tphotplug
endif
#	@echo copy usbp
#	cp -f $(NAS_PATH)/usbp/usbp $(NASPACKAGE_PATH)/usbp/usbp
	@echo copy fuse.ko
	-cp -f $(KERNELPATH)/fs/fuse/fuse.ko $(NASPACKAGE_PATH)/module/fuse.ko
	@echo copy usb kernel module
	-cp -f $(KERNELPATH)/drivers/usb/core/usbcore.ko $(NASPACKAGE_PATH)/module/usbcore.ko
	-cp -f $(KERNELPATH)/drivers/usb/host/ehci-hcd.ko $(NASPACKAGE_PATH)/module/ehci-hcd.ko
	#hornet do not has ohci-hcd.ko, for wr710 2.0
	-cp -f $(KERNELPATH)/drivers/usb/host/ohci-hcd.ko $(NASPACKAGE_PATH)/module/ohci-hcd.ko
	-cp -f $(KERNELPATH)/drivers/usb/storage/usb-storage.ko $(NASPACKAGE_PATH)/module/usb-storage.ko
	@echo copy fs kernel module
	-cp -f $(KERNELPATH)/fs/fat/fat.ko $(NASPACKAGE_PATH)/module/fat.ko
	-cp -f $(KERNELPATH)/fs/fat/vfat.ko $(NASPACKAGE_PATH)/module/vfat.ko
	-cp -f $(KERNELPATH)/fs/nls/nls_utf8.ko $(NASPACKAGE_PATH)/module/nls_utf8.ko
	-cp -f $(KERNELPATH)/fs/nls/nls_cp850.ko $(NASPACKAGE_PATH)/module/nls_cp850.ko
	@echo copy scsi module
	-cp -f $(KERNELPATH)/drivers/scsi/scsi_mod.ko $(NASPACKAGE_PATH)/module/scsi_mod.ko
	-cp -f $(KERNELPATH)/drivers/scsi/sg.ko $(NASPACKAGE_PATH)/module/sg.ko
	-cp -f $(KERNELPATH)/drivers/scsi/sd_mod.ko $(NASPACKAGE_PATH)/module/sd_mod.ko
	-cp -f $(KERNELPATH)/drivers/scsi/scsi_wait_scan.ko $(NASPACKAGE_PATH)/module/scsi_wait_scan.ko
	@echo copy ntfs-3g
	cp -f $(NAS_PATH)/ntfs-3g_ntfsprogs-2012.1.15/src/.libs/ntfs-3g $(NASPACKAGE_PATH)/ntfs-3g/ntfs-3g
	@echo copy libntfs-3g.so.83.0.0
	cp -f $(NAS_PATH)/ntfs-3g_ntfsprogs-2012.1.15/libntfs-3g/.libs/libntfs-3g.so.83.0.0 $(NASPACKAGE_PATH)/ntfs-3g/libntfs-3g.so.83.0.0

	@echo copy samba
	cp -r $(NAS_PATH)/naspackage/samba $(NASPACKAGE_PATH)

	cp -f $(NAS_PATH)/samba-TP/source/bin/smbd $(NASPACKAGE_PATH)/samba/smbd
	@echo hotplug and shell.sh
	cp -f $(NAS_PATH)/naspackage/shell.sh $(NASPACKAGE_PATH)

# run nas package shell to install NAS file to filesystem
nas_package:
	@echo package processing ...
	cd $(NASPACKAGE_PATH) && ./shell.sh $(INSTALL_ROOT_FOR_BOARD)
	
#  build NAS all, you can use prerequestes seperately by yourself 
nas: nas_clean nas_build nas_copy #nas_package
	@echo nas module process over ...
	
#nas_new: nas_clean nas_build nas_copy_new #nas_package
#	@echo nas module process over ...
#end nas build
	
# start build usbip server
USBIP_PATH=$(TOPDIR)/apps/usbip-0.1.7
usbip_build:
	@echo building usbip_server ...
	cd $(USBIP_PATH) && make clean && make
	
usbip_copy:
	@echo copying usbip.ko ...
	cp -f $(USBIP_PATH)/usbipd $(INSTALL_ROOT_FOR_BOARD)/usr/bin
	cp -f $(USBIP_PATH)/usbip.ko $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/nas
	cp -f $(USBIP_PATH)/usbip_common_mod.ko $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/nas
	
usbip_server: usbip_build
	@echo usbip_server module process over ...
# end build usbip server

#
# 3G tools build for apps build
#
ifeq ($(MODULE_3G), y)
export 3G_TOOLS_PATH = $(TOPDIR)/apps/3g_tools
export GPL_3G_TOOLS_PATH = $(GPL_DIR)/apps/3g_tools
export 3G_PACKAGE_PATH = $(IMAGEPATH)/3g
export GPL_3G_PACKAGE_PATH = $(GPL_IMAGEPATH)/3g

include $(3G_TOOLS_PATH)/Makefile
	
3g_prep:
	test -d $(3G_PACKAGE_PATH) || mkdir -p $(3G_PACKAGE_PATH)
ifeq ($(GPL_BUILD), y)
	test -d $(GPL_3G_PACKAGE_PATH) || mkdir -p $(GPL_3G_PACKAGE_PATH)
	mkdir -p $(GPL_3G_TOOLS_PATH)
endif

3g_tools:  3g_prep
ifneq ($(OPENSOURCE_BUILD), y)
	-rm -rf $(3G_PACKAGE_PATH)/*
endif
	cd $(3G_TOOLS_PATH) && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld 

3g_tools_install: 3g_prep
	cd $(3G_PACKAGE_PATH) && \
	cp -f chat $(INSTALL_ROOT_FOR_BOARD)/usr/sbin && \
	cp -f libusb-0.1.so.4.4.4 $(INSTALL_ROOT_FOR_BOARD)/lib && \
	ln -sf libusb-0.1.so.4.4.4 $(INSTALL_ROOT_FOR_BOARD)/lib/libusb-0.1.so.4 && \
	ln -sf libusb-0.1.so.4.4.4 $(INSTALL_ROOT_FOR_BOARD)/lib/libusb.so && \
	cp -f handle_card $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/ && \
	cp -f usr/sbin/usb_modeswitch $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/ && \
	cp -f modem_scan $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/ && \
	cp -f cmdmanage $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/ && \
	cp -f mode_switch.conf.bin $(INSTALL_ROOT_FOR_BOARD)/etc/ && \
	cp -f hotplug $(INSTALL_ROOT_FOR_BOARD)/sbin && \
	cp -rf etc/ppp $(INSTALL_ROOT_FOR_BOARD)/etc && \
	cp -rf etc/3gISP $(INSTALL_ROOT_FOR_BOARD)/etc
#	cp -rf etc/usb_modeswitch.d $(INSTALL_ROOT_FOR_BOARD)/etc/usb_modeswitch.d
	if grep 'mount -t usbfs none /proc/bus/usb' $(INSTALL_ROOT_FOR_BOARD)/etc/rc.d/rcS > /dev/null 2>&1 ; then \
	echo "rcS already have mount -t usbfs none /proc/bus/usb"  ;\
	else \
	sed 's/mount -t ramfs -n none \/var/mount -t ramfs -n none \/var\nmount -t usbfs none \/proc\/bus\/usb/' $(INSTALL_ROOT_FOR_BOARD)/etc/rc.d/rcS > $(INSTALL_ROOT_FOR_BOARD)/etc/rc.d/rcS.tmp && \
	mv -f $(INSTALL_ROOT_FOR_BOARD)/etc/rc.d/rcS.tmp $(INSTALL_ROOT_FOR_BOARD)/etc/rc.d/rcS && \
	chmod 755 $(INSTALL_ROOT_FOR_BOARD)/etc/rc.d/rcS ; \
	fi
ifeq ($(PRODUCT_ID), 0x90200001)
	rm $(INSTALL_ROOT_FOR_BOARD)/sbin/hotplug 
endif
endif
#end 3g tools

# Apple Devices USB charge
ifeq ($(MODULE_USB_IPAD_LITE), y)
export USB_IPAD_TOOLS_PATH = $(TOPDIR)/apps/usb_ipad_lite
export USB_IPAD_PACKAGE_PATH = $(IMAGEPATH)/ipad/

usb_ipad_lite:
	test -d $(USB_IPAD_PACKAGE_PATH) || mkdir -p $(USB_IPAD_PACKAGE_PATH)
	cd $(USB_IPAD_TOOLS_PATH) && make clean &&  make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar

usb_ipad_lite_install:
	cd $(USB_IPAD_PACKAGE_PATH) && \
	cp -f ipad_charge $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/
	
endif
#
# IPv6 tools build for apps build
#

#IPv6 tools, added by hejian, 121013
export IPV6_TOOLS_PATH = $(TOPDIR)/apps/ipv6_tools
export GPL_IPV6_TOOLS_PATH = $(TOPDIR)/apps/ipv6_tools
export IPV6_PACKAGE_PATH = $(IPV6_TOOLS_PATH)/ipv6_tools_output
export GPL_IPV6_PACKAGE_PATH = $(GPL_IPV6_TOOLS_PATH)/ipv6_tools_output

ipv6_prep:
ifeq ($(GPL_BUILD), y)
	test -d $(GPL_IPV6_PACKAGE_PATH) || mkdir -p $(GPL_IPV6_PACKAGE_PATH)
endif
	test -d $(IPV6_PACKAGE_PATH) || mkdir -p $(IPV6_PACKAGE_PATH)

#ipv6_tools: ipv6_prep libssl
ipv6_tools: ipv6_prep
ifeq ($(GPL_BUILD), y)
	cd $(TOPDIR)/apps/ipv6_tools && make clean
	cp -fr $(TOPDIR)/apps/ipv6_tools $(GPL_DIR)/apps/
endif
	-rm -rf $(IPV6_PACKAGE_PATH)/*
	cd $(TOPDIR)/apps/ipv6_tools && \
	make CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld

ipv6_tools_install: 
	cd $(IPV6_PACKAGE_PATH) && \
	#cp ip $(INSTALL_ROOT)/usr/sbin && \
	cp dhcp6s $(INSTALL_ROOT_FOR_BOARD)/usr/sbin && \
	cp dhcp6c $(INSTALL_ROOT_FOR_BOARD)/usr/sbin && \
	openssl rand -base64 16 > $(INSTALL_ROOT_FOR_BOARD)/etc/dhcp6sctlkey && \
	openssl rand -base64 16 > $(INSTALL_ROOT_FOR_BOARD)/etc/dhcp6cctlkey && \
	cp dhcp6ctl $(INSTALL_ROOT_FOR_BOARD)/usr/sbin && \
	cp radvd $(INSTALL_ROOT_FOR_BOARD)/usr/sbin  && \
	cp radvdctl $(INSTALL_ROOT_FOR_BOARD)/usr/sbin && \
	cp ping6 $(INSTALL_ROOT_FOR_BOARD)/usr/sbin && \
	ls -al $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/*
	#sleep 2
#	cp dnsproxy $(INSTALL_ROOT)/usr/sbin
#endi ipv6

#for debug use
SAR_PATH=$(TOPDIR)/apps/sysstat-6.0.1/

sar_build:
	@echo making sar
	cd $(SAR_PATH) && rm -f sysstat.cron.daily && rm -f sysstat.cron.hourly && $(MAKE) CC=$(TOOLPREFIX)gcc clean && $(MAKE) CC=$(TOOLPREFIX)gcc 
	cd $(SAR_PATH) && cp sar $(INSTALL_ROOT)/usr/bin/
	cd $(SAR_PATH) && cp sadc $(INSTALL_ROOT)/usr/bin/

web_server:
	echo -n "BUILD_TIME = " > $(TOPDIR)/web_server/sys/buildtime.h;
	expr `date +%H` \* 3600 + `date +%M` \* 60 + `date +%S` >> $(TOPDIR)/web_server/sys/buildtime.h;
	echo -n "BUILD_DATE = " >> $(TOPDIR)/web_server/sys/buildtime.h;
	@date +%D >> $(TOPDIR)/web_server/sys/buildtime.h;
	
	if test $(clean) -eq 1; then \
	cd $(TOPDIR)/web_server && 	make clean; \
	fi;
	
	cd $(TOPDIR)/web_server && $(MAKE) CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld && \
	ls -l httpd && \
	cp httpd $(IMAGEPATH) && cp httpd $(TFTPPATH)

ProductID_Back:
	@chmod 777 productIdAdd.sh
	./productIdAdd.sh  ./products_config/$(DEV_NAME)/model.conf   ../web_server/sys/ Back

ProductID_Add:
	@chmod 777 productIdAdd.sh
	./productIdAdd.sh  ./products_config/$(DEV_NAME)/model.conf   ../web_server/sys/ Add

httpd_build:
ifeq ($(FEATURE_WEB_NEWLOGO), y)
	sed -i "s/#define.*HTTP_SOCK_ARRAY.*4.*\/\*1/#define HTTP_SOCK_ARRAY  6     \/\*1/g" ../web_server/common_h/wmw_httpconf.h
	sed -i "s/OUTPUT_ARRAY_HEAD(\"visibleMenuList\");/httpPrintf(reqId, \"<!Doctype html>\\\n\");OUTPUT_ARRAY_HEAD(\"visibleMenuList\");/g" ../web_server/web_s/basicWeb/httpMenu.c
ifeq ($(FEATURE_PPPOE_PATCH), y)
	sed -i "s/swGetPppoeV6Cfg(\&wanOldPppoev6Cfg);/swGetPppoeV6Cfg(nWanIndex,\&wanOldPppoev6Cfg);/g" ../web_server/web_s/ipv6/httpNetworkWanPPPoEv6.c
endif
endif
ifeq ($(FEATURE_PRODUCTID_ADD), y)
	make ProductID_Add
endif
ifneq ($(OPENSOURCE_BUILD), y)
ifneq ($(findstring $(BOARD_TYPE), pb92 ap123 ap123-dsa ap124 ap143 db12x ap143-2.0 ap151 ap121 ap135_hnat ap152), )
	make web_server clean=1 &&\
	cd $(TOPDIR)/web_server &&\
	cp httpd $(TOPDIR)/images/$(DEV_NAME)/
ifeq ($(GPL_BUILD), y)
	mkdir -p $(GPL_DIR)/web_server/sys
	cp $(TOPDIR)/web_server/sys/buildtime.h $(GPL_DIR)/web_server/sys/
	mkdir -p $(GPL_DIR)/web_server/msglogd
	cp $(TOPDIR)/web_server/msglogd/libmsglog.h $(GPL_DIR)/web_server/msglogd/
	cp $(TOPDIR)/web_server/msglogd/libmsglog.so $(GPL_DIR)/web_server/msglogd/
	cd $(TOPDIR)/web_server && cp httpd $(GPL_DIR)/images/$(DEV_NAME)/
endif
endif
else
	cp $(TOPDIR)/web_server/msglogd/libmsglog.so $(INSTALL_ROOT)/lib/
endif
ifeq ($(FEATURE_PRODUCTID_ADD), y)
	make ProductID_Back
endif
ifeq ($(FEATURE_WEB_NEWLOGO), y)
	sed -i "s/#define.*HTTP_SOCK_ARRAY.*6.*\/\*1/#define HTTP_SOCK_ARRAY  4     \/\*1/g" ../web_server/common_h/wmw_httpconf.h
	sed -i "s/httpPrintf(reqId, \"<!Doctype html>\\\n\");OUTPUT_ARRAY_HEAD(\"visibleMenuList\");/OUTPUT_ARRAY_HEAD(\"visibleMenuList\");/g" ../web_server/web_s/basicWeb/httpMenu.c
ifeq ($(FEATURE_PPPOE_PATCH), y)
	sed -i "s/swGetPppoeV6Cfg(nWanIndex,\&wanOldPppoev6Cfg);/swGetPppoeV6Cfg(\&wanOldPppoev6Cfg);/g" ../web_server/web_s/ipv6/httpNetworkWanPPPoEv6.c
endif
endif

#
# utils
#
make_flash:
	cd $(TOPDIR)/util/make_flash_src/ && make && \
	cp make_flash $(TOPDIR)/util/

md5_des:
	cd $(TOPDIR)/util/md5_des_src/ && gcc main.c md5_des.c -o md5_des && \
	cp md5_des $(TOPDIR)/util/
		
#
# fs and image
#
strip_bin:
	$(STRIP) $(INSTALL_ROOT_FOR_BOARD)/bin/*
ifneq ($(findstring $(BOARD_TYPE), pb92), )
	mv $(INSTALL_ROOT_FOR_BOARD)/sbin/wpa_supplicant $(INSTALL_ROOT_FOR_BOARD)
	-$(STRIP) $(INSTALL_ROOT_FOR_BOARD)/sbin/*
	mv $(INSTALL_ROOT_FOR_BOARD)/wpa_supplicant $(INSTALL_ROOT_FOR_BOARD)/sbin/wpa_supplicant
else
	-$(STRIP) $(INSTALL_ROOT_FOR_BOARD)/sbin/*
endif
	$(STRIP) $(INSTALL_ROOT_FOR_BOARD)/usr/bin/*
	$(STRIP) $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/*
ifneq ($(filter $(BOARD_TYPE), ap121 ap123 ap123-dsa  ap124), )
	$(STRIP) $(INSTALL_ROOT_FOR_BOARD)/lib/*0.9.30.so
	$(STRIP) $(INSTALL_ROOT_FOR_BOARD)/lib/libgcc_s.so.1
endif
ifeq ($(MODULE_IPSEC_VPN), y)
	$(STRIP) $(INSTALL_ROOT)/lib/libcrypto.so.0.9.8 
	$(STRIP) $(INSTALL_ROOT)/lib/libssl.so.0.9.8
endif
	if [ -x $(INSTALL_ROOT_FOR_BOARD)/usr/arp ] ; then $(STRIP) $(INSTALL_ROOT_FOR_BOARD)/usr/arp ; fi
	if [ -x $(INSTALL_ROOT_FOR_BOARD)/usr/net_ioctl ] ; then $(STRIP) $(INSTALL_ROOT_FOR_BOARD)/usr/net_ioctl ; fi

strip_libs:
	cd $(INSTALL_ROOT_FOR_BOARD)/lib/ && \
	find . -name "*.so" | xargs $(STRIP) && \
	#find . -name "*.ko" | xargs ../../build/gcc-4.3.3/build_mips/staging_dir/usr/bin/mips-linux-sstrip && \
	echo "strip libs finished"

strip_kmod:
	find $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER) -name "*.ko" -type f | xargs \
	$(OLDSTRIP) \
			--strip-unneeded \
			--remove-section=.mdebug.abi32 \
			--remove-section=.comment \
			--remove-section=__ksymtab_unused \
			--remove-section=__kcrctab_unused \
			--remove-section=__ksymtab_unused_gpl \
			--remove-section=__kcrctab_unused_gpl
	
apxxfus_fs_prep:
	rm -Rf $(INSTALL_ROOT_FOR_BOARD)
	cp -Rf $(INSTALL_ROOT) $(INSTALL_ROOT_FOR_BOARD)
	@echo MODULE_3G=$(MODULE_3G)
# kernel_debug usb_net for LTE support

ifeq ($(MODULE_3G), y)
ifneq ($(FEATURE_FS_SIZE_CUT), y)
	make kernel_debug_install
endif
	make usb_net
	make 3g_tools_install
endif

ifeq ($(MODULE_USB_IPAD_LITE), y)
	make usb_ipad_lite_install
endif

ifeq ($(MODULE_IPV6), y)
	make ipv6_tools_install
endif

ifeq ($(MODULE_WOL), y)
	cd $(TOPDIR)/apps/wol && make clean &&  make CC=$(TOOLPREFIX)gcc LD=$(TOOLPREFIX)ld AR=$(TOOLPREFIX)ar && \
	cp wol $(INSTALL_ROOT_FOR_BOARD)/usr/sbin
endif

	make kernel_modules_install	
	make wireless_install
ifeq ($(MODULE_NAS), y)
	make nas_package
#added by ZQQ, 2014.11.17, WR710ND(UK) 2.0 do not has the FTP
ifeq ($(MODULE_FTP), y)
	cp $(IMAGEPATH)/vsftpd $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/
endif
ifeq ($(MODULE_MEDIA_SERVER), y)
ifeq ($(FEATURE_MEDIA_SERVER_USE_MINIDLNA), y)
	$(TOPDIR)/apps/nas/media_server/media_server_minidlna_install.sh $(NAS_PATH)/naspackage $(INSTALL_ROOT_FOR_BOARD)
else
	$(TOPDIR)/apps/nas/media_server/media_server_install.sh $(BOARD_TYPE) $(INSTALL_ROOT_FOR_BOARD)
endif
endif	
# usbip_server has been replaced by NetUSB_kcodes(see BOARD_KERNEL_MODULES), hided by tf
#	make usbip_copy
endif
	cp $(IMAGEPATH)/httpd $(INSTALL_ROOT_FOR_BOARD)/usr/bin/
ifeq ($(MODULE_SNMP),y)
	cp $(IMAGEPATH)/snmpd $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/
endif
	ls -al $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/*
	sleep 1
	make strip_bin
	ls -al $(INSTALL_ROOT_FOR_BOARD)/usr/sbin/*
	sleep 1
    #strip the *.so which are copied from the rootfs.build.2.6.31 to reduce size, it is about 4M saved. by ZQQ, 2014.11.20
	make strip_libs
	
	@mv $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/kernel/$(enet)_mod.ko $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/net/
	@-mv $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/kernel/$(enet)_mod_r.ko $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/net/ >/dev/null 2>&1
	@-mv $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/kernel/$(enet)_readid.ko $(INSTALL_ROOT_FOR_BOARD)/lib/modules/$(KERNELVER)/net/ >/dev/null 2>&1
	@test -d $(WEBDIR)/$(lang)/tmpweb || mkdir -p $(WEBDIR)/$(lang)/tmpweb
	@rm -rf $(WEBDIR)/$(lang)/tmpweb/*
ifneq ($(OPENSOURCE_BUILD), y)
	make webs_modules_package	
	@cd $(WEBDIR)/utils/web_collector/ && ./webc -s $(WEBDIR)/$(lang)/tmpweb -d $(INSTALL_ROOT_FOR_BOARD)/web >/dev/null 2>&1
	
ifeq ($(FEATURE_REMOVE_UTF8_BOM), y)
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name '*.htm' -o -name '*.html' -o -name '*.js' -o -name '*.css' | xargs sed -i '1 s/^\xef\xbb\xbf//g'
endif

ifeq ($(FEATURE_FS_SIZE_CUT), y)
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i 's:/\*.*\*/::g'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i 's/^[ \t]*//'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i '/^\s*\/\/\w?*/d'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i '/^[ \t]*\/\*/,/.*\*\//d'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i 's:<\!--.*-->::g'
endif
	
#compress CA pages
ifeq ($(FEATURE_DUAL_LANGUAGE),y)
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i 's:/\*.*\*/::g'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i 's/^[ \t]*//'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i '/^\s*\/\/\w?*/d'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i '/^[ \t]*\/\*/,/.*\*\//d'
	@find $(INSTALL_ROOT_FOR_BOARD)/web -name "*.htm" | xargs sed -i 's:<\!--.*-->::g'
ifeq ($(MODULE_GUESTNETWORK_V2),y)
ifeq ($(MODULE_NAS),n)
	@rm $(INSTALL_ROOT_FOR_BOARD)/web/userRpm/GuestNetFolderAdvRpm.htm
	@rm $(INSTALL_ROOT_FOR_BOARD)/web/userRpm/GuestNetUsbCfgRpm.htm
	@rm $(INSTALL_ROOT_FOR_BOARD)/web/userRpm/GuestNetUserModifyRpm.htm
	@rm $(INSTALL_ROOT_FOR_BOARD)/web/help/GuestNetFolderAdvHelpRpm.htm
	@rm $(INSTALL_ROOT_FOR_BOARD)/web/help/GuestNetUsbCfgHelpRpm.htm
endif
endif
endif
	
ifeq ($(GPL_BUILD), y)
	mkdir -p $(GPL_WEBDIR)/$(lang)
	cp -fr $(INSTALL_ROOT_FOR_BOARD)/web $(GPL_WEBDIR)/$(lang)/
endif
	@rm -rf $(WEBDIR)/$(lang)/tmpweb
else
	cp -fr $(WEBDIR)/$(lang)/web $(INSTALL_ROOT_FOR_BOARD)/
endif
	@test -d $(INSTALL_ROOT_FOR_BOARD)/web/oem/ || mkdir -p $(INSTALL_ROOT_FOR_BOARD)/web/oem/
#	@cp $(TOPDIR)/$(WEBS)/models/$(conf_file) $(TOPDIR)/$(WEBS)/models/model_tmp.conf
	@cp $(MODEL_CONFIG_FILE) $(PRODUCT_CONFIG_DIR)/model_tmp.conf
ifeq ($(MODULE_DROPBEAR),y)
	@cd $(INSTALL_ROOT_FOR_BOARD)/ && chmod 1777 ./tmp
endif

ifeq ($(FEATURE_FS_SIZE_CUT), y)
ifeq ($(strip $(BOARD_TYPE)), ap143-2.0)
	@-rm $(TOPDIR)/rootfs.$(DEV_NAME)/lib/modules/2.6.31/net/art-honeybee-2.0.ko
endif
endif

ifeq ($(MODULE_3G), y)
ifneq ($(FEATURE_FS_SIZE_CUT), y)
	@rm $(TOPDIR)/rootfs.$(DEV_NAME)/lib/modules/2.6.31/kernel/option.ko
endif
endif
	@-rm $(TOPDIR)/rootfs.$(DEV_NAME)/sbin/80211stats
	@-rm $(TOPDIR)/rootfs.$(DEV_NAME)/sbin/apstats
	@-rm $(TOPDIR)/rootfs.$(DEV_NAME)/sbin/athstats
	@-rm $(TOPDIR)/rootfs.$(DEV_NAME)/sbin/athstatsclr
	@-rm $(TOPDIR)/rootfs.$(DEV_NAME)/sbin/pktlogconf
	@-rm $(TOPDIR)/rootfs.$(DEV_NAME)/sbin/pktlogdump
ifeq ($(FEATURE_WEB_NEWUI), y)
	@rm -fr $(TOPDIR)/rootfs.$(DEV_NAME)/web/frames
	@rm -fr $(TOPDIR)/rootfs.$(DEV_NAME)/web/data
	@rm -fr $(TOPDIR)/rootfs.$(DEV_NAME)/web/locale/zh_CN
	@rm -fr $(TOPDIR)/rootfs.$(DEV_NAME)/web/js/jquery_ui
	@rm -fr $(TOPDIR)/rootfs.$(DEV_NAME)/web/js/libs
endif

fill_model_conf:
	@echo "" >> $(PRODUCT_CONFIG_DIR)/model_tmp.conf
	@cp -f $(PRODUCT_CONFIG_DIR)/../version_common.conf $(PRODUCT_CONFIG_DIR)/../version.conf
	@-cp -f $(PRODUCT_CONFIG_DIR)/version.conf	$(PRODUCT_CONFIG_DIR)/../version.conf
	@cat $(PRODUCT_CONFIG_DIR)/../version.conf >> $(PRODUCT_CONFIG_DIR)/model_tmp.conf
	@echo "" >> $(PRODUCT_CONFIG_DIR)/model_tmp.conf
	@cat $(TOPDIR)/web_server/sys/buildtime.h >> $(PRODUCT_CONFIG_DIR)/model_tmp.conf
	@$(TOPDIR)/util/md5_des $(PRODUCT_CONFIG_DIR)/model_tmp.conf $(INSTALL_ROOT_FOR_BOARD)/web/oem/model.conf enc


ifeq ($(MODULE_NVRAMMNGR), y)	
mk_squashfs_build:
	make fill_model_conf
	@find $(INSTALL_ROOT_FOR_BOARD) -name ".svn" | xargs rm -rf
# Here, remove the nonsense static archive libs
	@find $(INSTALL_ROOT_FOR_BOARD)/lib/ -name "*.a" | xargs rm -rf
	@find $(INSTALL_ROOT_FOR_BOARD)/lib/ -name "*.la" | xargs rm -rf
	@$(TOPDIR)/util/fakeroot/install/bin/fakeroot $(TOPDIR)/util/buildFS_LZ
	@ls -l $(IMAGEPATH)/$(FS_NAME)
	@cp $(IMAGEPATH)/$(FS_NAME) $(TFTPPATH)

TEMP:=$(shell grep -w "SYS_SOFTWARE_REVISION" $(PRODUCT_CONFIG_DIR)/model_tmp.conf | cut -d " " -f 3 | cut -b 7-8)
FIRST:=$(shell echo $$((16\#$(TEMP))))
TEMP:=$(shell grep -w "SYS_SOFTWARE_REVISION" $(PRODUCT_CONFIG_DIR)/model_tmp.conf | cut -d " " -f 3 | cut -b 9-10)
SECOND:=$(shell echo $$((16\#$(TEMP))))
TEMP:=$(shell grep -w "SYS_SOFTWARE_REVISION_MINOR" $(PRODUCT_CONFIG_DIR)/model_tmp.conf | cut -d " " -f 3 | cut -b 3-4)
THIRD:=$(shell echo $$((16\#$(TEMP))))
SOFTWARE_VERSION_STR:=V$(FIRST).$(SECOND).$(THIRD)P1

image_build:
	@echo 'nvrammanager building firmwares ...'
	@cp -f $(PRODUCT_CONFIG_DIR)/partition.conf $(IMAGEPATH)/partition.conf
	@cp -f $(PRODUCT_CONFIG_DIR)/supportlist.bin $(IMAGEPATH)/supportlist.bin
	@cp -f $(PRODUCT_CONFIG_DIR)/productinfo.bin $(IMAGEPATH)/productinfo.bin
	@cp -f $(TOPDIR)/util/addtphdr $(IMAGEPATH)/addtphdr
	@cd $(IMAGEPATH) && ./addtphdr -k ./vmlinux.bin.gz -o ./tp.vmlinux.bin.gz
	@cd $(IMAGEPATH) && $(TOPDIR)/util/nm_make_flash -p partition.conf -o "$(prefix)" -s "$(SOFTWARE_VERSION_STR)" -d 

else
mk_squashfs_build:
	make fill_model_conf
	@find $(INSTALL_ROOT_FOR_BOARD) -name ".svn" | xargs rm -rf
# Here, remove the nonsense static archive libs
	@find $(INSTALL_ROOT_FOR_BOARD)/lib/ -name "*.a" | xargs rm -rf
	@find $(INSTALL_ROOT_FOR_BOARD)/lib/ -name "*.la" | xargs rm -rf
	@$(TOPDIR)/util/fakeroot/install/bin/fakeroot $(TOPDIR)/util/buildFS_LZ
	@ls -l $(IMAGEPATH)/$(FS_NAME)
	@$(TOPDIR)/util/pad -i $(IMAGEPATH)/$(FS_NAME) -p $(fs_size)
	@cp $(IMAGEPATH)/$(FS_NAME) $(TFTPPATH)

image_build:
	cd $(IMAGEPATH)/ && \
	$(MAKE_FLASH_TOOL) -b $(UBOOT_FILE) -k $(KTFILE).gz -f $(FS_NAME) \
	-o $(prefix) -c $(PRODUCT_CONFIG_DIR)/model_tmp.conf -t $(TOPDIR)/web_server/sys/buildtime.h && \
	chmod 777 *
	rm -f $(PRODUCT_CONFIG_DIR)/model_tmp.conf \

endif

gpl_prep:
	@echo build gpl file
	#if test -d $(GPL_DIR); then rm -fr $(GPL_DIR);fi;
	mkdir -p $(GPL_DIR)
	mkdir -p $(GPL_DIR)/$(BOARD_TYPE)
	mkdir -p $(GPL_DIR)/$(BOARD_TYPE)/boot
	mkdir -p $(GPL_IMAGEPATH)
	mkdir -p $(GPL_DIR)/apps
	mkdir -p $(GPL_PRODUCT_CONFIG_DIR)
	cp $(PRODUCT_CONFIG_DIR)/* $(GPL_PRODUCT_CONFIG_DIR)/
	cp $(PRODUCT_CONFIG_DIR)/../version* $(GPL_PRODUCT_CONFIG_DIR)/../
	cp $(TOPDIR)/build/Makefile $(GPL_DIR)/build/
	sed -i 's/^ifndef DEV_NAME$$/export DEV_NAME=$(DEV_NAME)\nall:\n\nifndef DEV_NAME/' $(GPL_DIR)/build/Makefile
	echo "" >> $(GPL_DIR)/build/Makefile
	echo "all: fakeroot_build toolchain_prep fs_prep linux_build_all" >> $(GPL_DIR)/build/Makefile
	echo "" >> $(GPL_DIR)/build/Makefile
	cp $(TOPDIR)/build/Makefile.modules $(GPL_DIR)/build/
	cp $(TOPDIR)/build/Makefile.help $(GPL_DIR)/build/
	cp $(TOPDIR)/build/snmp.mk $(GPL_DIR)/build/
	echo "export DEV_NAME=$(DEV_NAME)" >> $(GPL_PRODUCT_CONFIG_DIR)/basic.config
	echo "export OPENSOURCE_BUILD=y" >> $(GPL_PRODUCT_CONFIG_DIR)/basic.config
	echo $(DEV_NAME): httpd_build > $(GPL_DIR)/build/Makefile.image
	echo "	make apxxfus_fs_prep enet=$(IMAGE_ENET) lang=$(IMAGE_LANG) oem_dir=$(IMAGE_OEMDIR)" >> $(GPL_DIR)/build/Makefile.image
	echo "	make mk_squashfs_build fs_size=$(IMAGE_FS_SIZE)" >> $(GPL_DIR)/build/Makefile.image
	echo "	make image_build prefix=$(DEV_NAME)" >> $(GPL_DIR)/build/Makefile.image
	echo "" >> $(GPL_DIR)/build/Makefile.image
	mkdir -p $(GPL_DIR)/util
	cp -fr $(TOPDIR)/util/lzma $(GPL_DIR)/util/
	cp $(TOPDIR)/util/buildFS $(GPL_DIR)/util/
	cp $(TOPDIR)/util/buildFS_LZ $(GPL_DIR)/util/
	cp $(TOPDIR)/util/cplibs $(GPL_DIR)/util/
	cp $(TOPDIR)/util/make_flash $(GPL_DIR)/util/
	cp $(TOPDIR)/util/make_flash-16M $(GPL_DIR)/util/
	cp $(TOPDIR)/util/make_flash_v2 $(GPL_DIR)/util/
	cp $(TOPDIR)/util/make_flash_v3 $(GPL_DIR)/util/
	cp $(TOPDIR)/util/md5_des $(GPL_DIR)/util/
	cp $(TOPDIR)/util/mkdev $(GPL_DIR)/util/
	cp $(TOPDIR)/util/mkdev.new $(GPL_DIR)/util/
	cp -fr $(TOPDIR)/util/mkfirmware $(GPL_DIR)/util/
	cp $(TOPDIR)/util/mksquashfs $(GPL_DIR)/util/
	cp $(TOPDIR)/util/mksquashfs4 $(GPL_DIR)/util/
	cp $(TOPDIR)/util/mksquashfs4-ap143 $(GPL_DIR)/util/
	cp $(TOPDIR)/util/pad $(GPL_DIR)/util/
	cp $(TOPDIR)/util/rmblankforhtm $(GPL_DIR)/util/
	cp $(TOPDIR)/util/rmfilesfor3g $(GPL_DIR)/util/
	cp $(TOPDIR)/util/rmfilesforap $(GPL_DIR)/util/
	cp $(TOPDIR)/util/rm_item_not_under_svnctl.sh $(GPL_DIR)/util/
	cp $(TOPDIR)/util/rmjunkfiles $(GPL_DIR)/util/
	mkdir -p $(GPL_DIR)/filesystem
	cp -fr $(TOPDIR)/filesystem/ap93fus $(GPL_DIR)/filesystem/

gpl_pkg:
	cp $(TOPDIR)/GPL/COPYING $(GPL_DIR)
	cp $(TOPDIR)/GPL/README  $(GPL_DIR)
	cd $(GPL_DIR) && \
	find -name ".svn" | xargs rm -rf && \
	sed -i 's/DEV_NAME/$(DEV_NAME)/g' README && \
	sed -i 's/GPL_PACKAGE_NAME/$(GPL_PACKAGE_NAME)/g' README
	cd $(TOPDIR) && \
	tar -czf $(GPL_PACKAGE_NAME).tar.gz $(GPL_DIR)

Emulator_build:
	@test -d $(WEBDIR)/$(lang)/tmpweb || mkdir -p $(WEBDIR)/$(lang)/tmpweb
	@rm -rf $(WEBDIR)/$(lang)/tmpweb/*
	chmod 777 -R ../util/makeEmulator/
	make webs_modules_package FEATURE_EMULATOR_MK=y
	#make webs_modules_package
	mkdir -p $(EMULATOR_DIR)
	@rm -rf $(EMULATOR_DIR)/*
	cp -fr $(WEBDIR)/$(lang)/tmpweb/*  $(EMULATOR_DIR)/
	@rm -rf $(WEBDIR)/$(lang)/tmpweb
ifeq ($(FEATURE_DUAL_LANGUAGE),y)
ifeq ($(MODULE_GUESTNETWORK_V2),y)
ifeq ($(MODULE_NAS),n)
	@rm $(EMULATOR_DIR)/userRpm/GuestNetFolderAdvRpm.htm
    @rm $(EMULATOR_DIR)/userRpm/GuestNetUsbCfgRpm.htm
    @rm $(EMULATOR_DIR)/userRpm/GuestNetUserModifyRpm.htm
    @rm $(EMULATOR_DIR)/help/GuestNetFolderAdvHelpRpm.htm
    @rm $(EMULATOR_DIR)/help/GuestNetUsbCfgHelpRpm.htm
endif
endif
endif

ifeq ($(GPL_BUILD), y)
linux_build_all: gpl_prep uboot kernel_build kernel_modules wireless apps_build $(DEV_NAME) gpl_pkg
else
linux_build_all: uboot kernel_build kernel_modules wireless apps_build $(DEV_NAME)
endif


all: fakeroot_build toolchain_prep fs_prep linux_build_all

