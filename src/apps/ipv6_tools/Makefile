#
# ipv6 tools Makefile
#  create by ZQQ 11.03.07
# 

CURRENTDIR = $(IPV6_TOOLS_PATH)
LIBUSBMIPS = install_libnl-1.1_mips
LIBOPENSSL = install_libopenssl

.PHONY: all
#all: ip_build 6to4config_build dhcpv6_build dproxy_build ipcserver_build radvd dproxy_nexgen_build
#all: clean radvd_build ip_2.6.33_build dhcpv6_build dproxy_nexgen_build iputils_build radvdCtl_build
all: clean radvd_build dhcpv6_build iputils_build radvdCtl_build 
#all: clean iputils_build
#all: dproxy_nexgen_build

mcast_tools_build:
	cd $(CURRENTDIR)/mcast-tools && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	ls

ip_build:
	@echo *******************make ip_build************************
	cd $(CURRENTDIR)/iproute2-2.6.31 && \
	$(MAKE) clean && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	#ls -l $(CURRENTDIR)/iproute2-2.6.31/ip/ip && $(TOOLPREFIX)sstrip $(CURRENTDIR)/iproute2-2.6.31/ip/ip && ls -l $(CURRENTDIR)/iproute2-2.6.31/ip/ip && \
	cp -f $(CURRENTDIR)/iproute2-2.6.31/ip/ip $(IPV6_PACKAGE_PATH)

ip_2.6.33_build:
	@echo *******************make ip_2.6.33_build************************
	cd $(CURRENTDIR)/iproute2-2.6.33 && \
	$(MAKE) clean && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	#ls -l $(CURRENTDIR)/iproute2-2.6.33/ip/ip && $(TOOLPREFIX)sstrip $(CURRENTDIR)/iproute2-2.6.33/ip/ip && ls -l $(CURRENTDIR)/iproute2-2.6.33/ip/ip && \
	cp -f $(CURRENTDIR)/iproute2-2.6.33/ip/ip $(IPV6_PACKAGE_PATH)

dproxy_nexgen_build:
	@echo *******************make dproxy_nexgen_build************************
	cd $(CURRENTDIR)/dproxy-nexgen && \
	$(MAKE) clean && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	#ls -l $(CURRENTDIR)/dproxy-nexgen/dnsproxy && $(TOOLPREFIX)sstrip $(CURRENTDIR)/dproxy-nexgen/dnsproxy && ls -l $(CURRENTDIR)/dproxy-nexgen/dnsproxy && \
	cp -f $(CURRENTDIR)/dproxy-nexgen/dnsproxy $(IPV6_PACKAGE_PATH)
	
dhcpv6_build:
	@echo *******************make dhcpv6_build************************
	cd $(CURRENTDIR)/wide-dhcpv6 && \
	$(MAKE) clean && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	#ls -l dhcp6s && $(TOOLPREFIX)sstrip dhcp6s && ls -l dhcp6s && \
	#ls -l dhcp6c && $(TOOLPREFIX)sstrip dhcp6c && ls -l dhcp6c && \
	#ls -l dhcp6ctl && $(TOOLPREFIX)sstrip dhcp6ctl && ls -l dhcp6ctl && \
	cp dhcp6s $(IPV6_PACKAGE_PATH) && \
	cp dhcp6c $(IPV6_PACKAGE_PATH) && \
	cp dhcp6ctl $(IPV6_PACKAGE_PATH)
	
radvd_build:
	@echo *******************make radvd_build************************
	cd $(CURRENTDIR)/radvd-1.7 && \
	./configure --prefix=$(CURRENTDIR)/radvd-1.7/install --build=i686-linux --host=mips-linux CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar && \
	$(MAKE) clean && \
	cp scanner_flex.c scanner.c && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	#ls -l radvd && $(TOOLPREFIX)sstrip radvd && ls -l radvd && \
	cp radvd $(IPV6_PACKAGE_PATH)

radvdCtl_build:
	@echo *******************make radvdCtl_build************************
	cd $(CURRENTDIR)/radvdCtl && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	#ls -l radvdctl && $(TOOLPREFIX)sstrip radvdctl && ls -l radvdctl && \
	cp radvdctl $(IPV6_PACKAGE_PATH)

ipcserver_build:
	@echo *******************make ipcserver_build************************
	cd $(CURRENTDIR)/ipcserver && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	#ls -l ipcserver && $(TOOLPREFIX)sstrip ipcserver && ls -l ipcserver && \
	cp ipcserver $(IPV6_PACKAGE_PATH)
	
libnl-1.1:ipv6_tools_prep
	@echo *******************make libnl-1.1************************
	cd $(CURRENTDIR)/libnl-1.1 && \
	if [ ! \( \( -e Makefile \) -a \( -e $(CURRENTDIR)/$(LIBUSBMIPS)/lib/libnl.so \) \) ]; then \
	chmod 777 configure && \
	./configure --prefix=$(CURRENTDIR)/$(LIBUSBMIPS) --build=i686-linux --host=mips-linux CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld install ; \
	fi 
	cp $(CURRENTDIR)/$(LIBUSBMIPS)/lib/libnl-1.1 $(3G_PACKAGE_PATH)
	
ipv6_tools_prep:
	test -d $(CURRENTDIR)/$(LIBUSBMIPS) || mkdir -p $(CURRENTDIR)/$(LIBUSBMIPS) && \
	test -d $(CURRENTDIR)/$(LIBOPENSSL) || mkdir -p $(CURRENTDIR)/$(LIBOPENSSL)

libopenssl_build:ipv6_tools_prep
	@echo *******************make libopenssl_build************************
	cd $(CURRENTDIR)/openssl-1.0.0d && \
	touch Makefile && \
	./Configure os/compiler:$(TOOLPREFIX)gcc --prefix=$(CURRENTDIR)/$(LIBOPENSSL) && \
	$(MAKE) clean && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR="$(TOOLPREFIX)ar r" LD=$(TOOLPREFIX)ld && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld install ; \
	
#iputils_build:libopenssl_build
iputils_build:
	@echo *******************make iputils_build************************
	cd $(CURRENTDIR)/iputils && \
	$(MAKE) CC=$(TOOLPREFIX)gcc AR=$(TOOLPREFIX)ar LD=$(TOOLPREFIX)ld  && \
	#ls -l ping6 && $(TOOLPREFIX)sstrip ping6 && ls -l ping6 && \
	mv -f ping6 $(IPV6_PACKAGE_PATH)
	


clean:
	find . -name "*.o" | xargs  rm -rf
