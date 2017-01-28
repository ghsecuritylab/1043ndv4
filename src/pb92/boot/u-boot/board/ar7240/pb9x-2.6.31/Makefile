include $(TOPDIR)/config.mk

LIB	= lib$(BOARD).a

OBJS	= $(BOARD).o flash.o ../common/ar7240_pci.o ../common/ar7240_flash.o 

ifeq ($(ENABLE_8367R_VB_SWITCH),1)
RTL_PATH = ../common/rtl8367r_phy

OBJS	+= $(RTL_PATH)/rtk_api.o $(RTL_PATH)/rtl_phy.o 
OBJS	+= $(RTL_PATH)/smi.o $(RTL_PATH)/rtl8367b_asicdrv.o 
OBJS	+= $(RTL_PATH)/rtl8367b_asicdrv_phy.o 
OBJS	+= $(RTL_PATH)/rtl8367b_asicdrv_port.o

#OBJS	+= $(RTL_PATH)/rtl8367b_asicdrv_green.o $(RTL_PATH)/ar7240_rtl8367r_phy.o 
#OBJS	+= $(RTL_PATH)/rtl8367b_asicdrv_vlan.o  
#OBJS	+= $(RTL_PATH)/rtl8367b_asicdrv_misc.o 
#OBJS	+= $(RTL_PATH)/rtl8367b_asicdrv_led.o $(RTL_PATH)/rtl8367b_asicdrv_dot1x.o

CFLAGS 	+= -DCHIP_RTL8367_VB -I../common/include
CFLAGS 	+= -DENABLE_8367R_VB_SWITCH 
else
OBJS	+= ../common/rtl8367_phy_setup.o ../common/smi.o 
endif

SOBJS	= ../common/lowlevel_init.o

$(LIB):	.depend $(OBJS) $(SOBJS)
	$(AR) crv $@ $(OBJS) $(SOBJS)

#########################################################################

.depend:	Makefile $(SOBJS:.o=.S) $(OBJS:.o=.c)
		$(CC) -M $(CFLAGS) $(SOBJS:.o=.S) $(OBJS:.o=.c) > $@

sinclude .depend

#########################################################################
