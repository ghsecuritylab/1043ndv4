include $(TOPDIR)/config.mk

LIB	= lib$(SOC).a

START	=
#OBJS	= ar7240_serial.o ag7240.o ar7240_flash.o meminit.o

OBJS	= meminit.o 

ifeq ($(BOARD_TYPE), ap121-2MB)
OBJS	+= hornet_serial.o hornet_ag7240.o
else
ifeq ($(BOARD_TYPE), hornet_emu)
OBJS	+= hornet_serial.o hornet_ag7240.o
else
OBJS	+= ar7240_serial.o ag7240.o
endif
endif

SOBJS	=

ifeq ($(ENABLE_8367R_VB_SWITCH),1)
CFLAGS += -DENABLE_8367R_VB_SWITCH
endif

all:	.depend $(START) $(LIB)

$(LIB):	$(OBJS) $(SOBJS) $(OBJS-0)
	$(AR) crv $@ $(OBJS) $(SOBJS)

#########################################################################

.depend:	Makefile $(START:.o=.S) $(OBJS:.o=.c)
		$(CC) -M $(CFLAGS) $(START:.o=.S) $(OBJS:.o=.c) > $@

sinclude .depend

#########################################################################
