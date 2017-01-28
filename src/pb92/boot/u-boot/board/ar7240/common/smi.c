/*
* Copyright c                  Realtek Semiconductor Corporation, 2006 
* All rights reserved.
* 
* Program : Control  smi connected RTL8366
* Abstract : 
* Author : Yu-Mei Pan (ympan@realtek.com.cn)                
*  $Id: smi.c,v 1.2 2008-04-10 03:04:19 shiehyy Exp $
* History:
			modified for CPU chip AR7242 by zhl, 24Aug2010.
*/


#include <linux/types.h>
#include <common.h>
#include <asm/addrspace.h>
#include <asm/types.h>
  
#include "ar7240_soc.h"
#include "rtl8367_phy_setup.h"
#include "smi.h"
#ifdef DELAY
#undef DELAY
#endif

#define AR7240_GPIO_FUNCTIONS           AR7240_GPIO_BASE+0x28

#define DELAY                        10000
#define CLK_DURATION(clk)            udelay(3)
#define _SMI_ACK_RESPONSE(ok)		{ /*if (!(ok)) return FAILED; */}

#define smi_SCK		6		/* GPIO used for SMI Clock Generation */			/* Here we should check with the hardware department */
#define smi_SDA		1		/* GPIO used for SMI Data signal */					/* Here we should check with the hardware department */
#define	GPIO_DIR_OUT		0
#define GPIO_DIR_IN			1
#define GPIO_INT_DISABLE	0
#define GPIO_INT_ENABLE		1

#define ack_timer                    5

void ar7240_configGpioPin(int gpio, int dir, int intr)
{
	if (dir == GPIO_DIR_OUT)
		ar7240_reg_rmw_set(AR7240_GPIO_OE, (1 << gpio))
	else
		ar7240_reg_rmw_clear(AR7240_GPIO_OE, (1 << gpio));
	
	if (intr == GPIO_INT_ENABLE)
		ar7240_reg_rmw_set(AR7240_GPIO_INT_MASK, (1 << gpio))
	else
		ar7240_reg_rmw_clear(AR7240_GPIO_INT_MASK, (1 << gpio));
}

void
ar7240_gpio_out_val(int gpio, int val)
{
    if (val & 0x1) {
		ar7240_reg_rmw_set(AR7240_GPIO_OUT, (1 << gpio));
	}
	else {
		ar7240_reg_rmw_clear(AR7240_GPIO_OUT, (1 << gpio));
	}
}

void
ar7240_gpio_in_val(int gpio, uint32_t * u)
{
	*u = 0x1 & (ar7240_reg_rd(AR7240_GPIO_IN) >> gpio);
}



void _smi_start(void)
{

	/* change GPIO pin to Output only */
	ar7240_configGpioPin(smi_SDA, GPIO_DIR_OUT, GPIO_INT_DISABLE);;
	ar7240_configGpioPin(smi_SCK, GPIO_DIR_OUT, GPIO_INT_DISABLE);
	
	/* Initial state: SCK: 0, SDA: 1 */
	ar7240_gpio_out_val(smi_SCK, 0);
	ar7240_gpio_out_val(smi_SDA, 1);
	CLK_DURATION(DELAY);

	/* CLK 1: 0 -> 1, 1 -> 0 */
	ar7240_gpio_out_val(smi_SCK, 1);
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SCK, 0);
	CLK_DURATION(DELAY);

	/* CLK 2: */
	ar7240_gpio_out_val(smi_SCK, 1);
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SDA, 0);
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SCK, 0);
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SDA, 1);

}



void _smi_writeBit(uint16 signal, uint32 bitLen)
{
	for( ; bitLen > 0; bitLen--)
	{
		CLK_DURATION(DELAY);

		/* prepare data */
		if ( signal & (1<<(bitLen-1)) ) 
			ar7240_gpio_out_val(smi_SDA, 1);	
		else 
			ar7240_gpio_out_val(smi_SDA, 0);    
		CLK_DURATION(DELAY);

		/* clocking */
		ar7240_gpio_out_val(smi_SCK, 1);
		CLK_DURATION(DELAY);
		ar7240_gpio_out_val(smi_SCK, 0);
	}
}



void _smi_readBit(uint32 bitLen, uint32 *rData) 
{
	uint32_t u;

	/* change GPIO pin to Input only */
	ar7240_configGpioPin(smi_SDA, GPIO_DIR_IN, GPIO_INT_DISABLE);

	for (*rData = 0; bitLen > 0; bitLen--)
	{
		CLK_DURATION(DELAY);

		/* clocking */
		ar7240_gpio_out_val(smi_SCK, 1);
		CLK_DURATION(DELAY);
		ar7240_gpio_in_val(smi_SDA, &u);
		ar7240_gpio_out_val(smi_SCK, 0);

		*rData |= (u << (bitLen - 1));
	}

	/* change GPIO pin to Output only */
	ar7240_configGpioPin(smi_SDA, GPIO_DIR_OUT, GPIO_INT_DISABLE);;
}



void _smi_stop(void)
{

	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SDA, 0);    
	ar7240_gpio_out_val(smi_SCK, 1);    
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SDA, 1);    
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SCK, 1);
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SCK, 0);
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SCK, 1);

	/* add a click */
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SCK, 0);
	CLK_DURATION(DELAY);
	ar7240_gpio_out_val(smi_SCK, 1);


	/* change GPIO pin to Output only */
	ar7240_configGpioPin(smi_SDA, GPIO_DIR_IN, GPIO_INT_DISABLE);
	ar7240_configGpioPin(smi_SCK, GPIO_DIR_IN, GPIO_INT_DISABLE);


}


void smi_init(void)
{
	/* If we use GPIO[6] as SCK, then we must set it work at GPIO mode */
	ar7240_reg_rmw_set(AR7240_GPIO_FUNCTIONS, 1);

	/* Here we must set the bit[19:18] to 0x3 according to the datasheet. */
	ar7240_reg_rmw_set(AR7240_GPIO_OE, (0x3 << 18));
	
	/* change GPIO pin to Input only */
	/* Initialize GPIO port C, pin 0 as SMI SDA0 */
	ar7240_configGpioPin(smi_SDA, GPIO_DIR_OUT, GPIO_INT_DISABLE);


	/* Initialize GPIO port C, pin 1 as SMI SCK0 */
	ar7240_configGpioPin(smi_SCK, GPIO_DIR_OUT, GPIO_INT_DISABLE);

	ar7240_gpio_out_val(smi_SDA, 1);	
	ar7240_gpio_out_val(smi_SCK, 1);	
}




int32 smi_read(uint32 mAddrs, uint32 *rData)
{
	uint32_t rawData=0, ACK;
	uint8_t  con;
	uint32_t ret = 0;

	_smi_start();                                /* Start SMI */

	_smi_writeBit(0x0b, 4); 			/* CTRL code: 4'b1010 */

	_smi_writeBit(0x4, 3);						/* CTRL code: 3'b100 */

	_smi_writeBit(0x1, 1);						/* 1: issue READ command */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);					/* ACK for issuing READ command*/
	} while ((ACK != 0) && (con < ack_timer));

	if (ACK != 0) ret = 1;

	_smi_writeBit((mAddrs&0xff), 8);			 /* Set reg_addr[7:0] */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);					/* ACK for setting reg_addr[7:0] */	
	} while ((ACK != 0) && (con < ack_timer));

	if (ACK != 0) ret = 1;

	_smi_writeBit((mAddrs>>8), 8);				 /* Set reg_addr[15:8] */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);					/* ACK by RTL8369 */
	} while ((ACK != 0) && (con < ack_timer));
	if (ACK != 0) ret = 1;

	_smi_readBit(8, &rawData);					/* Read DATA [7:0] */
	*rData = rawData&0xff; 

	_smi_writeBit(0x00, 1);						/* ACK by CPU */

	_smi_readBit(8, &rawData);					/* Read DATA [15: 8] */
	_smi_writeBit(0x01, 1);						/* ACK by CPU */
	*rData |= ((rawData & 0xff)<<8);

	_smi_stop();

	return ret;
}



int32 smi_write(uint32 mAddrs, uint32 rData)
{
	char con;
	uint32_t ACK;
	uint32_t ret = 0;
/*	int flags;	*/

	_smi_start();								/* Start SMI */

	_smi_writeBit(0x0b, 4); 					/* CTRL code: 4'b1010 */

	_smi_writeBit(0x4, 3);						/* CTRL code: 3'b100 */

	_smi_writeBit(0x0, 1);						/* 0: issue WRITE command */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);					/* ACK for issuing WRITE command*/
	} while ((ACK != 0) && (con < ack_timer));
	if (ACK != 0) ret = 1;

	_smi_writeBit((mAddrs&0xff), 8);			 /* Set reg_addr[7:0] */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);					/* ACK for setting reg_addr[7:0] */
	} while ((ACK != 0) && (con < ack_timer));
	if (ACK != 0) ret = 1;

	_smi_writeBit((mAddrs>>8), 8);				 /* Set reg_addr[15:8] */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);					/* ACK for setting reg_addr[15:8] */
	} while ((ACK != 0) && (con < ack_timer));
	if (ACK != 0) ret = 1;

	_smi_writeBit(rData&0xff, 8);				/* Write Data [7:0] out */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);					/* ACK for writting data [7:0] */
	} while ((ACK != 0) && (con < ack_timer));
	if (ACK != 0) ret = 1;

	_smi_writeBit(rData>>8, 8);					/* Write Data [15:8] out */

	con = 0;
	do {
		con++;
		_smi_readBit(1, &ACK);						/* ACK for writting data [15:8] */
	} while ((ACK != 0) && (con < ack_timer));
	if (ACK != 0) ret = 1;

	_smi_stop();	

	return ret;
}


