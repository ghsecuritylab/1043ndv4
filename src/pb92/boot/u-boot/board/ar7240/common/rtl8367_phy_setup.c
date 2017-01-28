/******************************************************************************
*
* Copyright (c) 2010 TP-LINK Technologies CO.,LTD.
* All rights reserved.
*
* FILE NAME  :   rtl8367_phy_setup.c
* VERSION    :   1.0
* DESCRIPTION:   The interface to setup the phy of rtl8367..
*
* AUTHOR     :   zhaolong <zhaolong@tp-link.net>
* CREATE DATE:   09/15/2010
*
* HISTORY    :
* 01   09/15/2010  zhaolong     Create.
*
******************************************************************************/
#include <common.h>
#include <linux/string.h>
#include "rtl8367_phy_setup.h"
#include "smi.h"


ret_t rtl8370_setAsicRegBit(uint32 reg, uint32 bit, uint32 value)
{
    uint32 regData;
    ret_t retVal;
    
    if(bit>=RTL8370_REGBITLENGTH)
        return RT_ERR_INPUT;

    retVal = smi_read(reg, &regData);
    if(retVal != RT_ERR_OK)
    {
		printf("rtl8370_setAsicRegBit: error occured when call smi_read()\n");
		return RT_ERR_SMI;
    }
	
    if (value) 
        regData = regData | (1<<bit);
    else
        regData = regData & (~(1<<bit));
    
    retVal = smi_write(reg, regData);
    if (retVal != RT_ERR_OK)
    {
		printf("rtl8370_setAsicRegBit: error occured when call smi_write()\n");
		return RT_ERR_SMI;
    }
  
    return RT_ERR_OK;
}

ret_t rtl8370_getAsicRegBit(uint32 reg, uint32 bit, uint32 *value)
{
    uint32 regData;
    ret_t retVal;

    retVal = smi_read(reg, &regData);
    if (retVal != RT_ERR_OK)
    {
		printf("rtl8370_getAsicRegBit: error occured when call smi_read()\n");
		return RT_ERR_SMI;
    }
    
    *value = (regData & (0x1 << bit)) >> bit;    

    return RT_ERR_OK;
}


/*
@func ret_t | rtl8370_setAsicRegBits | Set bits value of a specified register.
@parm uint32 | reg | Register's address.
@parm uint32 | bits | Bits mask for setting. 
@parm uint32 | value | Bits value for setting. Value of bits will be set with mapping mask bit is 1.   
@rvalue RT_ERR_OK | Success.
@rvalue RT_ERR_SMI | SMI access error.
@rvalue RT_ERR_INPUT | Invalid input parameter. 
@comm
    Set bits of a specified register to value. Both bits and value are be treated as bit-mask.
    
*/
ret_t rtl8370_setAsicRegBits(uint32 reg, uint32 bits, uint32 value)
{
    uint32 regData;    
    ret_t retVal;    
    uint32 bitsShift;    
    uint32 valueShifted;        

    if(bits>= (1<<RTL8370_REGBITLENGTH) )
        return RT_ERR_INPUT;

    bitsShift = 0;
    while(!(bits & (1 << bitsShift)))
    {
        bitsShift++;
        if(bitsShift >= RTL8370_REGBITLENGTH)
            return RT_ERR_INPUT;
    }
    valueShifted = value << bitsShift;

    if(valueShifted > RTL8370_REGDATAMAX)
        return RT_ERR_INPUT;

    retVal = smi_read(reg, &regData);
    if (retVal != RT_ERR_OK)
    {
		printf("rtl8370_setAsicRegBits: error occured when call smi_read()\n");
		return RT_ERR_SMI;
    }

    regData = regData & (~bits);
    regData = regData | (valueShifted & bits);

    retVal = smi_write(reg, regData);
    if (retVal != RT_ERR_OK)
    {
		printf("rtl8370_setAsicRegBits: error occured when call smi_write()\n");
		return RT_ERR_SMI;
    }

    return RT_ERR_OK;
}

ret_t rtl8370_getAsicRegBits(uint32 reg, uint32 bits, uint32 *value)
{
    uint32 regData;    
    ret_t retVal;    
    uint32 bitsShift;    

    if(bits>= (1<<RTL8370_REGBITLENGTH) )
        return RT_ERR_INPUT;    

    bitsShift = 0;
    while(!(bits & (1 << bitsShift)))
    {
        bitsShift++;
        if(bitsShift >= RTL8370_REGBITLENGTH)
            return RT_ERR_INPUT;
    }
    
    retVal = smi_read(reg, &regData);
    if (retVal != RT_ERR_OK) 
    {
		printf("rtl8370_getAsicRegBits: error occured when call smi_read()\n");
		return RT_ERR_SMI;
    }

    *value = (regData & bits) >> bitsShift;

    return RT_ERR_OK;
}

/*
@func ret_t | rtl8370_setAsicReg | Set content of asic register.
@parm uint32 | reg | Register's address.
@parm uint32 | value | Value setting to register.
@rvalue RT_ERR_OK | Success.
@rvalue RT_ERR_SMI | SMI access error.
@comm
    The value will be set to ASIC mapping address only and it is always return RT_ERR_OK while setting un-mapping address registers.
    
*/
ret_t rtl8370_setAsicReg(uint32 reg, uint32 value)
{
    ret_t retVal;

    retVal = smi_write(reg, value);
    if (retVal != RT_ERR_OK) 
    {
		printf("rtl8370_setAsicReg: error occured when call smi_write()\n");
		return RT_ERR_SMI;
    }

    return RT_ERR_OK;
}


/*
@func ret_t | rtl8370_getAsicReg | Get content of register.
@parm uint32 | reg | Register's address.
@parm uint32* | value | Value of register.
@rvalue RT_ERR_OK | Success.
@rvalue RT_ERR_SMI | SMI access error.
@comm
     Value 0x0000 will be returned for ASIC un-mapping address.
    
*/
ret_t rtl8370_getAsicReg(uint32 reg, uint32 *value)
{
    uint32 regData;
    ret_t retVal;

    retVal = smi_read(reg, &regData);
    if (retVal != RT_ERR_OK)
    {
		printf("rtl8370_getAsicReg: error occured when call smi_read()\n");
		return RT_ERR_SMI;
    }

    *value = regData;

    return RT_ERR_OK;
}


/*
@func ret_t | rtl8370_setAsicPHYReg | Set PHY registers .
@parm uint32 | phyNo | PHY number (0~7).
@parm uint32 | phyAddr | PHY address (0~31).
@parm uint32 | data | Writing data.
@rvalue RT_ERR_OK | 
@rvalue RT_ERR_FAILED | invalid parameter
@rvalue RT_ERR_PHY_REG_ID | invalid PHY address
@rvalue RT_ERR_PORT_ID | invalid port id.
@rvalue RT_ERR_BUSYWAIT_TIMEOUT | PHY access busy
@comm
    The API can set internal PHY register 0~31. There are 8 internal PHYs in switch and each PHY can be
    accessed by software.
 */
ret_t rtl8370_setAsicPHYReg( uint32 phyNo, uint32 phyAddr, uint32 data )
{
    ret_t retVal;
    uint32 regData;
    uint32 busyFlag;

    if(phyNo > RTL8370_PHY_INTERNALNOMAX)
        return RT_ERR_PORT_ID;


    if(phyAddr > RTL8370_PHY_REGNOMAX)
        return RT_ERR_PHY_REG_ID;

/*
word address    a[15]    a[14]    a[13]    a[12]    a[11]    a[10]    a[9]    a[8]    a[7]    a[6]    a[5]    a[4]    a[3]    a[2]    a[1]    a[0]
phy0 ~ phy7     [        3'd1         ]    [ 0        0        0        0      0 ]    [      PHY No.     ]    [        reg adr[4:0]              ]
*/

    /*Check internal phy access busy or not*/
    retVal = rtl8370_getAsicRegBit(RTL8370_REG_INDRECT_ACCESS_STATUS, RTL8370_PHY_BUSY_OFFSET,&busyFlag);
    if(retVal !=  RT_ERR_OK)
        return retVal;

    if(busyFlag)
        return RT_ERR_BUSYWAIT_TIMEOUT;

    /*prepare access data*/
    retVal = rtl8370_setAsicReg(RTL8370_REG_INDRECT_ACCESS_WRITE_DATA, data);
    if(retVal !=  RT_ERR_OK)
        return retVal;
    
    /*prepare access address*/
    regData = RTL8370_PHY_BASE | (phyNo<<RTL8370_PHY_OFFSET) | phyAddr; 
	
    retVal = rtl8370_setAsicReg(RTL8370_REG_INDRECT_ACCESS_ADDRESS, regData);
    if(retVal !=  RT_ERR_OK)
        return retVal;

    /*Set WRITE Command*/
    return rtl8370_setAsicReg(RTL8370_REG_INDRECT_ACCESS_CRTL, RTL8370_CMD_MASK | RTL8370_RW_MASK);
}

/*
@func ret_t | rtl8370_getAsicPHYReg | Set PHY registers .
@parm uint32 | phyNo | PHY number (0~7).
@parm uint32 | phyAddr | PHY address (0~31).
@parm uint32* | data | Read data.
@rvalue RT_ERR_OK | 
@rvalue RT_ERR_FAILED | invalid parameter
@rvalue RT_ERR_PHY_REG_ID | invalid PHY address
@rvalue RT_ERR_PORT_ID | iinvalid port id
@rvalue RT_ERR_BUSYWAIT_TIMEOUT | PHY access busy
@comm
     The API can get internal PHY register 0~31. There are 8 internal PHYs in switch and each PHY can be
    accessed by software.
 */
ret_t rtl8370_getAsicPHYReg( uint32 phyNo, uint32 phyAddr, uint32 *data )
{
    ret_t retVal;
    uint32 regData;
    uint32 busyFlag,checkCounter;

    if(phyNo > RTL8370_PHY_INTERNALNOMAX)
        return RT_ERR_PORT_ID;

    if(phyAddr > RTL8370_PHY_REGNOMAX)
        return RT_ERR_PHY_REG_ID;

    /*Check internal phy access busy or not*/
    retVal = rtl8370_getAsicRegBit(RTL8370_REG_INDRECT_ACCESS_STATUS, RTL8370_PHY_BUSY_OFFSET,&busyFlag);
    if(retVal !=  RT_ERR_OK)
        return retVal;

    if(busyFlag)
        return RT_ERR_BUSYWAIT_TIMEOUT;

    /*prepare access address*/
    regData = RTL8370_PHY_BASE | (phyNo<<RTL8370_PHY_OFFSET) | phyAddr; 
    
    retVal = rtl8370_setAsicReg(RTL8370_REG_INDRECT_ACCESS_ADDRESS, regData);
    if(retVal !=  RT_ERR_OK)
        return retVal;

    /*Set READ Command*/
    retVal = rtl8370_setAsicReg(RTL8370_REG_INDRECT_ACCESS_CRTL, RTL8370_CMD_MASK );
    if(retVal !=  RT_ERR_OK)
        return retVal;

    checkCounter = 5;
    while(checkCounter)
    {
        retVal = rtl8370_getAsicRegBit(RTL8370_REG_INDRECT_ACCESS_STATUS, RTL8370_PHY_BUSY_OFFSET,&busyFlag);
        if(retVal !=  RT_ERR_OK)
        {
            checkCounter --;
            if(0 == checkCounter)
                return retVal;
        }
        else
        {
            checkCounter = 0;
        }        
    }

    /*get PHY register*/
    retVal = rtl8370_getAsicReg(RTL8370_REG_INDRECT_ACCESS_READ_DATA, &regData);
    if(retVal !=  RT_ERR_OK)
        return retVal;

    *data = regData;

    return RT_ERR_OK;
}


static rtk_api_ret_t _rtk_switch_init2(void)
{
    rtk_api_ret_t retVal;
    uint32 index,regData;

	uint32 busyFlag,cnt;

    CONST_T uint16 chipData0[][2] ={{0x1b24,0x0000},{0x1b25,0x0000},{0x1b26,0x0000},{0x1b27,0x0000},
                                     {0x133f,0x0030},{0x133e,0x000e},{0x221f,0x0007},{0x221e,0x0048},
                                     {0x2219,0x4012},{0x221f,0x0003},{0x2201,0x3554},{0x2202,0x63e8},
                                     {0x2203,0x99c2},{0x2204,0x0113},{0x2205,0x303e},{0x220d,0x0207},
                                     {0x220e,0xe100},{0x221f,0x0007},{0x221e,0x0040},{0x2218,0x0000},
                                     {0x221f,0x0007},{0x221e,0x002c},{0x2218,0x008b},{0x221f,0x0005},
                                     {0x2205,0xfff6},{0x2206,0x0080},{0x221f,0x0005},{0x2205,0x8000},
                                     {0x2206,0x0280},{0x2206,0x2bf7},{0x2206,0x00e0},{0x2206,0xfff7},
                                     {0x2206,0xa080},{0x2206,0x02ae},{0x2206,0xf602},{0x2206,0x804e},
                                     {0x2206,0x0201},{0x2206,0x5002},{0x2206,0x0163},{0x2206,0x0201},
                                     {0x2206,0x79e0},{0x2206,0x8b8c},{0x2206,0xe18b},{0x2206,0x8d1e},
                                     {0x2206,0x01e1},{0x2206,0x8b8e},{0x2206,0x1e01},{0x2206,0xa000},
                                     {0x2206,0xe4ae},{0x2206,0xd8bf},{0x2206,0x8b88},{0x2206,0xec00},
                                     {0x2206,0x19a9},{0x2206,0x8b90},{0x2206,0xf9ee},{0x2206,0xfff6},
                                     {0x2206,0x00ee},{0x2206,0xfff7},{0x2206,0xfce0},{0x2206,0xe140},
                                     {0x2206,0xe1e1},{0x2206,0x41f7},{0x2206,0x2ff6},{0x2206,0x28e4},
                                     {0x2206,0xe140},{0x2206,0xe5e1},{0x2206,0x4104},{0x2206,0xf8fa},
                                     {0x2206,0xef69},{0x2206,0xe08b},{0x2206,0x86ac},{0x2206,0x201a},
                                     {0x2206,0xbf80},{0x2206,0x77d0},{0x2206,0x6c02},{0x2206,0x2978},
                                     {0x2206,0xe0e0},{0x2206,0xe4e1},{0x2206,0xe0e5},{0x2206,0x5806},
                                     {0x2206,0x68c0},{0x2206,0xd1d2},{0x2206,0xe4e0},{0x2206,0xe4e5},
                                     {0x2206,0xe0e5},{0x2206,0xef96},{0x2206,0xfefc},{0x2206,0x0425},
                                     {0x2206,0x0807},{0x2206,0x2640},{0x2206,0x7227},{0x2206,0x267e},
                                     {0x2206,0x2804},{0x2206,0xb729},{0x2206,0x2576},{0x2206,0x2a68},
                                     {0x2206,0xe52b},{0x2206,0xad00},{0x2206,0x2cdb},{0x2206,0xf02d},
                                     {0x2206,0x67bb},{0x2206,0x2e7b},{0x2206,0x0f2f},{0x2206,0x7365},
                                     {0x2206,0x31ac},{0x2206,0xcc32},{0x2206,0x2300},{0x2206,0x332d},
                                     {0x2206,0x1734},{0x2206,0x7f52},{0x2206,0x3510},{0x2206,0x0036},
                                     {0x2206,0x0600},{0x2206,0x370c},{0x2206,0xc038},{0x2206,0x7fce},
                                     {0x2206,0x3ce5},{0x2206,0xf73d},{0x2206,0x3da4},{0x2206,0x6530},
                                     {0x2206,0x3e67},{0x2206,0x0053},{0x2206,0x69d2},{0x2206,0x0f6a},
                                     {0x2206,0x012c},{0x2206,0x6c2b},{0x2206,0x136e},{0x2206,0xe100},
                                     {0x2206,0x6f12},{0x2206,0xf771},{0x2206,0x006b},{0x2206,0x7306},
                                     {0x2206,0xeb74},{0x2206,0x94c7},{0x2206,0x7698},{0x2206,0x0a77},
                                     {0x2206,0x5000},{0x2206,0x788a},{0x2206,0x1579},{0x2206,0x7f6f},
                                     {0x2206,0x7a06},{0x2206,0xa600},{0x2201,0x0701},{0x2200,0x0405},
                                     {0x221f,0x0000},{0x2200,0x1340},{0x221f,0x0000},{0x133f,0x0010},
                                     {0x133e,0x0ffe},{0x1203,0xff00},{0x1200,0x7fc4},{0x121d,0x7D16},
                                     {0x121e,0x03e8},{0x121f,0x024e},{0x1220,0x0230},{0x1221,0x0244},
                                     {0x1222,0x0226},{0x1223,0x024e},{0x1224,0x0230},{0x1225,0x0244},
                                     {0x1226,0x0226},{0x1227,0x00c0},{0x1228,0x00b4},{0x122f,0x00c0},
                                     {0x1230,0x00b4},{0x0208,0x03e8},{0x0209,0x03e8},{0x020a,0x03e8},
                                     {0x020b,0x03e8},{0x020c,0x03e8},{0x020d,0x03e8},{0x020e,0x03e8},
                                     {0x020f,0x03e8},{0x0210,0x03e8},{0x0211,0x03e8},{0x0212,0x03e8},
                                     {0x0213,0x03e8},{0x0214,0x03e8},{0x0215,0x03e8},{0x0216,0x03e8},
                                     {0x0217,0x03e8},{0x0900,0x0000},{0x0901,0x0000},{0x0902,0x0000},
                                     {0x0903,0x0000},{0x0865,0x3210},{0x087b,0x0000},{0x087c,0xff00},
                                     {0x087d,0x0000},{0x087e,0x0000},{0x0801,0x0100},{0x0802,0x0100},
                                     {0x0A20,0x2040},{0x0A21,0x2040},{0x0A22,0x2040},{0x0A23,0x2040},
                                     {0x0A24,0x2040},{0x0A28,0x2040},{0x0A29,0x2040},{0x20A0,0x1940},
                                     {0x20C0,0x1940},{0x20E0,0x1940},{0x130c,0x0050},{0xFFFF,0xABCD}};


    CONST_T uint16 chipData1[][2] ={{0x1b24,0x0000},{0x1b25,0x0000},{0x1b26,0x0000},{0x1b27,0x0000},
                                     {0x133f,0x0030},{0x133e,0x000e},{0x221f,0x0007},{0x221e,0x0048},
                                     {0x2219,0x4012},{0x221f,0x0003},{0x2201,0x3554},{0x2202,0x63e8},
                                     {0x2203,0x99c2},{0x2204,0x0113},{0x2205,0x303e},{0x220d,0x0207},
                                     {0x220e,0xe100},{0x221f,0x0007},{0x221e,0x0040},{0x2218,0x0000},
                                     {0x221f,0x0007},{0x221e,0x002c},{0x2218,0x008b},{0x221f,0x0005},
                                     {0x2205,0xfff6},{0x2206,0x0080},{0x221f,0x0005},{0x2205,0x8000},
                                     {0x2206,0x0280},{0x2206,0x2bf7},{0x2206,0x00e0},{0x2206,0xfff7},
                                     {0x2206,0xa080},{0x2206,0x02ae},{0x2206,0xf602},{0x2206,0x804e},
                                     {0x2206,0x0201},{0x2206,0x5002},{0x2206,0x0163},{0x2206,0x0201},
                                     {0x2206,0x79e0},{0x2206,0x8b8c},{0x2206,0xe18b},{0x2206,0x8d1e},
                                     {0x2206,0x01e1},{0x2206,0x8b8e},{0x2206,0x1e01},{0x2206,0xa000},
                                     {0x2206,0xe4ae},{0x2206,0xd8bf},{0x2206,0x8b88},{0x2206,0xec00},
                                     {0x2206,0x19a9},{0x2206,0x8b90},{0x2206,0xf9ee},{0x2206,0xfff6},
                                     {0x2206,0x00ee},{0x2206,0xfff7},{0x2206,0xfce0},{0x2206,0xe140},
                                     {0x2206,0xe1e1},{0x2206,0x41f7},{0x2206,0x2ff6},{0x2206,0x28e4},
                                     {0x2206,0xe140},{0x2206,0xe5e1},{0x2206,0x4104},{0x2206,0xf8fa},
                                     {0x2206,0xef69},{0x2206,0xe08b},{0x2206,0x86ac},{0x2206,0x201a},
                                     {0x2206,0xbf80},{0x2206,0x77d0},{0x2206,0x6c02},{0x2206,0x2978},
                                     {0x2206,0xe0e0},{0x2206,0xe4e1},{0x2206,0xe0e5},{0x2206,0x5806},
                                     {0x2206,0x68c0},{0x2206,0xd1d2},{0x2206,0xe4e0},{0x2206,0xe4e5},
                                     {0x2206,0xe0e5},{0x2206,0xef96},{0x2206,0xfefc},{0x2206,0x0425},
                                     {0x2206,0x0807},{0x2206,0x2640},{0x2206,0x7227},{0x2206,0x267e},
                                     {0x2206,0x2804},{0x2206,0xb729},{0x2206,0x2576},{0x2206,0x2a68},
                                     {0x2206,0xe52b},{0x2206,0xad00},{0x2206,0x2cdb},{0x2206,0xf02d},
                                     {0x2206,0x67bb},{0x2206,0x2e7b},{0x2206,0x0f2f},{0x2206,0x7365},
                                     {0x2206,0x31ac},{0x2206,0xcc32},{0x2206,0x2300},{0x2206,0x332d},
                                     {0x2206,0x1734},{0x2206,0x7f52},{0x2206,0x3510},{0x2206,0x0036},
                                     {0x2206,0x0600},{0x2206,0x370c},{0x2206,0xc038},{0x2206,0x7fce},
                                     {0x2206,0x3ce5},{0x2206,0xf73d},{0x2206,0x3da4},{0x2206,0x6530},
                                     {0x2206,0x3e67},{0x2206,0x0053},{0x2206,0x69d2},{0x2206,0x0f6a},
                                     {0x2206,0x012c},{0x2206,0x6c2b},{0x2206,0x136e},{0x2206,0xe100},
                                     {0x2206,0x6f12},{0x2206,0xf771},{0x2206,0x006b},{0x2206,0x7306},
                                     {0x2206,0xeb74},{0x2206,0x94c7},{0x2206,0x7698},{0x2206,0x0a77},
                                     {0x2206,0x5000},{0x2206,0x788a},{0x2206,0x1579},{0x2206,0x7f6f},
                                     {0x2206,0x7a06},{0x2206,0xa600},{0x2201,0x0701},{0x2200,0x0405},
                                     {0x221f,0x0000},{0x2200,0x1340},{0x221f,0x0000},{0x133f,0x0010},
                                     {0x133e,0x0ffe},{0x1203,0xff00},{0x1200,0x7fc4},{0x0900,0x0000},
                                     {0x0901,0x0000},{0x0902,0x0000},{0x0903,0x0000},{0x0865,0x3210},
                                     {0x087b,0x0000},{0x087c,0xff00},{0x087d,0x0000},{0x087e,0x0000},
                                     {0x0801,0x0100},{0x0802,0x0100},{0x0A20,0x2040},{0x0A21,0x2040},
                                     {0x0A22,0x2040},{0x0A23,0x2040},{0x0A24,0x2040},{0x0A25,0x2040},
                                     {0x0A26,0x2040},{0x0A27,0x2040},{0x0A28,0x2040},{0x0A29,0x2040},
                                     {0x130c,0x0050},{0xFFFF,0xABCD}};


    if ((retVal = rtl8370_setAsicReg(0x13C2,0x0249))!=RT_ERR_OK)
        return retVal;

    if ((retVal = rtl8370_getAsicRegBits(0x1302, 0x7,&regData))!=RT_ERR_OK)
        return retVal;   

    index = 0;
    switch(regData)
    {
        
        case 0x0000:
            while (chipData0[index][0] != 0xFFFF && chipData0[index][1] != 0xABCD)
            {    
                if ((chipData0[index][0]&0xF000)==0x2000)
                {
                    cnt = 0;
                    busyFlag = 1;
                    while (busyFlag&&cnt<5)
                    {
                        cnt++;
                        if ((retVal = rtl8370_getAsicRegBit(RTK_INDRECT_ACCESS_STATUS, RTK_PHY_BUSY_OFFSET,&busyFlag)) !=  RT_ERR_OK)
                            return retVal;
                    }
                    if (5 == cnt)
                        return RT_ERR_BUSYWAIT_TIMEOUT;
        
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_WRITE_DATA, 0)) !=  RT_ERR_OK)
                        return retVal;
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_ADDRESS, PHY_PAGE_ADDRESS)) !=  RT_ERR_OK)
                        return retVal;    
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_CRTL, RTK_CMD_MASK | RTK_RW_MASK)) !=  RT_ERR_OK)
                        return retVal; 
        
                    cnt = 0;
                    busyFlag = 1;
                    while (busyFlag&&cnt<5)
                    {
                        cnt++;
                        if ((retVal = rtl8370_getAsicRegBit(RTK_INDRECT_ACCESS_STATUS, RTK_PHY_BUSY_OFFSET,&busyFlag)) !=  RT_ERR_OK)
                            return retVal;
                    }
                    if (5 == cnt)
                        return RT_ERR_BUSYWAIT_TIMEOUT;
                    
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_WRITE_DATA, (uint32)chipData0[index][1])) !=  RT_ERR_OK)
                        return retVal;
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_ADDRESS, (uint32)chipData0[index][0])) !=  RT_ERR_OK)
                        return retVal;    
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_CRTL, RTK_CMD_MASK | RTK_RW_MASK)) !=  RT_ERR_OK)
                        return retVal; 
                }
                else
                {
                    if (RT_ERR_OK != rtl8370_setAsicReg((uint32)chipData0[index][0],(uint32)chipData0[index][1]))
                        return RT_ERR_FAILED;
                }
                index ++;    
            } 
            break;
        case 0x0001:    
            while (chipData1[index][0] != 0xFFFF && chipData1[index][1] != 0xABCD)
            {    
                if ((chipData1[index][0]&0xF000)==0x2000)
                {
                    cnt = 0;
                    busyFlag = 1;
                    while (busyFlag&&cnt<5)
                    {
                        cnt++;
                        if ((retVal = rtl8370_getAsicRegBit(RTK_INDRECT_ACCESS_STATUS, RTK_PHY_BUSY_OFFSET,&busyFlag)) !=  RT_ERR_OK)
                            return retVal;
                    }
                    if (5 == cnt)
                        return RT_ERR_BUSYWAIT_TIMEOUT;
      
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_WRITE_DATA, 0)) !=  RT_ERR_OK)
                        return retVal;
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_ADDRESS, PHY_PAGE_ADDRESS)) !=  RT_ERR_OK)
                        return retVal;    
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_CRTL, RTK_CMD_MASK | RTK_RW_MASK)) !=  RT_ERR_OK)
                        return retVal; 
        
                    cnt = 0;
                    busyFlag = 1;
                    while (busyFlag&&cnt<5)
                    {
                        cnt++;
                        if ((retVal = rtl8370_getAsicRegBit(RTK_INDRECT_ACCESS_STATUS, RTK_PHY_BUSY_OFFSET,&busyFlag)) !=  RT_ERR_OK)
                            return retVal;
                    }
                    if (5 == cnt)
                        return RT_ERR_BUSYWAIT_TIMEOUT;
        
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_WRITE_DATA, (uint32)chipData1[index][1])) !=  RT_ERR_OK)
                        return retVal;
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_ADDRESS, (uint32)chipData1[index][0])) !=  RT_ERR_OK)
                        return retVal;    
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_CRTL, RTK_CMD_MASK | RTK_RW_MASK)) !=  RT_ERR_OK)
                        return retVal; 
                }
                else
                {
                    if (RT_ERR_OK != rtl8370_setAsicReg((uint32)chipData1[index][0],(uint32)chipData1[index][1]))
                        return RT_ERR_FAILED;
                } 
                index ++;    
            }            
            break;
        case 0x0002:    
            while (chipData1[index][0] != 0xFFFF && chipData1[index][1] != 0xABCD)
            {    
                if ((chipData1[index][0]&0xF000)==0x2000)
                {
                    cnt = 0;
                    busyFlag = 1;
                    while (busyFlag&&cnt<5)
                    {
                        cnt++;
                        if ((retVal = rtl8370_getAsicRegBit(RTK_INDRECT_ACCESS_STATUS, RTK_PHY_BUSY_OFFSET,&busyFlag)) !=  RT_ERR_OK)
                            return retVal;
                    }
                    if (5 == cnt)
                        return RT_ERR_BUSYWAIT_TIMEOUT;
      
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_WRITE_DATA, 0)) !=  RT_ERR_OK)
                        return retVal;
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_ADDRESS, PHY_PAGE_ADDRESS)) !=  RT_ERR_OK)
                        return retVal;    
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_CRTL, RTK_CMD_MASK | RTK_RW_MASK)) !=  RT_ERR_OK)
                        return retVal; 
        
                    cnt = 0;
                    busyFlag = 1;
                    while (busyFlag&&cnt<5)
                    {
                        cnt++;
                        if ((retVal = rtl8370_getAsicRegBit(RTK_INDRECT_ACCESS_STATUS, RTK_PHY_BUSY_OFFSET,&busyFlag)) !=  RT_ERR_OK)
                            return retVal;
                    }
                    if (5 == cnt)
                        return RT_ERR_BUSYWAIT_TIMEOUT;
        
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_WRITE_DATA, (uint32)chipData1[index][1])) !=  RT_ERR_OK)
                        return retVal;
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_ADDRESS, (uint32)chipData1[index][0])) !=  RT_ERR_OK)
                        return retVal;    
                    if ((retVal = rtl8370_setAsicReg(RTK_INDRECT_ACCESS_CRTL, RTK_CMD_MASK | RTK_RW_MASK)) !=  RT_ERR_OK)
                        return retVal; 
                }
                else
                {
                    if (RT_ERR_OK != rtl8370_setAsicReg((uint32)chipData1[index][0],(uint32)chipData1[index][1]))
                        return RT_ERR_FAILED;
                } 
                index ++;    
            }            
            break;
        default:
            return RT_ERR_FAILED;
    }

    return RT_ERR_OK;
}




/* Function Name:
 *      rtk_switch_init 
 * Description:
 *      Set chip to default configuration enviroment
 * Input:
 *      None
 * Output:
 *      None
 * Return:
 *      RT_ERR_OK              - set shared meter successfully
 *      RT_ERR_FAILED          - FAILED to iset shared meter
 *      RT_ERR_SMI             - SMI access error
 * Note:
 *      The API can set chip registers to default configuration for different release chip model.
 */


rtk_api_ret_t rtk_switch_init(void)
{

    rtk_api_ret_t retVal;
    uint32 regData1,regData2;

    if ((retVal = rtl8370_setAsicReg(0x13C2,0x0249))!=RT_ERR_OK)
        return retVal;

    if ((retVal = rtl8370_getAsicRegBits(0x1301, 0xF000,&regData1))!=RT_ERR_OK)
        return retVal; 

    if ((retVal = rtl8370_setAsicPHYReg(0,31,5))!=RT_ERR_OK)
        return retVal; 
    if ((retVal = rtl8370_setAsicPHYReg(0,5,0x3ffe))!=RT_ERR_OK)
        return retVal; 
    if ((retVal = rtl8370_getAsicPHYReg(0,6,&regData2))!=RT_ERR_OK)
        return retVal; 

    if (0x2104 == regData2)
    {
		//printf("Here we will call rtk_switch_init2() !!!\n");
        if ((retVal = _rtk_switch_init2()) != RT_ERR_OK)
            return retVal;
    }
	
/* Modified by zhl, 08Sep10. Here we don't need to config the LEDs. */	
#if 1
    /*Enable System Based LED*/
    if ((retVal = rtl8370_setAsicRegBit(RTL8370_REG_LED_SYS_CONFIG, RTL8370_LED_IO_DISABLE_OFFSET, 0))!=RT_ERR_OK)
        return retVal; 
#endif
    
	/* divide LAN/WAN ports in boot. by HouXB, 29Nov11 */
	rtl8370_setAsicPHYReg(0, 0, 0x1940);
    
    return RT_ERR_OK;
}


/*
@func ret_t | rtl8370_setAsicPortExtMode | Set external interface mode configuration.
@parm uint32 | id | external interface id (0~1).
@parm uint32 |mode | external interface mode.
@rvalue RT_ERR_OK | Success.
@rvalue RT_ERR_SMI | SMI access error.
@rvalue RT_ERR_FAILED | Invalid parameter.
@comm
  This API can set external interface mode properties. 
    DISABLE,
    RGMII,
    MII_MAC,
    MII_PHY, 
    TMII_MAC,
    TMII_PHY, 
    GMII,
    RGMII_33V,    
 */
ret_t rtl8370_setAsicPortExtMode(uint32 id, uint32 mode)
{
    ret_t retVal;
    
    if(id >= RTL8370_EXTNO)
        return RT_ERR_INPUT;	

    if(mode > EXT_RGMII_33V)
        return RT_ERR_INPUT;	

    if( mode == EXT_RGMII_33V || mode == EXT_RGMII )
    {
        if((retVal= rtl8370_setAsicReg(RTL8370_REG_CHIP_DEBUG0,0x0367)) !=  RT_ERR_OK)
            return retVal;
        if((retVal= rtl8370_setAsicReg(RTL8370_REG_CHIP_DEBUG1,0x7777)) !=  RT_ERR_OK)
            return retVal;
    }
    else if((mode == EXT_TMII_MAC)||(mode == EXT_TMII_PHY))
    {
        if((retVal= rtl8370_setAsicRegBit(RTL8370_REG_BYPASS_LINE_RATE,(id+1)%2,1)) !=  RT_ERR_OK)
            return retVal;
    } 
    else if( mode == EXT_GMII )
    {
        if((retVal= rtl8370_setAsicRegBit(RTL8370_REG_CHIP_DEBUG0,RTL8370_CHIP_DEBUG0_DUMMY_0_OFFSET+id,1)) !=  RT_ERR_OK)
            return retVal;
        if((retVal= rtl8370_setAsicRegBit(RTL8370_REG_EXT0_RGMXF+id,6,1)) !=  RT_ERR_OK)
            return retVal;        
    } 
    else 
    {
        if((retVal= rtl8370_setAsicRegBit(RTL8370_REG_BYPASS_LINE_RATE,(id+1)%2,0)) !=  RT_ERR_OK)
            return retVal;
        if((retVal= rtl8370_setAsicRegBit(RTL8370_REG_EXT0_RGMXF+id,6,0)) !=  RT_ERR_OK)
            return retVal;     
    }      

    return rtl8370_setAsicRegBits(RTL8370_REG_DIGITIAL_INTERFACE_SELECT, RTL8370_SELECT_RGMII_0_MASK<<(id*RTL8370_SELECT_RGMII_1_OFFSET), mode);
}


/*
@func ret_t | rtl8370_getAsicPortForceLinkExt | Get external interface force linking configuration.
@parm uint32 | id | external interface id (0~1).
@parm rtl8370_port_ability_t* | portability | port ability configuration
@rvalue RT_ERR_OK | Success.
@rvalue RT_ERR_SMI | SMI access error.
@rvalue RT_ERR_FAILED | Invalid parameter.
@comm
      This API can get external interface force mode properties. 
 */
ret_t rtl8370_getAsicPortForceLinkExt(uint32 id, rtl8370_port_ability_t *portability)
{
    ret_t retVal;
    uint32 regData;
    uint16 *accessPtr;
    rtl8370_port_ability_t ability;

    /* Invalid input parameter */
    if(id >= RTL8370_EXTNO)
        return RT_ERR_PORT_ID;
    
    memset(&ability,0x00,sizeof(rtl8370_port_ability_t));


    accessPtr =  (uint16*)&ability;
 
    retVal = rtl8370_getAsicReg(RTL8370_REG_DIGITIAL_INTERFACE0_FORCE + id, &regData);
    if(retVal !=  RT_ERR_OK)
        return retVal;
    
    *accessPtr = regData;

    memcpy(portability, &ability, sizeof(rtl8370_port_ability_t));        
    
    return RT_ERR_OK;  
}


/*
@func ret_t | rtl8370_setAsicPortForceLinkExt | Set external interface force linking configuration.
@parm uint32 | id | external interface id (0~1).
@parm rtl8370_port_ability_t* | portability | port ability configuration
@rvalue RT_ERR_OK | Success.
@rvalue RT_ERR_SMI | SMI access error.
@rvalue RT_ERR_FAILED | Invalid parameter.
@comm
      This API can set external interface force mode properties. 
 */
ret_t rtl8370_setAsicPortForceLinkExt(uint32 id, rtl8370_port_ability_t *portability)
{
    uint32 regData;
    uint16 *accessPtr;
    rtl8370_port_ability_t ability;

    /* Invalid input parameter */
    if(id >=RTL8370_EXTNO)
        return RT_ERR_PORT_ID;
    
    memset(&ability, 0x00, sizeof(rtl8370_port_ability_t));
    memcpy(&ability, portability, sizeof(rtl8370_port_ability_t));    

    accessPtr = (uint16*)&ability;
 
    regData = *accessPtr;

    return rtl8370_setAsicReg(RTL8370_REG_DIGITIAL_INTERFACE0_FORCE + id, regData);
}




/* Function Name:
 *      rtk_port_macForceLinkExt0_set
 * Description:
 *      Set external interface 0 force linking configuration.
 * Input:
 *      mode - external interface mode
 *      pPortability - port ability configuration
 * Output:
 *      None 
 * Return:
 *      RT_ERR_OK              - set shared meter successfully
 *      RT_ERR_FAILED          - FAILED to iset shared meter
 *      RT_ERR_SMI             - SMI access error
 *      RT_ERR_INPUT - Invalid input parameters.
 * Note:
 *      This API can set external interface 0 force mode properties. 
 *      The external interface can be set to:
 *      MODE_EXT_DISABLE,
 *      MODE_EXT_RGMII,
 *      MODE_EXT_MII_MAC,
 *      MODE_EXT_MII_PHY, 
 *      MODE_EXT_TMII_MAC,
 *      MODE_EXT_TMII_PHY, 
 *      MODE_EXT_GMII, 
 *      MODE_EXT_RGMII_33V,
 */
rtk_api_ret_t rtk_port_macForceLinkExt0_set(rtk_mode_ext_t mode, rtk_port_mac_ability_t *pPortability)
{
    rtk_api_ret_t retVal;
    rtl8370_port_ability_t ability;

    if (mode >=MODE_EXT_END)
        return RT_ERR_INPUT;    

    if (pPortability->forcemode>1||pPortability->speed>2||pPortability->duplex>1||
       pPortability->link>1||pPortability->nway>1||pPortability->txpause>1||pPortability->rxpause>1)
        return RT_ERR_INPUT;

    if ((retVal = rtl8370_setAsicPortExtMode(RTK_EXT_0, mode))!=RT_ERR_OK)
        return retVal;

    if ((retVal = rtl8370_getAsicPortForceLinkExt(RTK_EXT_0,&ability))!=RT_ERR_OK)
        return retVal;
     
    ability.forcemode = pPortability->forcemode;
    ability.speed     = pPortability->speed;
    ability.duplex    = pPortability->duplex;
    ability.link      = pPortability->link;
    ability.nway      = pPortability->nway;
    ability.txpause   = pPortability->txpause;
    ability.rxpause   = pPortability->rxpause;

    if ((retVal = rtl8370_setAsicPortForceLinkExt(RTK_EXT_0,&ability))!=RT_ERR_OK)
        return retVal;

    return RT_ERR_OK;
}


/* Function Name:
 *      rtk_port_rgmiiDelayExt0_set
 * Description:
 *      Set RGMII interface 0 delay value for TX and RX.
 * Input:
 *      txDelay - TX delay value, 1 for delay 2ns and 0 for no-delay
 *      rxDelay - RX delay value, 0~7 for delay setup.
 * Output:
 *      None 
 * Return:
 *      RT_ERR_OK              - set shared meter successfully
 *      RT_ERR_FAILED          - FAILED to iset shared meter
 *      RT_ERR_SMI             - SMI access error
 *      RT_ERR_INPUT - Invalid input parameters.
 * Note:
 *      This API can set external interface 0 RGMII delay. 
 *      In TX delay, there are 2 selection: no-delay and 2ns delay.
 *      In RX dekay, there are 8 steps for delay tunning. 0 for n0-delay, and 7 for maximum delay.  
 */
rtk_api_ret_t rtk_port_rgmiiDelayExt0_set(rtk_data_t txDelay, rtk_data_t rxDelay)
{
    rtk_api_ret_t retVal;
    uint32 regData;

    if ((txDelay > 1)||(rxDelay > 7))
        return RT_ERR_INPUT;
    
    if ((retVal = rtl8370_getAsicReg(RTL8370_REG_EXT0_RGMXF, &regData))!=RT_ERR_OK)
        return retVal;

    regData = (regData&0xFFF0) | ((txDelay<<3)&0x0008) | (rxDelay&0x007);

    if ((retVal = rtl8370_setAsicReg(RTL8370_REG_EXT0_RGMXF, regData))!=RT_ERR_OK)
        return retVal;

    return RT_ERR_OK;
}



/******************************************************************************
* FUNCTION      : rtl_phySetup()
* AUTHOR        : zhaolong <zhaolong@tp-link.net>
* DESCRIPTION   : reset and setup the PHY associated with
* 				  the specified MAC unit number 
* INPUT         : ethUnit, the unit number of some MAC.
* OUTPUT        : N/A
* RETURN        : TRUE,		associated PHY is alive; 
* 				  FALSE,	no LINKs on this ethernet unit
* OTHERS        : N/A
******************************************************************************/
BOOL rtl8367_phy_setup(int ethUnit)
{
	int retVal = 0;
/*	uint32 data = 0;	
	int loopCount = 0;*/

	//printf("Here we will setup the rtl8367m!\n");

	/* we init the SMI interface here temporarily, but
	 * we must make sure it was called before any config 
	 * of rtl8367m with SMI interface. */
	smi_init();

	udelay(100*1000);
	
	/* when smi_init, it need a little time to off the switch led.
	   so we turn off the QSS and USB lend after a little delay.
	   by HouXB, 19May11 */
   	toggleGpioLeds(0);

	/* 
	(*((volatile unsigned int*)(0xb8040008))) = 
		*((volatile unsigned int*)(0xb8040008)) | (0x101);
	*/
	
	udelay(900*1000);
	if (SUCCESS != rtk_switch_init())
	{
		printf ("initChip failed\n");
		return FAILED;
	}

/* Modified by zhl, 06Set2010, According to the request of realtek. */
	rtk_port_mac_ability_t ability;

	/*External Interface setup*/
    
	//printf ("Here we will set the RGMII 0 of RTL8367M.\n");
    memset(&ability, 0, sizeof(ability));
    ability.forcemode   = 1;
    ability.duplex          = 1;
    ability.speed           = SPD_1000M;
    ability.link                = 1;
    retVal = rtk_port_macForceLinkExt0_set(MODE_EXT_RGMII, &ability);
	if (SUCCESS != retVal) 
	{
		printf ("RGMII 0 set failed, errno: 0x%08x\n", retVal);
		return FAILED;
	}

   /*RGMII TX/RX delay tunning*/
   /*In TX delay, there are 2 selection: no-delay and 2ns delay.*/
   /*In RX dekay, there are 8 steps for delay tunning. 0 for no-delay,
and 7 for maximum delay. */
   retVal = rtk_port_rgmiiDelayExt0_set(1, 4);
   if (SUCCESS != retVal) 
	{
		printf ("RGMII 0 delay failed, errno: 0x%08x\n", retVal);
		return FAILED;
	}

/* End: Modified by zhl, 06Set2010, According to the request of realtek. */
	return SUCCESS;
		
}


