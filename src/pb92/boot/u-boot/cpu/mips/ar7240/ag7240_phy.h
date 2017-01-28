#ifndef _AG7240_PHY_H
#define _AG7240_PHY_H

extern int rtl8367_phy_setup(int ethUnit);

static inline void ag7240_phy_setup(int unit)
{
	if (is_ar7242() && (unit==0)) 
	{
		/* switch setup interface. 
		   if the ENABLE_8367R_VB_SWITCH was defined then use switch rtl8367r_vb
		   else use switch 8367r
		   the macro was defined in u-boot/Makefile.
		   by HouXB, 18Jan12 */
#ifdef ENABLE_8367R_VB_SWITCH
        if (0 != rtl_phySetup())			
#else			
        if (0 != rtl8367_phy_setup(unit))
#endif			
        {
			printf("rtl8367_phy_setup FAILED!!!\n");
        }
		else
		{
			printf("rtl8367_phy_setup SUCCESS!!!\n");
		}
    }
}

static inline void ag7240_phy_link(int unit, u32 *link)
{
	if (is_ar7242() && (unit==0)) 
	{
		*link = 1;
	}
}

static inline void ag7240_phy_duplex(int unit, u32 *duplex)
{
		if (is_ar7242() && (unit==0)) 
		{
			*duplex = 1;
		}

}

static inline void ag7240_phy_speed(int unit, u32 *speed)
{
	if (is_ar7242() && (unit==0)) 
	{
		*speed = 1000;
	}
}

#endif /*_AG7240_PHY_H*/
