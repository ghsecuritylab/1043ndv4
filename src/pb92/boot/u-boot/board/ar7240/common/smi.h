
#ifndef __SMI_H__
#define __SMI_H__


void smi_init(void);
int smi_read(uint32 mAddrs, uint32 *rData);
int smi_write(uint32 mAddrs, uint32 rData);


#endif /* __SMI_H__ */


