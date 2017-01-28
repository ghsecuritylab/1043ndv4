
#ifndef __SMI_H__
#define __SMI_H__


void smi_init(void);
int smi_read(unsigned int mAddrs, unsigned int *rData);
int smi_write(unsigned int mAddrs, unsigned int rData);


#endif /* __SMI_H__ */


