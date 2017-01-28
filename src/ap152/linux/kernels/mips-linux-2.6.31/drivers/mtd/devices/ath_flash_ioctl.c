/********************************************************************
 *This is flash ioctl for  reading ,writing and erasing application
 *******************************************************************/

#include <linux/init.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/module.h>
#include <linux/mtd/mtd.h>
//#include <asm-mips/ioctl.h>
//#include <asm-mips/uaccess.h>
#include <linux/cdev.h>
#include <linux/errno.h>
#include <linux/spinlock_types.h>
#include <asm/system.h>

#include <atheros.h>
#include <ath_spi.h>
//#include "ath_flash.h"
#include <linux/jiffies.h>
#include <linux/timer.h>

/*
 * IOCTL Command Codes
 */
#define ATH_FLASH_READ				0x01
#define ATH_FLASH_WRITE				0x02
#define ATH_FLASH_ERASE				0x03
//#define ATH_FLASH_APP_WRITE	      	0x04
//#define ATH_FLASH_APP_ERASE			0x05


#define ATH_IO_MAGIC 				0xB3
#define	ATH_IO_FLASH_READ			_IOR(ATH_IO_MAGIC, ATH_FLASH_READ, char)
#define ATH_IO_FLASH_WRITE			_IOW(ATH_IO_MAGIC, ATH_FLASH_WRITE, char)
#define	ATH_IO_FLASH_ERASE			_IO (ATH_IO_MAGIC, ATH_FLASH_ERASE)
//#define ATH_IO_APP_WRITE				_IOW(ATH_IO_MAGIC, ATH_FLASH_APP_WRITE, char)
//#define ATH_IO_APP_ERASE				_IO(ATH_IO_MAGIC, ATH_FLASH_APP_ERASE)
#define	ATH_IOC_MAXNR				14
#define flash_major      				239
#define flash_minor      				0
#define TP_LINK_FLASH_SIZE          CONFIG_MTD_ATH_FLASH_SIZE

/**
 * If we need to software control power bit
 * (when upgrade, blink it), we should define
 * this bit here
 */
#if defined(CONFIG_GPIO_POWER_LED_BIT)
#if (CONFIG_GPIO_POWER_LED_BIT >= 0)
#define POWER_LED_GPIO_BIT   (CONFIG_GPIO_POWER_LED_BIT)
#define POWER_LED_GPIO_ON    (CONFIG_GPIO_POWER_LED_ON)
#else
#undef  POWER_LED_GPIO_BIT
#endif
#else
#undef  POWER_LED_GPIO_BIT
#endif
extern void ath_gpio_config_output(int gpio);
extern void ath_gpio_out_val(int gpio, int val);

int ath_flash_erase(struct mtd_info *mtd, struct erase_info *instr);
int ath_flash_read(struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char *buf);
int ath_flash_write(struct mtd_info *mtd, loff_t to, size_t len, size_t *retlen, const u_char *buf);
void ath_spi_sector_erase(uint32_t addr);

int ath_flash_ioctl(struct inode *inode, struct file *file,  unsigned int cmd, unsigned long arg);
int ath_flash_open (struct inode *inode, struct file *file);

struct file_operations flash_device_op = {
        .owner = THIS_MODULE,
        .ioctl = ath_flash_ioctl,
        .open = ath_flash_open,
};

static struct cdev flash_device_cdev = {
		//.kobj   = {.name = "ar7240_flash_chrdev", },
        .owner  = THIS_MODULE,
		.ops = &flash_device_op,
};

typedef struct 
{
	u_int32_t addr;		/* flash r/w addr	*/
	u_int32_t len;		/* r/w length		*/
	u_int8_t* buf;		/* user-space buffer*/
	u_int32_t buflen;	/* buffer length	*/
    u_int32_t reset;    /* reset flag       */
	u_int32_t hasHead;	/* has head or not	*/
}ARG;

//#define ATH_FLASH_IO_BUF_LEN		2048
#define ATH_FLASH_SECTOR_SIZE	(64 * 1024)

#define TRUE 1
#define FALSE 0
#define FLASH_ERASE_SIZE  ATH_FLASH_SECTOR_SIZE

static inline void 
ath_flash_sector_erase(uint32_t addr)
{
    ath_flash_spi_down();
    ath_spi_sector_erase(addr);
    ath_flash_spi_up();
}

int nvram_flash_read(struct mtd_info *mtd, u_int8_t *tempData, 
    u_int32_t hasHead, u_int32_t offset, u_int8_t *data, u_int32_t len)
{
    int i = 0;
    int ret = 0;
    int retlen = 0;
	
    int nSector = len / (ATH_FLASH_SECTOR_SIZE); 	/* Divide ATH_FLASH_SECTOR_SIZE */	
    int oddLen  = len % (ATH_FLASH_SECTOR_SIZE);	/* odd length (0 ~ ATH_FLASH_SECTOR_SIZE) */

    /* copy from flash to kernel buffer */  
    for (i = 0; i < nSector; i++)
    {
        ret = ath_flash_read(mtd, offset, ATH_FLASH_SECTOR_SIZE, &retlen, tempData);
        if ((ret == 0) && (retlen == ATH_FLASH_SECTOR_SIZE))
        {
            /*copy from kernel to user*/
            if (copy_to_user(data, tempData, ATH_FLASH_SECTOR_SIZE))
            {
                printk("read copy_to_user failed\n");
                goto wrong;
            }
        }
        else
        {
            printk("Read failed, ret:%d!\n", ret);
            goto wrong;
        }
        offset += ATH_FLASH_SECTOR_SIZE;
        data += ATH_FLASH_SECTOR_SIZE;
    }
    
    if (oddLen) 
    {
        ret = ath_flash_read(mtd, offset, oddLen, &retlen, tempData);
        if ((ret == 0) && (retlen == oddLen))
        {
            /*copy from kernel to user*/
            if (copy_to_user(data, tempData, oddLen))
            {
                printk("read copy_to_user failed\n");
                goto wrong;
            }
        } 
        else 
        {
            printk("Read failed!\n");
            goto wrong;
        }
    }
    return 0;

wrong:
    return -1;
}

int nvram_flash_write(struct mtd_info *mtd, u_int8_t *tempData, 
    u_int32_t hasHead, u_int32_t offset, u_int8_t *data, u_int32_t len)
{
	u_int32_t address = 0;
	u_int32_t headLen = 0;
	u_int32_t endAddr = 0, startAddr = 0;
	u_int8_t *orignData = NULL;
	u_int32_t headData[2] = {len, 0};
	u_int32_t frontLen = 0, tailLen = 0;
	u_int32_t retLen = 0;
#if defined(POWER_LED_GPIO_BIT)
	int gpio_val = 0x1;
#endif
	int ret = 0;

	headData[0] = htonl(len);	

	if (hasHead != FALSE)
	{
		headLen = 2 * sizeof(u_int32_t);
		len += headLen;
	}

	frontLen = offset % FLASH_ERASE_SIZE;
	tailLen  = (offset + len) % FLASH_ERASE_SIZE;
	/* 第一个block起始地址 */
	address = offset - frontLen;
	/* 最后一个不完整的block起始地址，如果没有，则是再下一个block起始地址 */
	endAddr = offset + len - tailLen;

	orignData = tempData + FLASH_ERASE_SIZE;

	if (frontLen > 0 || headLen > 0)/* 第一个block */
	{
		ret = ath_flash_read(mtd, address, FLASH_ERASE_SIZE, &retLen, orignData);
		if ((ret != 0) || (retLen != FLASH_ERASE_SIZE))
		{
			printk("\Read in write to flash failed status:%d retLen:%d\n", ret, retLen);
			return -1;
		}
		memcpy(tempData, orignData, frontLen);/* 前面一部分为原来的的数据 */
		
		if (FLASH_ERASE_SIZE < frontLen + headLen) /* 头部被拆分到两个blcok */
		{
			headLen = FLASH_ERASE_SIZE - frontLen;
			/* 分区头部，第一部分 */
			memcpy(tempData + frontLen, headData, headLen);

			/***************************************************/
			if (memcmp(orignData, tempData, FLASH_ERASE_SIZE)) /*内容变化*/
			{
				ath_flash_sector_erase(address);
				ret = ath_flash_write(mtd, address, FLASH_ERASE_SIZE, &retLen, tempData);
				if ((ret != 0) && (retLen != FLASH_ERASE_SIZE))
				{
					printk("\nWrite in write to flash failed status:%d retLen:%d\n", ret, retLen);
					return -1;
				}
				
                printk("*");
#if defined(POWER_LED_GPIO_BIT) 
                gpio_val = gpio_val ^ 0x1;
                ath_gpio_out_val(POWER_LED_GPIO_BIT,gpio_val);
#endif
			}
			address += FLASH_ERASE_SIZE;
			/***************************************************/

			ret = ath_flash_read(mtd, address, FLASH_ERASE_SIZE, &retLen, orignData);
			if ((ret != 0) || (retLen != FLASH_ERASE_SIZE))
			{
				printk("\Read in write to flash failed status:%d retLen:%d\n", ret, retLen);
				return -1;
			}
			
			/* 分区头部，第二部分 */
			memcpy(tempData, (u_int8_t*)(headData) + headLen, 8 - headLen);

			if (len - headLen < FLASH_ERASE_SIZE) /*写入数据长度小于一个block*/
			{
				headLen = 8 - headLen;
				copy_from_user(tempData + headLen, data, tailLen - headLen);/* 需要写入的数据 */
				memcpy(tempData + tailLen, orignData + tailLen, FLASH_ERASE_SIZE - tailLen);/* 原来的数据 */
				data += tailLen - headLen;
			}
			else
			{
				headLen = 8 - headLen;
				copy_from_user(tempData + headLen, data, FLASH_ERASE_SIZE - headLen);/* 需要写入的数据 */
				data += FLASH_ERASE_SIZE - headLen;
			}
		}
		else /* 头部未被拆分 */
		{
			memcpy(tempData + frontLen, headData, headLen);/* 分区头部(如果有的话) */
			
			if (len + frontLen < FLASH_ERASE_SIZE) /*写入数据长度小于一个block*/
			{
				copy_from_user(tempData + frontLen + headLen, data, len - headLen);/* 后面为需要写入的数据 */
				data += len - headLen;
				/* 再后面是原来的数据 */
				memcpy(tempData + frontLen + len,
						orignData + frontLen + len,
						FLASH_ERASE_SIZE - (frontLen + len));
			}
			else
			{
				copy_from_user(tempData + frontLen + headLen, data, FLASH_ERASE_SIZE - frontLen - headLen);
				/* 后面为需要写入的数据 */
				data += FLASH_ERASE_SIZE - frontLen - headLen;
			}
		}

		/***************************************************/
		if (memcmp(orignData, tempData, FLASH_ERASE_SIZE)) /*内容变化*/
		{
		    ath_flash_sector_erase(address);
		    ret = ath_flash_write(mtd, address, FLASH_ERASE_SIZE, &retLen, tempData);
			if ((ret != 0) && (retLen != FLASH_ERASE_SIZE))
			{
				printk("\nWrite in write to flash failed status:%d retLen:%d\n", ret, retLen);
				return -1;
			}
            printk("*");
#if defined(POWER_LED_GPIO_BIT) 
			gpio_val = gpio_val ^ 0x1;
            ath_gpio_out_val(POWER_LED_GPIO_BIT,gpio_val);
#endif
		}
		address += FLASH_ERASE_SIZE;
		/***************************************************/
	}

	if (address < endAddr)/* 中间完整的block，注意:此处用 < 而不是 <=。 */
	{
		startAddr = address;
		while (address < endAddr)
		{
			ret = ath_flash_read(mtd, address, FLASH_ERASE_SIZE, &retLen, orignData);
			if ((ret != 0) || (retLen != FLASH_ERASE_SIZE))
			{
				printk("\Read in write to flash failed status:%d retLen:%d\n", ret, retLen);
				return -1;
			}
			copy_from_user(tempData, data, FLASH_ERASE_SIZE);
			/***************************************************/
			if (memcmp(orignData, tempData, FLASH_ERASE_SIZE)) /*内容变化*/
			{
				ath_flash_sector_erase(address);
				ret = ath_flash_write(mtd, address, FLASH_ERASE_SIZE, &retLen, tempData);
				if ((ret != 0) && (retLen != FLASH_ERASE_SIZE))
				{
					printk("\nWrite in write to flash failed status:%d retLen:%d\n", ret, retLen);
					return -1;
				}
                printk("*");
#if defined(POWER_LED_GPIO_BIT) 
				gpio_val = gpio_val ^ 0x1;
            	ath_gpio_out_val(POWER_LED_GPIO_BIT,gpio_val);
#endif
			}
			address += FLASH_ERASE_SIZE;
			/***************************************************/
			data += FLASH_ERASE_SIZE;
		}
	}

	if (address < offset + len) /* 如果还没有写完，则说明最后有一个不完整的block */
	{
		ret = ath_flash_read(mtd, address, FLASH_ERASE_SIZE, &retLen, orignData);
		if ((ret != 0) || (retLen != FLASH_ERASE_SIZE))
		{
			printk("\Read in write to flash failed status:%d retLen:%d\n", ret, retLen);
			return -1;
		}
		copy_from_user(tempData, data, tailLen);/*前面一部分为需要写入的数据*/
		memcpy(tempData + tailLen, orignData + tailLen, FLASH_ERASE_SIZE - tailLen);
		/*后面为原来数据*/
		/***************************************************/
		if (memcmp(orignData, tempData, FLASH_ERASE_SIZE)) /*内容变化*/
		{
		    ath_flash_sector_erase(address);
		    ret = ath_flash_write(mtd, address, FLASH_ERASE_SIZE, &retLen, tempData);
			if ((ret != 0) && (retLen != FLASH_ERASE_SIZE))
			{
				printk("\nWrite in write to flash failed status:%d retLen:%d\n", ret, retLen);
				return -1;
			}
            printk("*");
#if defined(POWER_LED_GPIO_BIT) 
			gpio_val = gpio_val ^ 0x1;
            ath_gpio_out_val(POWER_LED_GPIO_BIT,gpio_val);
#endif
		}
		address += FLASH_ERASE_SIZE;
		/***************************************************/
	}

	return 0;
}


int ath_flash_ioctl(struct inode *inode, struct file *file,  unsigned int cmd, unsigned long arg)
{
	struct mtd_info *mtd = (struct mtd_info *)kmalloc(sizeof(struct mtd_info), GFP_KERNEL);
	/* temp buffer for r/w */
	unsigned char *rwBuf = (unsigned char *)kmalloc(2*FLASH_ERASE_SIZE, GFP_KERNEL);
	
	ARG *pArg = (ARG*)arg;
	u_int8_t* usrBuf = pArg->buf;
	u_int32_t usrBufLen = pArg->buflen;
	u_int32_t addr = pArg->addr;
    //u_int32_t reset = pArg->reset;
	u_int32_t hasHead = pArg->hasHead;
	
	int ret = 0;
    
	if ((mtd == NULL) || (rwBuf == NULL))
	{
		goto wrong;
	}

	memset(mtd, 0, sizeof(struct mtd_info));

    mtd->size               =   TP_LINK_FLASH_SIZE;
	mtd->erasesize          =   ATH_FLASH_SECTOR_SIZE;
	mtd->numeraseregions    =   0;
	mtd->eraseregions       =   NULL;
	mtd->owner              =   THIS_MODULE;

	if (_IOC_TYPE(cmd) != ATH_IO_MAGIC) {
		printk("cmd type error!\n");
		goto wrong;
	}
	if (_IOC_NR(cmd) > ATH_IOC_MAXNR) {
		printk("cmd NR error!\n");
		goto wrong;
	}
    
	if (_IOC_DIR(cmd) & _IOC_READ) {
		ret = access_ok(VERIFY_WRITE, (void __user *)usrBuf, _IOC_SIZE(cmd));
	} else if (_IOC_DIR(cmd) & _IOC_WRITE) {
		ret = access_ok(VERIFY_READ, (void __user *)usrBuf, _IOC_SIZE(cmd));
	}
    
	if (ret < 0) { 
		printk("access %p not ok!\n", usrBuf);
		goto wrong;
	}

	switch(cmd)
	{
	case ATH_IO_FLASH_READ:
		ret = nvram_flash_read(mtd, rwBuf, hasHead, addr, usrBuf, usrBufLen);
        if (ret < 0)
        {
                goto wrong;
        }

		break;

	case ATH_IO_FLASH_WRITE:
		ret = nvram_flash_write(mtd, rwBuf, hasHead, addr, usrBuf, usrBufLen);
        if (ret < 0)
        {
            goto wrong;
        }
		break;

	case  ATH_FLASH_ERASE:
		ret = -1;
		break;
	}

wrong:
	if (mtd) {
		kfree(mtd);
	}

	if (rwBuf) {
		kfree(rwBuf);
	}

	return ret;
}


int ath_flash_open (struct inode *inode, struct file *filp)
{
	int minor = iminor(inode);
	//int devnum = minor; //>> 1;
	//struct mtd_info *mtd;
	//printk("Now flash open!\n");
	
	if ((filp->f_mode & 2) && (minor & 1)) {
		printk("You can't open the RO devices RW!\n");
		return -EACCES;
	}

	//mtd = get_mtd_device(NULL, devnum);   
	//if (!mtd) {
	//	printk("Can not open mtd!\n");
	//	return -ENODEV;	
	//}
	//filp->private_data = mtd;
	return 0;
	
}

#ifdef CONFIG_TPLINK_MEM_ROOTFS
static struct mtd_info *mtdram_info = NULL;

static int mtdram_read(struct mtd_info *mtd, loff_t from, size_t len,
		size_t *retlen, u_char *buf)
{
	if (from + len > mtd->size)
		return -EINVAL;

	memcpy(buf, mtd->priv + from, len);

	*retlen = len;
	return 0;
}

static void mtdram_cleanup(void)
{
    if (mtdram_info) {
        del_mtd_device(mtdram_info);
        kfree(mtdram_info);
        mtdram_info = NULL;
    }
}

static int mtdram_setup(void)
{
    struct mtd_info *mtd;
    extern unsigned int mtd_ram_addr;
    extern unsigned int mtd_ram_size;

    if (mtd_ram_addr == 0 || mtd_ram_size == 0) {
        return 0;
    }
    printk(KERN_NOTICE "%s: booting with mem rootfs@%x/%x.\n",
        __func__, mtd_ram_addr, mtd_ram_size);

    mtd = get_mtd_device_nm("rootfs");
    if (mtd != NULL && mtd != ERR_PTR(-ENODEV)) {
        put_mtd_device(mtd);
        del_mtd_device(mtd);
    } else {
        return -ENODEV;
    }
    
	mtd = kmalloc(sizeof(struct mtd_info), GFP_KERNEL);
	memset(mtd, 0, sizeof(*mtd));

	mtd->name = "rootfs";
	mtd->type = MTD_ROM;
	mtd->flags = MTD_CAP_ROM;
	mtd->size = mtd_ram_size;
	mtd->writesize = 1;
	mtd->priv = (void*)mtd_ram_addr;

	mtd->owner = THIS_MODULE;
	mtd->read = mtdram_read;

    mtdram_info = mtd;
	if (add_mtd_device(mtd)) {
		return -EIO;
	}

	return 0;
}
#endif

int __init ath_flash_chrdev_init (void)
{
    dev_t dev;
    int result;
    int err;
    int ath_flash_major = flash_major;
    int ath_flash_minor = flash_minor;

    if (ath_flash_major) {
        dev = MKDEV(ath_flash_major, ath_flash_minor);
        result = register_chrdev_region(dev, 1, "ar7240_flash_chrdev");
    } else {
        result = alloc_chrdev_region(&dev, ath_flash_minor, 1, "ar7240_flash_chrdev");
        ath_flash_major = MAJOR(dev);
    }

    if (result < 0) {
        printk(KERN_WARNING "ar7240_flash_chrdev : can`t get major %d\n", ath_flash_major);
        return result;
    }
    cdev_init (&flash_device_cdev, &flash_device_op);
    err = cdev_add(&flash_device_cdev, dev, 1);
    if (err) printk(KERN_NOTICE "Error %d adding flash_chrdev ", err);
//    devfs_mk_cdev(dev, S_IFCHR | S_IRUSR | S_IWUSR, "ar7240flash_chrdev");

#ifdef CONFIG_TPLINK_MEM_ROOTFS
    mtdram_setup();
#endif
    return 0;

}

static void __exit cleanup_ath_flash_chrdev_exit (void)
{
//	unregister_chrdev_region(MKDEV(flash_major, flash_minor), 1);
#ifdef CONFIG_TPLINK_MEM_ROOTFS
    mtdram_cleanup();
#endif
}


module_init(ath_flash_chrdev_init);
module_exit(cleanup_ath_flash_chrdev_exit);
MODULE_LICENSE("GPL");

