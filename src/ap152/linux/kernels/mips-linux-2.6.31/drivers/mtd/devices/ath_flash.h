/* 
 * Copyright (c) 2014 Qualcomm Atheros, Inc.
 * 
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 * 
 */

#ifndef _ATH_FLASH_H
#define _ATH_FLASH_H

#define ATH_SPI_CE_LOW		0x60000
#define ATH_SPI_CE_HIGH		0x60100
#define ATH_SPI_SECTOR_SIZE	(1024*64)
#define ATH_SPI_PAGE_SIZE	256

#define ATH_FLASH_MAX_BANKS	1

#define display(_x)	ath_reg_wr_nf(0x18040008, (_x))

/*
 * primitives
 */

#define ath_be_msb(_val, __i) (((_val) & (1 << (7 - __i))) >> (7 - __i))

#define ath_spi_bit_banger(_byte)	do {				\
	int _i;								\
	for(_i = 0; _i < 8; _i++) {					\
		ath_reg_wr_nf(ATH_SPI_WRITE,				\
			ATH_SPI_CE_LOW | ath_be_msb(_byte, _i));	\
		ath_reg_wr_nf(ATH_SPI_WRITE,				\
			ATH_SPI_CE_HIGH | ath_be_msb(_byte, _i));	\
	}								\
} while(0)

#define ath_spi_go()	do {				\
	ath_reg_wr_nf(ATH_SPI_WRITE, ATH_SPI_CE_LOW);	\
	ath_reg_wr_nf(ATH_SPI_WRITE, ATH_SPI_CS_DIS);	\
} while(0);


#define ath_spi_send_addr(__a)	do {			\
	ath_spi_bit_banger(((__a & 0xff0000) >> 16));	\
	ath_spi_bit_banger(((__a & 0x00ff00) >> 8));	\
	ath_spi_bit_banger(__a & 0x0000ff);		\
} while(0);

#define ath_spi_delay_8()	ath_spi_bit_banger(0)
#define ath_spi_done()		ath_reg_wr(ATH_SPI_FS, 0)

int ath_flash_erase(struct mtd_info *mtd, struct erase_info *instr);
int ath_flash_read(struct mtd_info *mtd, loff_t from, size_t len, size_t *retlen, u_char *buf);
int ath_flash_write(struct mtd_info *mtd, loff_t to, size_t len, size_t *retlen, const u_char *buf);
void ath_spi_sector_erase(uint32_t addr);

#endif /*_ATH_FLASH_H*/
