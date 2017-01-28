ARCH           	 := mips
#BOARD_TYPE 	 := db12x
#TOOLPREFIX  	 := mips-linux-uclibc-
#TOPDIR		 := /home/ytl/Downloads/branch_db120
INSTALL_PREFIX 	 = $(TOPDIR)/apps/nas/naspackage/minidlna
TOOLPATH 	 := $(TOPDIR)/build/gcc-4.3.3/build_mips/staging_dir/usr

export PATH   := $(TOOLPATH):$(PATH)
export CC     = $(TOOLPREFIX)gcc
export CXX    = $(TOOLPREFIX)g++
export AR     = $(TOOLPREFIX)ar
export AS    = $(TOOLPREFIX)as
export LD     = $(TOOLPREFIX)ld 
export RANLIB = $(TOOLPREFIX)ranlib
export CFLAGS+= -I$(INSTALL_PREFIX)/include
export CPPFLAGS+= -I$(INSTALL_PREFIX)/include
export CPPFLAGS+= -I$(TOOLPATH)/include
export LDFLAGS+= -L$(INSTALL_PREFIX)/lib 
export LDFLAGS+= -L$(TOOLPATH)/mips-linux-uclibc/lib 

CUR_PATH      = $(CURDIR)
FFMPEG_SRC    = $(CUR_PATH)/ffmpeg-0.11.2
FLAC_SRC      = $(CUR_PATH)/flac-1.2.1
JPEG_SRC      = $(CUR_PATH)/jpeg-9
LIBEXIF_SRC   = $(CUR_PATH)/libexif-0.6.21
LIBICONV_SRC  = $(CUR_PATH)/libiconv-1.14
LIBID3TAG_SRC = $(CUR_PATH)/libid3tag-0.15.1b
LIBOGG_SRC    = $(CUR_PATH)/libogg-1.1.4
LIBUUID_SRC   = $(CUR_PATH)/libuuid-1.0.2
LIBVORBIS_SRC = $(CUR_PATH)/libvorbis-1.2.3
ZLIB_SRC      = $(CUR_PATH)/zlib-1.2.6
SQLITE3_SRC   = $(CUR_PATH)/sqlite-3.7.12.1
LIBTIFF_SRC     = $(CUR_PATH)/tiff-4.0.3
MINIDLNA_SRC  = $(CUR_PATH)/minidlna-1.1.0
FFMPEG_CUSTOM_ENCODERS:= \
	ac3 \
	jpegls \
	mpeg1video \
	mpeg2video \
	mpeg4 \
	pcm_s16be \
	pcm_s16le \
	png \
	bmp \
	tiff \
	gif \
	vorbis \
	zlib \

FFMPEG_CUSTOM_DECODERS:= \
	libfdk-aac \
	ac3 \
	atrac3 \
	flac \
	gif \
	tiff \
	bmp	\
	h264 \
	jpegls \
	mp2 \
	mp3 \
	mpeg1video \
	mpeg2video \
	mpeg4 \
	mpegvideo \
	pcm_s16be \
	pcm_s16le \
	png \
	vorbis \
	wmav1 \
	wmav2 \
	zlib \
	flv \

FFMPEG_CUSTOM_MUXERS:= \
	ac3 \
	aiff \
	adts \
	ffm \
	h264 \
	mp3 \
	mp4 \
	mpeg1video \
	mpeg2video \
	mpegts \
	ogg \
	rtp \
	gif \
	gxf \
	ipod \
	dv \
	srt \
	swf \
	image2 \
	rm \
	wav \
	mov \
	avi \
	
FFMPEG_CUSTOM_DEMUXERS:= \
	aac \
	ac3 \
	avi \
	aiff \
	adts \
	dv \
	flac \
	flv \
	ffm \
	h264 \
	image2 \
	matroska \
	mov \
	mp3 \
	mpegps \
	mpegts \
	mpegvideo \
	ogg \
	rm \
	rtsp \
	sdp \
	v4l2 \
	wav \

FFMPEG_CUSTOM_PARSERS:= \
	aac \
	ac3 \
	flac \
	h264 \
	mpegaudio \
	mpeg4video \
	mpegvideo \
	png \
	vorbis \
	
FFMPEG_CUSTOM_PROTOCOLS:= \
	file http pipe rtp tcp udp
	
FFMPEG_ENABLE= \
	$(foreach c, $(2), \
		--enable-$(1)="$(c)" \
	)


# 说明：这里为了缩短编译时间，只编译了minidlna，没有编译相关依赖库，如果有需要可以修改makefile，重新编译库文件。
.PHONY:media_server
media_server: minidlna # build_prep zlib tiff libogg sqlite3  libvorbis libiconv  flac    libexif  jpeg libuuid   libid3tag ffmpeg minidlna  

.PHONY: media_server_clean
media_server_clean:   zlib_clean sqlite3_clean  libvorbis_clean libiconv_clean  flac_clean  libogg_clean  \
		   libexif_clean  jpeg_clean libuuid_clean   libid3tag_clean ffmpeg_clean minidlna_clean 

.PHONY:variables
variables:
	echo $(ARCH);\
	echo $(BOARD_TYPE);\
	echo $(TOOLPREFIX);\
	echo $(TOPDIR);\
	echo $(INSTALL_PREFIX);\
	echo $(TOOLPATH) ;
	
.PHONY:build_prep
build_prep:
	-mkdir $(INSTALL_PREFIX)/lib; 
	-mkdir $(INSTALL_PREFIX)/include;

.PHONY:tiff_configure
tiff_configure:
	cd $(LIBTIFF_SRC); \
	./configure --prefix=$(INSTALL_PREFIX) \
		--build=i686-linux --host=mips-linux 
.PHONY:tiff
tiff:tiff_configure
	cd $(LIBTIFF_SRC) && \
		$(MAKE) && $(MAKE) install 
.PHONY:tiff_clean
tiff_clean:tiff_configure
	cd $(LIBTIFF_SRC) && \
		$(MAKE) clean

.PHONY:ffmpeg_configure
ffmpeg_configure:
	cd $(FFMPEG_SRC) && \
		./configure \
		--prefix=$(INSTALL_PREFIX) \
		--libdir=$(INSTALL_PREFIX)/lib \
		--shlibdir=$(INSTALL_PREFIX)/lib \
		--incdir=$(INSTALL_PREFIX)/include \
		--cc=$(TOOLPREFIX)gcc \
		--host-cc=gcc \
		--enable-cross-compile --target-os=linux --arch=mips \
		--enable-shared --enable-static \
		--disable-debug  --pkg-config="pkg-config" \
		--enable-gpl --enable-version3 --enable-nonfree \
		--disable-asm --disable-doc \
		--disable-dxva2 --enable-pthreads --enable-small --disable-stripping \
		--enable-zlib --disable-outdevs \
		--disable-ffmpeg --disable-ffserver --disable-ffplay --disable-ffprobe \
		--disable-avfilter --disable-postproc \
		--disable-everything \
		$(call FFMPEG_ENABLE,encoder,$(FFMPEG_CUSTOM_ENCODERS)) \
		$(call FFMPEG_ENABLE,decoder,$(FFMPEG_CUSTOM_DECODERS)) \
		$(call FFMPEG_ENABLE,muxer,$(FFMPEG_CUSTOM_MUXERS)) \
		$(call FFMPEG_ENABLE,demuxer,$(FFMPEG_CUSTOM_DEMUXERS)) \
		$(call FFMPEG_ENABLE,parser,$(FFMPEG_CUSTOM_PARSERS)) \
		$(call FFMPEG_ENABLE,protocol,$(FFMPEG_CUSTOM_PROTOCOLS)) 

.PHONY:ffmpeg
ffmpeg:ffmpeg_configure
	cd $(FFMPEG_SRC) && \
		$(MAKE) && $(MAKE) install
.PHONY:ffmpeg_clean
ffmpeg_clean:
	cd $(FFMPEG_SRC) && \
		$(MAKE) clean
##############################################
.PHONY:flac_configure
flac_configure:

	cd $(FLAC_SRC); \
		./configure --prefix=$(INSTALL_PREFIX) \
		--build=i686-linux --host=mips-linux \
		--disable-cpplibs 

.PHONY:flac
flac: flac_configure
	cd $(FLAC_SRC); \
		$(MAKE) && $(MAKE) install
.PHONY:flac_clean
flac_clean:
	cd $(FLAC_SRC); \
		$(MAKE)  clean
##############################################		
.PHONY:libogg_configure
libogg_configure: 

	cd $(LIBOGG_SRC) && \
		./configure --prefix=$(INSTALL_PREFIX) --host=$(ARCH)-linux \
		--disable-asm-optimizations --enable-shared --disable-cpplibs 

.PHONY:libogg
libogg:libogg_configure
	cd $(LIBOGG_SRC) && \
		 $(MAKE) && $(MAKE) install
.PHONY:libogg_clean
libogg_clean:
	cd $(LIBOGG_SRC); \
		$(MAKE)  clean
##############################################		
.PHONY:jpeg_configure
jpeg_configure:

	cd $(JPEG_SRC) && ./configure --prefix=$(INSTALL_PREFIX)  \
		--host=$(ARCH)-linux 

.PHONY:jpeg
jpeg:jpeg_configure
	cd $(JPEG_SRC);\
		$(MAKE) && $(MAKE) install
.PHONY:jpeg_clean
jpeg_clean:
	cd $(JPEG_SRC);\
		$(MAKE)  clean
##############################################
.PHONY:libexif_configure
libexif_configure: 

	cd $(LIBEXIF_SRC) && \
		./configure --prefix=$(INSTALL_PREFIX) --host=$(ARCH)-linux \
		--enable-shared 

.PHONY:libexif
libexif: libexif_configure
	cd $(LIBEXIF_SRC) && \
		$(MAKE) && $(MAKE) install
.PHONY:libexif_clean
libexif_clean: 
	cd $(LIBEXIF_SRC) && \
		$(MAKE) clean
##############################################
.PHONY:libiconv_configure
libiconv_configure:

	cd $(LIBICONV_SRC); \
	./configure --prefix=$(INSTALL_PREFIX) \
		--build=i686-linux --host=$(ARCH)-linux --enable-shared 

.PHONY:libiconv
libiconv:libiconv_configure
	cd $(LIBICONV_SRC); \
		$(MAKE) && $(MAKE) install	
PHONY:libiconv_clean
libiconv_clean:
	cd $(LIBICONV_SRC); \
		$(MAKE) clean
##############################################
.PHONY:libid3tag_configure
libid3tag_configure:

	cd $(LIBID3TAG_SRC) && \
		CPPFLAGS=-I$(INSTALL_PREFIX)/include LDFLAGS=-L$(INSTALL_PREFIX)/lib \
		./configure --prefix=$(INSTALL_PREFIX) --host=$(ARCH)-linux --enable-shared 

.PHONY:libid3tag
libid3tag:libid3tag_configure
	cd $(LIBID3TAG_SRC) && \
		$(MAKE) && $(MAKE) install
.PHONY:libid3tag_clean
libid3tag_clean:
	cd $(LIBID3TAG_SRC) && \
		$(MAKE) clean
##############################################
.PHONY:libogg_configure
libogg_configure: 

	cd $(LIBOGG_SRC); \
	./configure --prefix=$(INSTALL_PREFIX) \
		--build=i686-linux --host=$(ARCH)-linux --enable-shared 

.PHONY:libogg
libogg: libogg_configure
	cd $(LIBOGG_SRC); \
		$(MAKE) && $(MAKE) install
.PHONY:libogg_clean
libogg_clean:
	cd $(LIBOGG_SRC); \
		$(MAKE) clean
##############################################
.PHONY:libuuid_configure
libuuid_configure:

	cd $(LIBUUID_SRC); \
	./configure --prefix=$(INSTALL_PREFIX) \
		--build=i686-linux --host=$(ARCH)-linux --enable-shared 

.PHONY:libuuid
libuuid: libuuid_configure
	cd $(LIBUUID_SRC); \
		$(MAKE) && $(MAKE) install
.PHONY:libuuid_clean
libuuid_clean: 
	cd $(LIBUUID_SRC); \
		$(MAKE) clean
##############################################
.PHONY:libvorbis_configure
libvorbis_configure:

	cd $(LIBVORBIS_SRC) ; \
		LDFLAGS+="-L$(INSTALL_PREFIX)/lib -Wl,-rpath-link,$(TOOLPATH)/mips-linux-uclibc/lib"; \
		./configure --prefix=$(INSTALL_PREFIX)  \
		--host=$(ARCH)-linux --enable-shared --disable-oggtest 

.PHONY:libvorbis
libvorbis:libvorbis_configure
	cd $(LIBVORBIS_SRC) ; \
		$(MAKE) && $(MAKE) install
.PHONY:libvorbis_clean
libvorbis_clean:
	cd $(LIBVORBIS_SRC) ; \
		$(MAKE) clean
##############################################
.PHONY:zlib_configure
zlib_configure:

	cd $(ZLIB_SRC) && \
		./configure --prefix=$(INSTALL_PREFIX)  	

.PHONY:zlib
zlib:zlib_configure
	cd $(ZLIB_SRC) && \
		$(MAKE) && $(MAKE) install
.PHONY:zlib_clean
zlib_clean:
	cd $(ZLIB_SRC) && \
		$(MAKE) clean
##############################################
.PHONY:sqlite3_configure
sqlite3_configure:
	export CFLAGS+=-DSQLITE_ENABLE_MEMORY_MANAGEMENT; \
	cd $(SQLITE3_SRC) && \
		./configure --prefix=$(INSTALL_PREFIX) \
				--libexecdir=$(INSTALL_PREFIX) \
				--libdir=$(INSTALL_PREFIX)/lib \
				--includedir=$(INSTALL_PREFIX)/include \
				--build=i686-linux --host=$(ARCH)-linux 

.PHONY:sqlite3
sqlite3:sqlite3_configure
	cd $(SQLITE3_SRC) && \
		$(MAKE) $(CFLAGS) && $(MAKE) install
.PHONY:sqlite3_clean
sqlite3_clean:
	cd $(SQLITE3_SRC) && \
		$(MAKE) clean
##############################################
.PHONY:minidlna_configure
minidlna_configure:

	cd $(MINIDLNA_SRC) ;\
		echo $(PATH); \
		export LDFLAGS+="-L$(INSTALL_PREFIX)/lib  -L$(TOOLPATH)/mips-linux-uclibc/lib "; \
		export LDFLAGS+="-Wl,-rpath-link,$(INSTALL_PREFIX)/lib -Wl,-rpath-link,$(TOOLPATH)/mips-linux-uclibc/lib "; \
		./configure --prefix=$(INSTALL_PREFIX)  --build=i686-linux --host=$(ARCH)-linux \
		--enable-cross-compile  --with-log-path=/tmp/mediaserver --with-db-path=/tmp/mediaserver/cache

.PHONY:minidlna
minidlna:minidlna_configure
	cd $(MINIDLNA_SRC) ;\
		$(MAKE) && $(MAKE) install
.PHONY:minidlna_clean
minidlna_clean:
	cd $(MINIDLNA_SRC) ;\
		$(MAKE) clean
