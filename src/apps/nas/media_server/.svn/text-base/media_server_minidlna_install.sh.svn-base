#!/bin/bash

TOP_DIR=$1
ROOTFS_DIR=$2

#put minidlna
echo  "put minidlna"
#cp -f ${TOP_DIR}/minidlna/sbin/minidlna.conf ${ROOTFS_DIR}/etc
cp -f ${TOP_DIR}/minidlna/sbin/minidlnad  ${ROOTFS_DIR}/usr/sbin
cp ${TOP_DIR}/minidlna/lib/libjpeg.so.9.0.0 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libid3tag.so.0.3.0 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libsqlite3.so.0.8.6 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libavformat.so.54.6.100 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libavutil.so.51.54.100 ${ROOTFS_DIR}/lib
cp -f ${TOP_DIR}/minidlna/lib/libavcodec.so.54.23.100 ${ROOTFS_DIR}/lib
cp -f ${TOP_DIR}/minidlna/lib/libavdevice.so.54.0.100  ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libexif.so.12.3.3 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libFLAC.so.8.2.0 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libogg.so.0.6.0 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libvorbis.so.0.4.3 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libiconv.so.2.5.1 ${ROOTFS_DIR}/lib
cp ${TOP_DIR}/minidlna/lib/libswscale.so.2.1.100 ${ROOTFS_DIR}/lib
cp -f ${TOP_DIR}/minidlna/lib/libz.so.1.2.6  ${ROOTFS_DIR}/lib
cp -f ${TOP_DIR}/minidlna/lib/libtiff.so.5.2.0 ${ROOTFS_DIR}/lib
cp -f ${TOP_DIR}/minidlna/lib/libtiffxx.so.5.2.0 ${ROOTFS_DIR}/lib

cd ${ROOTFS_DIR}/lib
ln -sf libjpeg.so.9.0.0 libjpeg.so
ln -sf libjpeg.so.9.0.0 libjpeg.so.9
ln -sf libid3tag.so.0.3.0 libid3tag.so
ln -sf libid3tag.so.0.3.0 libid3tag.so.0
ln -sf libsqlite3.so.0.8.6 libsqlite3.so
ln -sf libsqlite3.so.0.8.6 libsqlite3.so.0
ln -sf libavformat.so.54.6.100 libavformat.so
ln -sf libavformat.so.54.6.100 libavformat.so.54
ln -sf libavutil.so.51.54.100 libavutil.so
ln -sf libavutil.so.51.54.100 libavutil.so.51
ln -sf libavcodec.so.54.23.100 libavcodec.so
ln -sf libavcodec.so.54.23.100 libavcodec.so.54
ln -sf libavdevice.so.54.0.100 libavdevice.so
ln -sf libavdevice.so.54.0.100 libavdevice.so.54
ln -sf libexif.so.12.3.3 libexif.so
ln -sf libexif.so.12.3.3 libexif.so.12
ln -sf libFLAC.so.8.2.0 libFLAC.so
ln -sf libFLAC.so.8.2.0 libFLAC.so.8
ln -sf libogg.so.0.6.0 libogg.so
ln -sf libogg.so.0.6.0 libogg.so.0
ln -sf libvorbis.so.0.4.3 libvorbis.so
ln -sf libvorbis.so.0.4.3 libvorbis.so.0
ln -sf libiconv.so.2.5.1 libiconv.so
ln -sf libiconv.so.2.5.1 libiconv.so.2
ln -sf libswscale.so.2.1.100 libswscale.so
ln -sf libswscale.so.2.1.100 libswscale.so.2
ln -sf libz.so.1.2.6 libz.so
ln -sf libz.so.1.2.6 libz.so.1
ln -sf libtiff.so.5.2.0 libtiff.so
ln -sf libtiff.so.5.2.0 libtiff.so.5
ln -sf libtiffxx.so.5.2.0 libtiffxx.so
ln -sf libtiffxx.so.5.2.0 libtiffxx.so.5
