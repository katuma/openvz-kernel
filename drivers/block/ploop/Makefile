#
# Makefile for Parallels loop device
#
CFLAGS_io_direct.o = -I$(src)
CFLAGS_ploop_events.o = -I$(src)

obj-$(CONFIG_BLK_DEV_PLOOP)	+= ploop.o
ploop-objs := dev.o map.o io.o sysfs.o tracker.o freeblks.o ploop_events.o discard.o

obj-$(CONFIG_BLK_DEV_PLOOP)	+= pfmt_ploop1.o
pfmt_ploop1-objs := fmt_ploop1.o

obj-$(CONFIG_BLK_DEV_PLOOP)	+= pfmt_raw.o
pfmt_raw-objs := fmt_raw.o

obj-$(CONFIG_BLK_DEV_PLOOP)	+= pio_direct.o
pio_direct-objs := io_direct.o io_direct_map.o compat.o

obj-$(CONFIG_BLK_DEV_PLOOP)	+= pio_kaio.o
pio_kaio-objs := io_kaio.o io_kaio_map.o

obj-$(CONFIG_BLK_DEV_PLOOP)	+= pio_nfs.o
pio_nfs-objs := io_nfs.o
