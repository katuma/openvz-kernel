drbd-y := drbd_buildtag.o drbd_bitmap.o drbd_proc.o
drbd-y += drbd_worker.o drbd_receiver.o drbd_req.o drbd_actlog.o
drbd-y += lru_cache.o drbd_main.o drbd_strings.o drbd_nl.o

drbd_trace-y := drbd_tracing.o

obj-$(CONFIG_BLK_DEV_DRBD)     += drbd.o
obj-$(CONFIG_DRBD_TRACE)       += drbd_trace.o
