#!/bin/sh
set -x
lsmod
rmmod sys_xcrypt
insmod sys_xcrypt.ko
lsmod
