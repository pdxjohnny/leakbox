// Copyright (c) 2016, Intel Corporation
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//    * Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in the
//      documentation and/or other materials provided with the distribution.
//    * Neither the name of Intel Corporation nor the names of its contributors
//      may be used to endorse or promote products derived from this software
//      without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/errno.h>
#include <asm/uaccess.h>

#include "leakbox.h"

#define INFO KERN_INFO "leakbox: "
#define FIRST_MINOR 0
#define MINOR_CNT 1

#define OF_SIZE 256

static dev_t dev;
static struct cdev c_dev;
static struct class *cl;

void vulnerable_func(const char *msg, ssize_t msg_size, short call_times);

static int leakbox_open(struct inode *i, struct file *f) { return 0; }

static int leakbox_close(struct inode *i, struct file *f) { return 0; }

static long leakbox_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
  struct poc_msg msg;

  if (copy_from_user(&msg, (struct poc_msg *)arg, sizeof(struct poc_msg))) {
    return -EACCES;
  }

  printk(INFO "msg.length: %d\n", msg.length);

  // Call it multiple times to make sure we dont overwrite the return on ioctl
  // handler
  vulnerable_func(msg.buffer, msg.length, 10);

  return 0;
}

void vulnerable_func(const char *msg, ssize_t msg_size, short call_times) {
  // The buffer we will overflow
  char overflow_me[OF_SIZE];
  printk(INFO "called vulnerable_func\n");
  if (call_times < 0) {
    // Doh! Used size of attacker controlled not defender controlled for copy!
    // Stack overflow eminent!
    memcpy(overflow_me, msg, msg_size);
    // If we succeed in the memcpy then say so
    printk(INFO "vulnerable_func finished memcpy\n");
  } else {
    vulnerable_func(msg, msg_size, --call_times);
  }
  printk(INFO "exit vulnerable_func\n");
}

static struct file_operations leakbox_fops = {.owner = THIS_MODULE,
                                              .open = leakbox_open,
                                              .release = leakbox_close,
                                              .unlocked_ioctl = leakbox_ioctl};

static int __init leakbox_init(void) {
  int ret;
  struct device *dev_ret;

  if ((ret = alloc_chrdev_region(&dev, FIRST_MINOR, MINOR_CNT, "leakbox")) <
      0) {
    return ret;
  }

  cdev_init(&c_dev, &leakbox_fops);

  if ((ret = cdev_add(&c_dev, dev, MINOR_CNT)) < 0) {
    return ret;
  }

  if (IS_ERR(cl = class_create(THIS_MODULE, "leakbox_char"))) {
    cdev_del(&c_dev);
    unregister_chrdev_region(dev, MINOR_CNT);
    return PTR_ERR(cl);
  }
  if (IS_ERR(dev_ret = device_create(cl, NULL, dev, NULL, "leakbox"))) {
    class_destroy(cl);
    cdev_del(&c_dev);
    unregister_chrdev_region(dev, MINOR_CNT);
    return PTR_ERR(dev_ret);
  }

  printk(INFO "Loaded\n");
  return 0;
}

static void __exit leakbox_exit(void) {
  device_destroy(cl, dev);
  class_destroy(cl);
  cdev_del(&c_dev);
  unregister_chrdev_region(dev, MINOR_CNT);
  printk(INFO "Unloaded\n");
}

module_init(leakbox_init);
module_exit(leakbox_exit);

MODULE_LICENSE("GPL");
