/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-crypto device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/delay.h>

#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	int *host_fd;
	//unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	//int host_fd = -1;

	//Extra declarations
	unsigned int num_out = 0;
	unsigned int num_in = 0;
	struct scatterlist syscall_type_sg , host_fd_sg, *sgs[2];

	debug("Entering open");

	/* Allocate all data that will be sent to the host. */
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_OPEN;
	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = -1;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
		      iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/* We need two sg lists, one for syscall_type and*
	 * one to get the file descriptor from the host. */
	//syscall_type
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	//host_fd from the host
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	/* Wait for the host to process our data. */
	if (down_interruptible(&crdev->lock)) {
		return -ERESTARTSYS;
	}
	virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(crdev->vq);

	while(virtqueue_get_buf(crdev->vq, &len) == NULL);

	up(&crdev->lock);

	/* If host failed to open() return -ENODEV. */
	if ((crof->host_fd = *host_fd) <= 0) {
		ret= -ENODEV;
		goto fail;
	}	

fail:
	debug("Leaving open");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;
	int *host_fd;
	//unsigned int syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;

	//Extra declarations
	struct scatterlist syscall_type_sg, host_fd_sg, /*ret_sg, *sgs[3];*/ *sgs[2];
	unsigned int len;
	unsigned int num_out = 0;
	unsigned int num_in = 0;
	long *host_return_val;

	debug("Entering release");

	/* Allocate all data that will be sent to the host. */
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_CLOSE;
	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;
	host_return_val = kmalloc(sizeof(*host_return_val), GFP_KERNEL);
	*host_return_val = -1;

	/* Send data to the host. */
	//syscall_type
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	//host_fd
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;

	//host_return_val from the host is NEEDED?
	//sg_init_one(&ret_sg, host_return_val, sizeof(*host_return_val));
	//sgs[num_out + num_in++] = &ret_sg;

	/* Wait for the host to process our data. */
	if (down_interruptible(&crdev->lock)) {
		return -ERESTARTSYS;
	}
	virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in, &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(crdev->vq);

	while(virtqueue_get_buf(crdev->vq, &len) == NULL);

	up(&crdev->lock);

	kfree(crof);
	debug("Leaving realease");
	return ret;
}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
                                unsigned long arg)
{
	long ret = 0; 
	int err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;

	//Extra declarations
	struct scatterlist syscall_type_sg, host_fd_sg, cmd_sg, session_sg, crypto_sg,/*output_msg_sg, input_msg_sg,*/ key_msg_sg, ret_sg, dest_msg_sg, src_msg_sg, iv_msg_sg, *sgs[9];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	unsigned char *output_msg, *input_msg, *key, *src, *dst, *iv;
	unsigned int *syscall_type;
	unsigned int *ioctl_cmd;
	int *host_fd;
	long *host_return_val;
	uint32_t *ses;
	struct session_op seop, *seop_pointer;
	struct crypt_op crop, *crop_pointer;

	debug("Entering ioctl frontend");
	
	/* Allocate all data that will be sent to the host. */
	output_msg = kmalloc(MSG_LEN, GFP_KERNEL);
	input_msg = kmalloc(MSG_LEN, GFP_KERNEL);
	syscall_type = kmalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTO_SYSCALL_IOCTL;
	host_fd = kmalloc(sizeof(*host_fd), GFP_KERNEL);
	*host_fd = crof->host_fd;
	printk("crof->host_fd = %d \n", *host_fd);
	ioctl_cmd = kmalloc(sizeof(*ioctl_cmd), GFP_KERNEL);
	*ioctl_cmd = cmd;
	host_return_val = kmalloc(sizeof(*host_return_val), GFP_KERNEL);
	*host_return_val = -1;
	ses = kmalloc(sizeof(*ses), GFP_KERNEL);
	*ses = 0;

	num_out = 0;
	num_in = 0;
	key = NULL;
	src = NULL;
	dst = NULL; 
	iv = NULL;

	/* These are common to all ioctl commands. */
	//syscall_type  | num_out++ = 1
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	//host_fd  | num_out++ = 2
	sg_init_one(&host_fd_sg, host_fd, sizeof(*host_fd));
	sgs[num_out++] = &host_fd_sg;
	debug("After sg_initS and before switch command execution");
	printk("cmd = %d \n", cmd);

	/* Add all the cmd specific sg lists. */
	switch (cmd) {
	case CIOCGSESSION:
		debug("Entering CIOCGSESSION frontend");
		memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36);
		input_msg[0] = '\0';

		//cmd ={CIOCGSESSION, CIOCFSESSION, CIOCCRYPT}  | num_out++ = 3
		sg_init_one(&cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
		sgs[num_out++] = &cmd_sg;

/*		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);*/
/*		sgs[num_out++] = &output_msg_sg;*/
/*		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);*/
/*		sgs[num_out + num_in++] = &input_msg_sg;*/

		//get session struct from arg from userspace
		if (unlikely(copy_from_user(&seop, (struct session_op*)arg, sizeof(struct session_op))))
			return -EFAULT;

		//key
		key = kmalloc(seop.keylen, GFP_KERNEL);
		if (unlikely(copy_from_user(key, seop.key, seop.keylen)))
			return -EFAULT;

		//seop->key should be sent to backend  | num_out++ = 4
		sg_init_one(&key_msg_sg, key, seop.keylen);
		sgs[num_out++] = &key_msg_sg;   	 

		seop_pointer = &seop;
		//session struct seop should be filled from backend  | num_out + num_in++ = 5
		sg_init_one(&session_sg, seop_pointer, sizeof(struct session_op *));
		sgs[num_out + num_in++] = &session_sg;

		//host_return_val  | num_out + num_in++ = 6
		sg_init_one(&ret_sg, host_return_val, sizeof(*host_return_val));
		sgs[num_out + num_in++] = &ret_sg;

		debug("Leaving CIOCGSESSION frontend");
		break;

	case CIOCFSESSION:
		debug("Entering CIOCFSESSION frontend");
		memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36);
		input_msg[0] = '\0';

		//cmd ={CIOCGSESSION, CIOCFSESSION, CIOCCRYPT}  | num_out++ = 3
		sg_init_one(&cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
		sgs[num_out++] = &cmd_sg;

/*		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);*/
/*		sgs[num_out++] = &output_msg_sg;*/
/*		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);*/
/*		sgs[num_out + num_in++] = &input_msg_sg;*/

		if (unlikely(copy_from_user(ses, (uint32_t*)arg, sizeof(*ses))))
			return -EFAULT;

		// session->ses should be sent to backend  | num_out++ = 4
		sg_init_one(&session_sg, ses, sizeof(*ses));
		sgs[num_out++] = &session_sg;

		//host_return_val  | num_out + num_in++ = 5
		sg_init_one(&ret_sg, host_return_val, sizeof(*host_return_val));
		sgs[num_out + num_in++] = &ret_sg;

		debug("Leaving CIOCFSESSION frontend");
		break;

	case CIOCCRYPT:
		debug("Entering CIOCCRYPT frontend");
		memcpy(output_msg, "Hello HOST from ioctl CIOCCRYPT.", 33);
		input_msg[0] = '\0';

		//cmd ={CIOCGSESSION, CIOCFSESSION, CIOCCRYPT}  | num_out++ = 3
		sg_init_one(&cmd_sg, ioctl_cmd, sizeof(*ioctl_cmd));
		sgs[num_out++] = &cmd_sg;

/*		sg_init_one(&output_msg_sg, output_msg, MSG_LEN);*/
/*		sgs[num_out++] = &output_msg_sg;*/
/*		sg_init_one(&input_msg_sg, input_msg, MSG_LEN);*/
/*		sgs[num_out + num_in++] = &input_msg_sg;*/

		// crypto struct crop should be sent to backend
		if (unlikely(copy_from_user(&crop, (struct crypt_op*)arg, sizeof(struct crypt_op))))
			return -EFAULT;
		crop_pointer = &crop;
		sg_init_one(&crypto_sg, crop_pointer, sizeof(struct crypt_op*));
		sgs[num_out++] = &crypto_sg;
		   	 
		// crop->src should be sent to backend
		src = kmalloc(crop.len, GFP_KERNEL);
		if (unlikely(copy_from_user(src, crop.src, crop.len)))
			return -EFAULT;
		sg_init_one(&src_msg_sg, src, crop.len);
		sgs[num_out++] = &src_msg_sg;

		iv = kmalloc(16, GFP_KERNEL);
		// crop->iv should be sent to backend
		if (unlikely(copy_from_user(iv, crop.iv, 16)))
			return -EFAULT;
		sg_init_one(&iv_msg_sg, iv, 16);
		sgs[num_out++] = &iv_msg_sg;

		// crop->dst should filled from backend
		dst = kmalloc(crop.len, GFP_KERNEL);
		sg_init_one(&dest_msg_sg, dst, crop.len);
		sgs[num_out + num_in++] = &dest_msg_sg;

		//host_return_val  | num_out + num_in++ = ?
		sg_init_one(&ret_sg, host_return_val, sizeof(*host_return_val));
		sgs[num_out + num_in++] = &ret_sg;

		debug("Leaving CIOCCRYPT frontend");
		break;

	default:
		debug("Unsupported ioctl command");

		break;
	}

	/* Wait for the host to process our data. */
	/* ?? Lock ?? -> OK*/ 
	if (down_interruptible(&crdev->lock)) {
		return -ERESTARTSYS;
	}
	err = virtqueue_add_sgs(crdev->vq, sgs, num_out, num_in,
	                        &syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(crdev->vq);
	while (virtqueue_get_buf(crdev->vq, &len) == NULL)
		/* do nothing */;
	up(&crdev->lock);

	/* AFTER SGS ARE READY FROM BACKEND */
	switch(cmd) {
	case (CIOCGSESSION):
		debug("CIOCGSESSION RET");
		if (unlikely(copy_to_user((struct session_op*)arg, &seop, sizeof(struct session_op))))
			return -EFAULT;
		kfree(key);

		break;
		
	case (CIOCFSESSION):
		debug("CIOCFSESSION RET");
	
		break;
		
	case (CIOCCRYPT):
		debug("CIOCCRYPT RET");
		if (unlikely(copy_to_user((struct crypt_op*)arg, &crop, sizeof(struct crypt_op))))
			return -EFAULT;
		if (unlikely(copy_to_user(crop.dst, dst, crop.len*sizeof(char))))
			return -EFAULT;
		kfree(src);
		kfree(dst);
		kfree(iv);
		
		break;	
	}

	//debug("We said: '%s'", output_msg);
	//debug("Host answered: '%s'", input_msg);

	kfree(output_msg);
	kfree(input_msg);
	kfree(syscall_type);

	debug("Leaving ioctl front end");

	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
                                  size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;
	
	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}