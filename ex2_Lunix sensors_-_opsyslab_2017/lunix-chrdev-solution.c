/*
 * lunix-chrdev.c
 *
 * Implementation of character devices
 * for Lunix:TNG
 *
 * < Your name here >
 *
 */

#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/list.h>
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/ioctl.h>
#include <linux/types.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mmzone.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "lunix.h"
#include "lunix-chrdev.h"
#include "lunix-lookup.h"

/*
 * Global data
 */
struct cdev lunix_chrdev_cdev;

/*
 * Just a quick [unlocked] check to see if the cached
 * chrdev state needs to be updated from sensor measurements.
 */
static int lunix_chrdev_state_needs_refresh(struct lunix_chrdev_state_struct *state)
{
	debug("refresh_entering\n");
	
	struct lunix_sensor_struct *sensor;
	
	WARN_ON ( !(sensor = state->sensor));

	if (!(sensor->msr_data[state->type]->last_update == state->buf_timestamp)) {
		return 1;
	}

	/* The following return is bogus, just for the stub to compile */
	debug("refresh_leaving\n");
	return 0; /* ? */
}

/*
 * Updates the cached state of a character device
 * based on sensor data. Must be called with the
 * character device state lock held.
 */
static int lunix_chrdev_state_update(struct lunix_chrdev_state_struct *state)
{
	int i, type, refreshed;
	uint32_t data;
	unsigned long flags;
	long dec, fract;
	long data_value;
	long *lookup[N_LUNIX_MSR] = {lookup_voltage, lookup_temperature, lookup_light};
	unsigned char sign, *temp_buf;
	struct lunix_sensor_struct *sensor;

	debug("update_entering\n");
	sensor = state->sensor;
	WARN_ON(!sensor);
	/*
	 * Grab the raw data quickly, hold the
	 * spinlock for as little as possible.
	 */
	/* ? */
	/* Why use spinlocks? See LDD3, p. 119 */
	/*
	 * Any new data available?
	 */
	/* ? */
	spin_lock_irqsave(&sensor->lock, flags);
	refreshed = lunix_chrdev_state_needs_refresh(state);
	if (refreshed == 1) {
		data = sensor->msr_data[state->type]->values[0];
		state->buf_timestamp = sensor->msr_data[state->type]->last_update;
	}
	spin_unlock_irqrestore(&sensor->lock, flags);

	/*
	 * Now we can take our time to format them,
	 * holding only the private state semaphore
	 */
	/* ? */
	if (refreshed == 1) {
		/*data matching*/
		data_value = lookup[state->type][data];
		/*add sign*/
        	if (data_value >= 0) {
        		sign = '+';
        	}
		else {
			sign = '-';
		}
		dec = data_value / 1000;
		fract = data_value % 1000;
		debug("update_2\n");

		snprintf(state->buf_data, LUNIX_CHRDEV_BUFSZ,"%c%d.%d\n", sign, dec, fract);
		debug("smells good: %s\n", state->buf_data);
		state->buf_lim = strnlen(state->buf_data, LUNIX_CHRDEV_BUFSZ);
		debug("update_3\n");
	      
		state->buf_data[state->buf_lim]='\0';
		state->buf_lim = strnlen(state->buf_data, LUNIX_CHRDEV_BUFSZ);
	}
	else if (state->buf_lim > 0) {
		return -EAGAIN;
    	} 
    	else {
       		return -ERESTARTSYS;
    	}

	debug("update_leaving\n");
	return 0;
}

/*************************************
 * Implementation of file operations
 * for the Lunix character device
 *************************************/

static int lunix_chrdev_open(struct inode *inode, struct file *filp)
{
	/* Declarations */
	/* ? */
	unsigned int minor_num;
	unsigned int sensor_num;
	unsigned int measurement_type;
	int ret;
	//struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	debug("open_entering\n");
	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto out;

	/*
	 * Associate this open file with the relevant sensor based on
	 * the minor number of the device node [/dev/sensor<NO>-<TYPE>]
	 */
	minor_num = iminor(inode);
	measurement_type = minor_num & 7;	
	sensor_num =  (minor_num-measurement_type) >> 3;
	
	/* Allocate a new Lunix character device private state structure */
	/* ? */
	state = kmalloc(sizeof(struct lunix_chrdev_state_struct), GFP_KERNEL);
	if (!state) {
        	/* handle error ... */
		debug("Out of memory! State struct allocation failed!\n");
		ret = -ENOMEM;
		goto out;
	}
	/*initializing state struct*/
	state->type = measurement_type;
	state->sensor = &lunix_sensors[sensor_num];
	state->buf_lim = 0;
	//state->buf_data = "";
	state->buf_timestamp = 0;
	sema_init(&state->lock, 1);

	filp->private_data = state;
	
out:
	debug("open_leaving, with ret = %d\n", ret);
	return ret;
}

static int lunix_chrdev_release(struct inode *inode, struct file *filp)
{
	/* ? */
	kfree(filp->private_data);
	return 0;
}

static long lunix_chrdev_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	/* Why? */
	return -EINVAL;
}

static ssize_t lunix_chrdev_read(struct file *filp, char __user *usrbuf, size_t cnt, loff_t *f_pos)
{
	ssize_t ret, rem;

	struct lunix_sensor_struct *sensor;
	struct lunix_chrdev_state_struct *state;

	state = filp->private_data;
	WARN_ON(!state);

	sensor = state->sensor;
	WARN_ON(!sensor);

	debug("read_entering\n");

	/* Lock? */
	if (down_interruptible(&state->lock)){
		return -ERESTARTSYS;
	}

	/*
	 * If the cached character device state needs to be
	 * updated by actual sensor data (i.e. we need to report
	 * on a "fresh" measurement, do so
	 */
	if (*f_pos == 0) {
		while (lunix_chrdev_state_update(state) == -EAGAIN) {
			/* ? */
			/* The process needs to sleep */
			/* See LDD3, page 153 for a hint */
			up(&state->lock);/*release the lock*/
			if (filp->f_flags & O_NONBLOCK) {
				return -EAGAIN;
			}
			debug("reading: going to sleeep\n");
			if (wait_event_interruptible(sensor->wq, lunix_chrdev_state_needs_refresh(state))) {
				return -ERESTARTSYS;/* signal: tell the fs layer to handle it */
			}
			/* otherwise loop, but first reacquire the lock */
			if (down_interruptible(&state->lock)) {
				return -ERESTARTSYS;
			}
		}
	}
	/* ok, data is there, trying to read something */

	/* End of file */
	/* ? */
	if (state->buf_lim == 0) {
		ret = 0;
		goto out;
	}	

	/* Determine the number of cached bytes to copy to userspace */
	/* ? */
	if (*f_pos + cnt > state->buf_lim) {
		cnt = state->buf_lim - *f_pos;
	}

	/*copy_to_user returns how many bytes failed to be copied*/
	if (copy_to_user(usrbuf, state->buf_data + *f_pos, cnt)) {
		ret = -EFAULT;
		goto out;
	}

	*f_pos += cnt;
	ret = cnt;

	/* Auto-rewind on EOF mode? */
	/* ? */
	if (*f_pos >= state->buf_lim) {
		*f_pos = 0;
	}
	
	debug("read_leaving\n");
out:
	/* Unlock? */
	up(&state->lock);
	return ret;
}

static int lunix_chrdev_mmap(struct file *filp, struct vm_area_struct *vma)
{
	return -EINVAL;
}

static struct file_operations lunix_chrdev_fops = 
{
        .owner          = THIS_MODULE,
	.open           = lunix_chrdev_open,
	.release        = lunix_chrdev_release,
	.read           = lunix_chrdev_read,
	.unlocked_ioctl = lunix_chrdev_ioctl,
	.mmap           = lunix_chrdev_mmap
};

int lunix_chrdev_init(void)
{
	/*
	 * Register the character device with the kernel, asking for
	 * a range of minor numbers (number of sensors * 8 measurements / sensor)
	 * beginning with LINUX_CHRDEV_MAJOR:0
	 */
	int ret;
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
	
	debug("initializing character device\n");
	cdev_init(&lunix_chrdev_cdev, &lunix_chrdev_fops);
	lunix_chrdev_cdev.owner = THIS_MODULE;
	
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	/* ? */
	/* register_chrdev_region? */
	ret = register_chrdev_region(dev_no, lunix_minor_cnt, "lunix");
	//ret = register_chrdev_region(dev_no, lunix_sensor_cnt*3, "lunix");
	if (ret < 0) {
		debug("failed to register region, ret = %d\n", ret);
		goto out;
	}	
	/* ? */
	/* cdev_add? */
	ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_minor_cnt);
	//ret = cdev_add(&lunix_chrdev_cdev, dev_no, lunix_sensor_cnt*3);
	if (ret < 0) {
		debug("failed to add character device\n");
		goto out_with_chrdev_region;
	}
	debug("completed successfully\n");
	return 0;

out_with_chrdev_region:

	unregister_chrdev_region(dev_no, lunix_minor_cnt);
out:
	return ret;
}

void lunix_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int lunix_minor_cnt = lunix_sensor_cnt << 3;
		
	debug("entering\n");
	dev_no = MKDEV(LUNIX_CHRDEV_MAJOR, 0);
	cdev_del(&lunix_chrdev_cdev);
	unregister_chrdev_region(dev_no, lunix_minor_cnt);
	debug("leaving\n");
}
