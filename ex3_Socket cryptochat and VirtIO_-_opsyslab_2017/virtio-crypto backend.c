/*
 * Virtio Crypto Device
 *
 * Implementation of virtio-crypto qemu backend device.
 *
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr> 
 *
 */


#include <qemu/iov.h>
#include "hw/virtio/virtio-serial.h"
#include "hw/virtio/virtio-crypto.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <crypto/cryptodev.h>

static uint32_t get_features(VirtIODevice *vdev, uint32_t features)
{
	DEBUG_IN();
	return features;
}

static void get_config(VirtIODevice *vdev, uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_config(VirtIODevice *vdev, const uint8_t *config_data)
{
	DEBUG_IN();
}

static void set_status(VirtIODevice *vdev, uint8_t status)
{
	DEBUG_IN();
}

static void vser_reset(VirtIODevice *vdev)
{
	DEBUG_IN();
}

static void vq_handle_output(VirtIODevice *vdev, VirtQueue *vq)
{
	VirtQueueElement elem;
	unsigned int *syscall_type;
	int *host_fd;

	DEBUG_IN();

	if (!virtqueue_pop(vq, &elem)) {
		DEBUG("No item to pop from VQ :(");
		return;
	} 

	DEBUG("I have got an item from VQ :)");

	syscall_type = elem.out_sg[0].iov_base;
	switch (*syscall_type) {
	case VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_OPEN");
		/* We get the file descriptor the frondend sends and 
		we return there the result of open syscall */
				
		host_fd = elem.in_sg[0].iov_base;
		*host_fd = open(CRYPTODEV_FILENAME, O_RDWR);
		printf("*host_fd after open= %d\n", *host_fd);

		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_CLOSE");
		/* We get the file descriptor the frondend sends but
		there is no need to send anything back. We simply 
		close the file  */
				
		host_fd = elem.out_sg[1].iov_base;
		printf("*host_fd before close= %d\n", *host_fd);
		close(*host_fd);

		break;

	case VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL:
		DEBUG("VIRTIO_CRYPTO_SYSCALL_TYPE_IOCTL");
		/* First we obtain the adress of the message we need to 
		encrypt and the one we need to write to. */
		unsigned char *output_msg ;
		unsigned char *input_msg ;
		unsigned int *ioctl_cmd;
		long * host_return_val;
		
//		DEBUG("Before Seg faulting memcopy");
/*		*input_msg = elem.in_sg[0].iov_base;*/
/*		memcpy(input_msg, "Host: Welcome to the virtio World!", 35);*/
/*		printf("We say: %s\n", input_msg);*/
				
		host_fd = elem.out_sg[1].iov_base;
		ioctl_cmd = elem.out_sg[2].iov_base;
		printf("Host_fd is: %d\n", *host_fd);
//		printf("Ioctl cmd is: %d\n", *ioctl_cmd);
		switch (*ioctl_cmd) {
		case(CIOCGSESSION):
			DEBUG("Entering CIOCGSESSION backend");
		
			unsigned char *session_key;
			unsigned char *temp1;
			struct session_op *session_op;

/*			output_msg = elem.out_sg[1].iov_base;*/
/*			input_msg = elem.in_sg[1].iov_base;*/

			//read from here
			session_key = elem.out_sg[3].iov_base;
			session_op = elem.in_sg[0].iov_base;
			//write here
			host_return_val = elem.in_sg[1].iov_base;
			//we save the key we recieved so that the frondend gets the right address
			temp1 = session_op->key;
			session_op->key = session_key;
			//syscall
			*host_return_val = ioctl(*host_fd, CIOCGSESSION, session_op);
			session_op->key = temp1;

			DEBUG("Leaving CIOCGSESSION backend");
			break;

		case(CIOCFSESSION):
			DEBUG("Entering CIOCFSESSION backend");
			uint32_t *ses_id;

/*			output_msg = elem.out_sg[1].iov_base;*/
/*			input_msg = elem.in_sg[0].iov_base;*/

			//read from here
			ses_id = elem.out_sg[3].iov_base;
			//write here
			host_return_val = elem.in_sg[0].iov_base;
			// syscall
			*host_return_val = ioctl(*host_fd, CIOCFSESSION, ses_id);

			DEBUG("Leaving CIOCFSESSION backend");
			break;

		case(CIOCCRYPT):
			DEBUG("Entering CIOCCRYPT backend");
			
			struct crypt_op crypt_op;

/*			output_msg = elem.out_sg[1].iov_base;*/
/*			input_msg = elem.in_sg[1].iov_base;*/

			//crypt_op fields
			crypt_op = *((struct crypt_op*) elem.out_sg[3].iov_base);
			crypt_op.src = elem.out_sg[4].iov_base;
			crypt_op.iv = elem.out_sg[5].iov_base;
			crypt_op.dst = elem.in_sg[0].iov_base;
			
			host_return_val = elem.in_sg[1].iov_base;
			*host_return_val = ioctl(*host_fd, CIOCCRYPT, &crypt_op);

			DEBUG("Leaving CIOCCRYPT backend");
			break;

		}
		printf("Guest says: %s\n", output_msg);
		printf("We say: %s\n", input_msg);

		break;

	default:
		DEBUG("Unknown syscall_type");
	}

	virtqueue_push(vq, &elem, 0);
	virtio_notify(vdev, vq);
}

static void virtio_crypto_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);

	DEBUG_IN();

    virtio_init(vdev, "virtio-crypto", 13, 0);
	virtio_add_queue(vdev, 128, vq_handle_output);
}

static void virtio_crypto_unrealize(DeviceState *dev, Error **errp)
{
	DEBUG_IN();
}

static Property virtio_crypto_properties[] = {
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_crypto_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *k = VIRTIO_DEVICE_CLASS(klass);

	DEBUG_IN();
    dc->props = virtio_crypto_properties;
    set_bit(DEVICE_CATEGORY_INPUT, dc->categories);

    k->realize = virtio_crypto_realize;
    k->unrealize = virtio_crypto_unrealize;
    k->get_features = get_features;
    k->get_config = get_config;
    k->set_config = set_config;
    k->set_status = set_status;
    k->reset = vser_reset;
}

static const TypeInfo virtio_crypto_info = {
    .name          = TYPE_VIRTIO_CRYPTO,
    .parent        = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtCrypto),
    .class_init    = virtio_crypto_class_init,
};

static void virtio_crypto_register_types(void)
{
    type_register_static(&virtio_crypto_info);
}

type_init(virtio_crypto_register_types)