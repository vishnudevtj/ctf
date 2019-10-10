#include <linux/anon_inodes.h>
#include <linux/err.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/ioctl.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/fdtable.h>

#define MAJOR_NUM 100
#define DEVICE_NAME "mod"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("teambi0s <amritabi0s1@gmail.com>");
MODULE_DESCRIPTION("kpwn");

#undef PRINTK
#ifdef KDEBUG
#define PRINTK(fmt, args...) printk(KERN_DEBUG "mod: " fmt, ##args)
#else
#define PRINTK(fmt, args...) /* not debugging: nothing */
#endif

#define BOX_SIZE 0x100
#define ENC_BOX struct encBox

struct encBox {
  size_t key;
  char *ptr;
};

#define IOCTL_NEW_BOX 0x1337
#define IOCTL_UNLOCK_BOX 0x1338
#define IOCTL_LOCK_BOX 0x1339
#define IOCTL_DELETE_BOX 0x133a
#define IOCTL_SET_BOX 0x133b

ssize_t enc_read(struct file *file, char __user *to, size_t size, loff_t *off) {
  ENC_BOX *box;

  PRINTK("enc_read(%px,%px,%x)\n", file, to, size);
  box = file->private_data;
  if (size > BOX_SIZE)
    size = BOX_SIZE;

  if (copy_to_user(to, box->ptr, size))
    return -EFAULT;
  return size;
}

ssize_t enc_write(struct file *file, const char *from, size_t size,
                  loff_t *off) {
  ENC_BOX *box;

  PRINTK("enc_write(%px,%px,%x)\n", file, from, size);
  box = file->private_data;

  if (size > BOX_SIZE)
    size = BOX_SIZE;

  if (copy_from_user(box->ptr, from, size))
    return -EFAULT;
  return size;
}

int enc_release(struct inode *inode, struct file *file) {
  ENC_BOX * box;
  PRINTK("enc_release(%px)\n", file);
  box = (ENC_BOX *)file->private_data;
  kfree(box->ptr);
  kfree(box);
  file->private_data = 0;
  return 0;

}

struct file_operations encBox_fops = {
    .read = enc_read,
    .write = enc_write,
    .release = enc_release,
};

struct file *check_encfile(struct file *encfile) {
  if (!encfile)
    return ERR_PTR(-EBADF);

  if (encfile->f_op != &encBox_fops) {
    fput(encfile);
    return ERR_PTR(-EINVAL);
  }
  return encfile;
}

static struct file *get_encfile(struct file *file) {
  int fd;
  struct file *encfile;
  if (!(fd = (size_t)file->private_data))
    return ERR_PTR(-EBADFD);

  encfile = fget(fd);
  return check_encfile(encfile);
}

static int box_create(struct file *file, char *attr) {
  ENC_BOX *box = 0;
  size_t key;
  ssize_t retval = 0;

  PRINTK("create box:\n");
  box = kzalloc(sizeof(ENC_BOX), GFP_KERNEL);
  if (!box)
    return -ENOMEM;

  if (copy_from_user(&key, (char *)attr, sizeof(size_t))) {
    return -EFAULT;
  }

  box->key = key;
  box->ptr = (char *)kzalloc(BOX_SIZE, GFP_KERNEL);
  if (!box->ptr)
    return -ENOMEM;

  retval = anon_inode_getfd("encBox", &encBox_fops, box, O_RDWR | O_CLOEXEC);
  return retval;
}

static int box_set(struct file *file, char *attr) {
  int fd;
  struct file *f;
  struct file *encfile;

  PRINTK("set box:\n");
  if (copy_from_user(&fd, (char *)attr, sizeof(int)))
    return -EFAULT;

  encfile = fget(fd);
  f = check_encfile(encfile);
  if (IS_ERR(f))
    return -EBADF;

  if (file->private_data) {
    encfile = fget((unsigned int)(unsigned long)file->private_data);
    f = check_encfile(encfile);
    if (!IS_ERR(f))
      fput(f);
    fput(encfile);
  }

  file->private_data = (void *)(unsigned long)fd;
  return 0;
}

static int box_del(struct file *file, char *attr) {
  struct file *encfile;
  ENC_BOX *box;
  ssize_t err = 0;

  PRINTK("delete box:\n");
  encfile = get_encfile(file);
  if (IS_ERR(encfile)) {
    file->private_data = 0;
    return PTR_ERR(encfile);
  }

  box = encfile->private_data;
  kfree(box->ptr);
  kfree(box);
  encfile->private_data = 0;
  file->private_data = 0;
  fput(encfile);

  return err;
}

static int crypt_box(ENC_BOX *box) {

  int i;
  for (i = 0; i < BOX_SIZE / sizeof(size_t); i += 1)
    ((size_t *)box->ptr)[i] ^= box->key;

  return BOX_SIZE;
}

static int box_lock(struct file *file, char *attr) {
  struct file *encfile;
  ENC_BOX *box;

  PRINTK("lock box:\n");
  encfile = get_encfile(file);
  if (IS_ERR(encfile))
    return PTR_ERR(encfile);

  box = encfile->private_data;
  crypt_box(box);
  fput(encfile);
  return 0;
}

static int box_unlock(struct file *file, char *attr) {
  struct file *encfile;
  ENC_BOX *box;
  size_t key;

  PRINTK("unlock box:\n");
    if (copy_from_user(&key, (char *)attr, sizeof(size_t))) {
    return -EFAULT;
  }

  encfile = get_encfile(file);
  if (IS_ERR(encfile))
    return PTR_ERR(encfile);
  
  box = encfile->private_data;
  if (box->key != key)
    return -EINVAL;
  
  crypt_box(box);
  fput(encfile);

  return 0;
}

static long device_ioctl(struct file *file, unsigned int ioctl_num,
                         unsigned long ioctl_param) {

  ssize_t err = 0;

  PRINTK("ioctl : %x\nfile ptr : %px\n", ioctl_num, file);
  switch (ioctl_num) {
  case IOCTL_NEW_BOX:
    err = box_create(file, (char *)ioctl_param);
    break;
  case IOCTL_LOCK_BOX:
    err = box_lock(file, (char *)ioctl_param);
    break;
  case IOCTL_UNLOCK_BOX:
    err = box_unlock(file, (char *)ioctl_param);
    break;
  case IOCTL_DELETE_BOX:
    err = box_del(file, (char *)ioctl_param);
    break;
  case IOCTL_SET_BOX:
    err = box_set(file, (char *)ioctl_param);
    break;
  default:
    err = -EINVAL;
  }
  return err;
}

static int device_open(struct inode *inode, struct file *file) { return 0; }

static int device_release(struct inode *inode, struct file *file) { return 0; }

struct file_operations Fops = {
    .unlocked_ioctl = device_ioctl,
    .open = device_open,
    .release = device_release,
};

int init_module() {
  int ret_val;
  ret_val = register_chrdev(MAJOR_NUM, DEVICE_NAME, &Fops);
  if (ret_val < 0) {
    printk(KERN_ALERT "%s failed with %d\n",
           "Sorry, registering the character device ", ret_val);
    return ret_val;
  }
  PRINTK("module initialized\n");
  return 0;
}

void cleanup_module() {
  unregister_chrdev(MAJOR_NUM, DEVICE_NAME);
  PRINTK("module removed\n");
}
