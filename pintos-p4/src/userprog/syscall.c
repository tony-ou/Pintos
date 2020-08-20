#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include "lib/syscall-nr.h"
#include <list.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

static void syscall_handler (struct intr_frame *);

static int sys_write (int handle, void *usrc_, unsigned size);
static int sys_create (const char *file, unsigned size);
static int sys_open (const char *file);
static int sys_read (int handle, void *dst, unsigned size);
static int sys_filesize (int handle);
static int sys_close (int handle);

static int sys_exec (const char *file);
static int sys_wait (tid_t child);

static int sys_seek (int handle, off_t pos);
static int sys_remove (const char *file);
static int sys_tell (int handle);

static void copy_in (void *dst_, const void *usrc_, size_t size);
static bool validate_mem_access(const uint8_t *uddar);

static bool sys_chdir (const char *dir);
static bool sys_mkdir(const char *dir);
static bool sys_readdir(int handle, char *name);
static bool sys_isdir(int fd);
static int sys_inumber(int fd);

typedef struct file_descriptor
{
  int handle;                 /* File handle. */
  struct file *file;          /* File. */
  struct list_elem elem;      /* List element. */
  struct dir *dir;            /* Directory. */
} file_descriptor;

static int arg_cnts[20] = {0,1,1,1,2, 1,1,1,3,3, 2,1,1,2,1, 1,1,2,1,1};
static struct lock write_lock; //lock for sys_write


/* try to find a file_descriptor corresponding to given handle */
static file_descriptor *lookup_fd (int handle)
{
  struct thread *cur = thread_current ();
  struct list_elem *item;
  for (item = list_begin(&cur->fds); item != list_end(&cur->fds); item = list_next(item))
  {
    file_descriptor* fd = list_entry(item, file_descriptor, elem);
    if (fd->handle == handle) return fd;
  }

  return NULL;
}


void syscall_init ()
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&write_lock);
}


/* System call handler. */
static void syscall_handler (struct intr_frame *f)
{
  //...;
  unsigned call_nr;
  struct thread *t = thread_current ();

  int args[3]; // It's 3 because that's the max number of arguments in all syscalls.
  if (!validate_mem_access(f->esp))
    sys_exit(-1);

  copy_in (&call_nr, f->esp, sizeof call_nr); // See the copy_in function implementation below.

  // copy the args (depends on arg_cnt for every syscall).
  // note that if the arg passed is a pointer (e.g. a string),
  // then we just copy the po inter here, and you still need to
  // call 'copy_in_string' on the pointer to pass the string
  // from user space to kernel space

  memset (args, 0, sizeof args);


  copy_in (args, (uint32_t *) f->esp + 1, sizeof *args * arg_cnts[call_nr]);
  int return_val = -1;

  switch (call_nr)
  {
    case SYS_WRITE:
      return_val = sys_write(args[0], args[1], args[2]);
      break;

    case SYS_EXIT:
    {
      sys_exit(args[0]);
      break;
    }

    case SYS_CREATE:
    {
      return_val = sys_create(args[0], args[1]);
      break;
    }

    case SYS_OPEN:
      return_val = sys_open(args[0]);
      break;

    case SYS_READ:
      return_val = sys_read(args[0],args[1],args[2]);
      break;

    case SYS_FILESIZE:
      return_val = sys_filesize(args[0]);
      break;

    case SYS_CLOSE:
      return_val = sys_close(args[0]);
      break;

    case SYS_EXEC:
      return_val = sys_exec(args[0]);
      break;

    case SYS_WAIT:
      return_val = sys_wait(args[0]);
      break;

    case SYS_SEEK:
      return_val = sys_seek(args[0],args[1]);
      break;

    case SYS_REMOVE:
      return_val = sys_remove(args[0]);
      break;

    case SYS_TELL:
      return_val = sys_tell(args[0]);
      break;

    case SYS_CHDIR:
      return_val = sys_chdir(args[0]);
      break;

    case SYS_MKDIR:
      return_val = sys_mkdir(args[0]);
      break;

    case SYS_READDIR:
      return_val = sys_readdir(args[0], args[1]);
      break;

    case SYS_ISDIR:
      return_val = sys_isdir(args[0]);
      break;

    case SYS_INUMBER:
      return_val = sys_inumber(args[0]);
      break;
}

  // return value
  f->eax = return_val;

}

void sys_exit (int status){
  struct thread *t = thread_current ();
  t->child_info->exit_code = status;
  thread_exit();
}

static int sys_create (const char *file, unsigned size){
  if (!validate_mem_access(file)) sys_exit(-1);
  return filesys_create(file, size, FILE_INODE);
}

// return a file discripter
static int sys_open (const char *file){
  if (!validate_mem_access(file)) sys_exit(-1);
  file_descriptor * fd;
  fd = malloc(sizeof(file_descriptor));
  if (fd == NULL) return -1;
  fd->dir = NULL;
  fd->file = NULL;

  struct inode* i;
  lock_acquire(&write_lock);
  i = filesys_open(file);

  if (i != NULL){
    struct thread * t = thread_current();
    if (inode_get_type(i) == DIR_INODE)
    {
      fd->dir = dir_open(i);
    }
    else
      fd->file =file_open(i);
    if (fd->dir != NULL || fd->file != NULL )
    {
      fd ->handle = t->n_file;
      t->n_file ++;
      list_push_back(&t->fds, &fd->elem);
      lock_release(&write_lock);
      return fd->handle;
    }
    else
    {
      inode_close(i);
      free(fd);
      lock_release(&write_lock);
      return -1;
    }
  }else{
    free(fd);
    lock_release(&write_lock);
    return -1;
  }
}

// return the file size of handle
static int sys_filesize(int handle){
  file_descriptor * fd = lookup_fd(handle);
  if (fd == NULL) return -1;
  if(fd->file == NULL) return -1;
  lock_acquire(&write_lock);
  int file_size = file_length(fd->file);
  lock_release(&write_lock);
  return file_size;
}


// return number of bytes ready
static int sys_read (int handle, void *input_dst, unsigned size){
  if  (size == 0) return 0;
  int bytes_read = 0;

  if(!validate_mem_access(input_dst)) sys_exit(-1);

  uint8_t * dst = input_dst;

  if(handle == STDIN_FILENO){
    lock_acquire(&write_lock);
    while(size > 0){
      strlcat(dst, input_getc(),1);
      size --;
      dst ++;
      bytes_read ++;
    }
    lock_release(&write_lock);
    return bytes_read;
  } else {
    file_descriptor *fd = lookup_fd(handle);
    if (fd == NULL) return -1;

    lock_acquire(&write_lock);
    while (size > 0){
      size_t n_to_read = 0;
      if(size < PGSIZE - pg_ofs(dst)) n_to_read = size;
      else n_to_read = PGSIZE - pg_ofs(dst);

      size_t n_read = file_read(fd->file, dst, n_to_read);


      if (n_read < 0) break;
      size -= n_read;
      dst += n_read;
      bytes_read += n_read;

      if(n_read < n_to_read) break;
    }
    lock_release(&write_lock);
    return bytes_read;
  }
}

static int sys_close (int handle){
  file_descriptor * fd = lookup_fd(handle);
  if (fd == NULL) return -1;
  lock_acquire(&write_lock);
  file_close(fd->file);
  dir_close(fd->dir);
  list_remove(&fd->elem);
  lock_release(&write_lock);
  return 0;
}

static int sys_exec (const char *file){
  if(!validate_mem_access(file)) return -1;
  lock_acquire(&write_lock);
  int pid = process_execute(file);
  lock_release(&write_lock);
  if (pid == TID_ERROR)
    return -1;
  return pid;
}

static int sys_wait (tid_t child){
  return process_wait(child);
}

static int sys_seek (int handle, off_t pos){
  file_descriptor * fd = lookup_fd(handle);
  if (fd == NULL) sys_exit(-1);
  file_seek(fd->file,pos);
  return 0;
}

static int sys_remove (const char *file){
  if (!validate_mem_access(file)) sys_exit(-1);
  int ret = filesys_remove(file);
  return ret;
}

static int sys_tell (int handle){
  file_descriptor * fd = lookup_fd(handle);
  if (fd == NULL) sys_exit(-1);
  return file_tell(fd->file);
}


/* Copies a byte from user address USRC to kernel address DST.  USRC must
   be below PHYS_BASE.  Returns true if successful, false if a segfault
   occurred. Unlike the one posted on the p2 website, this one takes two
   arguments: dst, and usrc */

static inline bool get_user (uint8_t *dst, const uint8_t *usrc)
{
  int eax;
  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
       : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
  return eax != 0;
}


/* Copies SIZE bytes from user address USRC to kernel address DST.  Call
   thread_exit() if any of the user accesses are invalid. */

static void copy_in (void *dst_, const void *usrc_, size_t size) {

  uint8_t *dst = dst_;
  const uint8_t *usrc = usrc_;

  for (; size > 0; size--, dst++, usrc++)
    if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc))
      thread_exit ();
}


/* Check if user memory address is vaid */
static bool validate_mem_access(const uint8_t *uaddr)
{
  struct thread *cur = thread_current ();
  if (uaddr == NULL || uaddr >= PHYS_BASE || pagedir_get_page(cur->pagedir, uaddr) == NULL)
    return false;
  else return true;
}

/* Write system call. */
static int sys_write (int handle, void *usrc_, unsigned size)
{
  if (size == 0) return 0;

  const char *usrc = usrc_;
  int written_bytes = 0;
  file_descriptor *fd = NULL;

  //if write to stdout, we don't need to look up file_descriptor
  if (handle != STDOUT_FILENO)
  {
    fd = lookup_fd(handle);
    if (fd == NULL) sys_exit(-1);
  }
  int sizeToWrite = size;

  //validate user source before writing
  if (!validate_mem_access(usrc))
    sys_exit(-1);

  lock_acquire(&write_lock); //only one write at a time
  while (sizeToWrite > 0) {
    off_t retval;
    size_t write_amount;
    size_t remain_buffer = PGSIZE - pg_ofs(usrc);
    write_amount = remain_buffer > sizeToWrite? sizeToWrite : remain_buffer;
    if (!validate_mem_access(usrc))
    {
      lock_release(&write_lock);
      sys_exit(-1);
    }
    if (handle == STDOUT_FILENO)
    {
      putbuf (usrc, write_amount);
      retval = write_amount;
    }
    else
    {
      if (fd->file == NULL){
        written_bytes = -1;
        break;
      }
      retval = file_write (fd->file, usrc, write_amount);
    }

    written_bytes += retval;
    if (retval != write_amount) break;
    sizeToWrite -= retval;
    usrc += retval;
    /* retval < write_amount means we have written past end-of-file, so we break */
  }
  lock_release(&write_lock);

  return written_bytes;

}



static bool sys_chdir (const char *dir)
{
  return filesys_chdir(dir);
}

static bool sys_mkdir(const char *dir)
{
  return filesys_create(dir, 0, DIR_INODE);
}

static bool sys_readdir(int handle, char *name)
{
  file_descriptor *fd = lookup_fd(handle);
  if (fd->dir == NULL) sys_exit(-1);
  return dir_readdir(fd->dir, name);
}

static bool sys_isdir(int handle)
{
  file_descriptor *fd = lookup_fd(handle);
  return fd->dir != NULL;
}

static int sys_inumber(int handle){

  file_descriptor *fd = lookup_fd(handle);
  struct inode *i = NULL;

  if (fd->dir !=NULL)
    i = dir_get_inode(fd->dir);
  else
    i = file_get_inode(fd->file);
  return inode_get_inumber (i);
};
