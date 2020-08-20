#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/cache.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  cache_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void)
{
  free_map_close ();
  cache_flush ();
}

// give this to students

/* Extracts a file name part from *SRCP into PART,
   and updates *SRCP so that the next call will return the next
   file name part.
   Returns 1 if successful, 0 at end of string, -1 for a too-long
   file name part. */
static int
get_next_part (char part[NAME_MAX], const char **srcp)
{
  const char *src = *srcp;
  char *dst = part;

  /* Skip leading slashes.
     If it's all slashes, we're done. */
  while (*src == '/')
    src++;

  if (*src == '\0')
    return 0;


  /* Copy up to NAME_MAX character from SRC to DST.
     Add null terminator. */
  while (*src != '/' && *src != '\0')
    {
      if (dst < part + NAME_MAX)
        *dst++ = *src;
      else
        return -1;
      src++;
    }
  *dst = '\0';

  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

/* Resolves relative or absolute file NAME.
   Returns true if successful, false on failure.
   Stores the directory corresponding to the name into *DIRP,
   and the file name part into BASE_NAME. */

static bool
resolve_name_to_entry (const char *name,
                      struct dir **dirp, char base_name[NAME_MAX + 1])
{
  // get current directory
  struct dir * dir;
  struct dir * wkdir = thread_current()->working_dir;
  // absolute or relative
  if (!wkdir || name[0] == '/'){
    dir = dir_open_root();
  } else {
    dir = dir_reopen(wkdir);
  }
  if (dir == NULL){
    *dirp = NULL;
    base_name[0] = '\0';
    return false;
  }

  // store parts
  char part1[NAME_MAX+1];
  char part2[NAME_MAX+1];

  if (get_next_part(part1, &name) <= 0) goto error;

  while(1){
    int flag = get_next_part(part2, &name);
    if (flag < 0) goto error;
    if (flag == 0) goto done;
    struct inode *in;
    if (!dir_lookup (dir, part1, &in)) goto error;
    dir_close (dir);

    dir = dir_open (in);
    if (dir == NULL) goto error;

    strlcpy (part1, part2, NAME_MAX + 1);
  }

  error:
    *dirp = NULL;
    base_name[0] = '\0';
    dir_close (dir);
    return false;

  done:
    *dirp = dir;
    strlcpy (base_name, part1, NAME_MAX + 1);
    return true;
}


/* Resolves relative or absolute file NAME to an inode.
   Returns an inode if successful, or a null pointer on failure.
   The caller is responsible for closing the returned inode. */
static struct inode *
resolve_name_to_inode (const char *name)
{
  struct inode *i = NULL;
  struct dir *dir;
  char base_name[NAME_MAX + 1];

  const char* pt = name;
  char part[NAME_MAX + 1];
  char next[NAME_MAX + 1];

  if (name[0] == '/' && get_next_part(next, &pt) == 0)
  {
    //return root directory
    return inode_open(ROOT_DIR_SECTOR);
  }
  else
  {
    if (resolve_name_to_entry(name, &dir, base_name))
    {
      dir_lookup(dir, base_name, &i);
      dir_close(dir);
      return i;
    }
    else return NULL;
  }
}



/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool
filesys_create (const char *name, off_t initial_size, enum inode_type type)
{
  struct dir *dir;
  char base_name[NAME_MAX + 1];
  struct inode* i;
  block_sector_t sector;

  if (!resolve_name_to_entry(name,&dir,base_name)) return false;

  if (!free_map_allocate(&sector)) {
    dir_close(dir);
    return false;
  }
  if (type == FILE_INODE)
    i = file_create(sector, initial_size);
  else
    i = dir_create(sector, inode_get_inumber(dir_get_inode(dir)));
  if (i == NULL) goto fail;

  if (!dir_add (dir, base_name, sector))
  {
    inode_remove(i);
    inode_close(i);
    goto fail;
  }


  inode_close(i);
  dir_close(dir);


  return true;

  fail:
    dir_close(dir);
    return false;

}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct inode *
filesys_open (const char *name)
{
  return resolve_name_to_inode(name);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool
filesys_remove (const char *name)
{
  struct dir *dir;
  char base_name[NAME_MAX + 1];
  if (!resolve_name_to_entry(name, &dir, base_name)) return false;

  if (dir_remove(dir, base_name)) {
    dir_close(dir);
    return true;
  }
  else return false;
}

/* Change current directory to NAME.
   Return true if successful, false on failure. */
bool
filesys_chdir (const char *name)
{
  //test if the name is valid
  struct inode *i = resolve_name_to_inode(name);
  struct dir *dir = dir_open(i);
  if (dir == NULL) return false;
  else
  {
    dir_close(thread_current()->working_dir);
    thread_current()->working_dir = dir;
    return true;
  }
}


/* Formats the file system. */
static void
do_format (void)
{
  struct inode *inode;
  printf ("Formatting file system...");

  /* Set up free map. */

  free_map_create ();

  /* Set up root directory. */
  inode = dir_create (ROOT_DIR_SECTOR, ROOT_DIR_SECTOR);

  if (inode == NULL)
    PANIC ("root directory creation failed");
  inode_close (inode);

  free_map_close ();

  printf ("done.\n");
}
