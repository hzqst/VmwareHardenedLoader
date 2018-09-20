#include "cs_driver_mm.h"
#include <fltkernel.h>

// A pool tag for memory allocation
static const ULONG CS_DRIVER_POOL_TAG = 'rdsC';


// A structure to implement realloc()
typedef struct _CS_DRIVER_MEMBLOCK
{
  size_t size;   // A number of bytes allocated
  char data[1];  // An address returned to a caller
} CS_DRIVER_MEMBLOCK;
C_ASSERT(sizeof(CS_DRIVER_MEMBLOCK) == sizeof(void *) * 2);


// free()
static void CAPSTONE_API csdrv_free(void *ptr)
{
  if (ptr)
  {
    ExFreePoolWithTag(CONTAINING_RECORD(ptr, CS_DRIVER_MEMBLOCK, data),
      CS_DRIVER_POOL_TAG);
  }
}

// malloc()
static void * CAPSTONE_API csdrv_malloc(size_t size)
{
  // Disallow zero length allocation because they waste pool header space and,
  // in many cases, indicate a potential validation issue in the calling code.
  NT_ASSERT(size);

  CS_DRIVER_MEMBLOCK *block = (CS_DRIVER_MEMBLOCK *)ExAllocatePoolWithTag(
    NonPagedPoolNx, size + sizeof(CS_DRIVER_MEMBLOCK), CS_DRIVER_POOL_TAG);
  if (!block)
  {
    return NULL;
  }
  block->size = size;
  return block->data;
}

// calloc()
static void * CAPSTONE_API csdrv_calloc(size_t n, size_t size)
{
  size_t total = n * size;

  void *new_ptr = csdrv_malloc(total);
  if (!new_ptr)
  {
    return NULL;
  }

  return RtlFillMemory(new_ptr, total, 0);
}

// realloc()
static void * CAPSTONE_API csdrv_realloc(void *ptr, size_t size)
{
  void *new_ptr = NULL;
  size_t current_size = 0;
  size_t smaller_size = 0;

  if (!ptr)
  {
    return csdrv_malloc(size);
  }

  new_ptr = csdrv_malloc(size);
  if (!new_ptr)
  {
    return NULL;
  }

  current_size = CONTAINING_RECORD(ptr, CS_DRIVER_MEMBLOCK, data)->size;
  smaller_size = (current_size < size) ? current_size : size;
  RtlCopyMemory(new_ptr, ptr, smaller_size);
  csdrv_free(ptr);
  return new_ptr;
}

// vsnprintf(). _vsnprintf() is avaialable for drivers, but it differs from
// vsnprintf() in a return value and when a null-terminater is set.
// csdrv_vsnprintf() takes care of those differences.
#pragma warning(push)
#pragma warning(disable : 28719)  // Banned API Usage : _vsnprintf is a Banned
                                  // API as listed in dontuse.h for security
                                  // purposes.
static int CAPSTONE_API csdrv_vsnprintf(char *buffer, size_t count,
  const char *format, va_list argptr)
{
  int result = _vsnprintf(buffer, count, format, argptr);

  // _vsnprintf() returns -1 when a string is truncated, and returns "count"
  // when an entire string is stored but without '\0' at the end of "buffer".
  // In both cases, null-terminater needs to be added manually.
  if (result == -1 || (size_t)result == count)
  {
    buffer[count - 1] = '\0';
  }
  if (result == -1)
  {
    // In case when -1 is returned, the function has to get and return a number
    // of characters that would have been written. This attempts so by re-tring
    // the same conversion with temp buffer that is most likely big enough to
    // complete formatting and get a number of characters that would have been
    // written.
    char tmp[1024];
    result = _vsnprintf(tmp, RTL_NUMBER_OF(tmp), format, argptr);
    NT_ASSERT(result != -1);
  }

  return result;
}
#pragma warning(pop)

/*
Initializes Capstone dynamic memory management for Windows drivers

@return: CS_ERR_OK on success, or other value on failure.
Refer to cs_err enum for detailed error.

NOTE: cs_driver_init() can be called at IRQL <= DISPATCH_LEVEL.
*/
cs_err CAPSTONE_API cs_driver_mm_init()
{
  KFLOATING_SAVE float_save;
  NTSTATUS status;
  cs_opt_mem setup;
  cs_err err;

  NT_ASSERT(KeGetCurrentIrql() <= DISPATCH_LEVEL);

  // Capstone API may use floating point.
  status = KeSaveFloatingPointState(&float_save);
  if (!NT_SUCCESS(status))
  {
    return CS_ERR_MEM;
  }

  setup.malloc = csdrv_malloc;
  setup.calloc = csdrv_calloc;
  setup.realloc = csdrv_realloc;
  setup.free = csdrv_free;
  setup.vsnprintf = csdrv_vsnprintf;
  err = cs_option(0, CS_OPT_MEM, (size_t)&setup);

  KeRestoreFloatingPointState(&float_save);
  return err;
}
