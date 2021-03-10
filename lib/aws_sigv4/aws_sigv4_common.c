#include <string.h>
#include <stdarg.h>
#include "aws_sigv4_common.h"

int aws_sigv4_empty_str(aws_sigv4_str_t* str)
{
  return (str == NULL || str->data == NULL || str->len == 0) ? 1 : 0;
}

/* reference: http://lxr.nginx.org/source/src/core/ngx_string.c */
static int aws_sigv4_vslprintf(unsigned char* buf, unsigned char* last, const char* fmt, va_list args)
{
  unsigned char*    c_ptr = buf;
  aws_sigv4_str_t*  str;

  while (*fmt && c_ptr < last)
  {
    size_t n_max = last - c_ptr;
    if (*fmt == '%')
    {
      if (*(fmt + 1) == 'V')
      {
        str = va_arg(args, aws_sigv4_str_t *);
        if (aws_sigv4_empty_str(str))
        {
          goto finished;
        }
        size_t cp_len = n_max >= str->len ? str->len : n_max;
        memcpy(c_ptr, str->data, cp_len);
        c_ptr += cp_len;
        fmt += 2;
      }
      else
      {
        *(c_ptr++) = *(fmt++);
      }
    }
    else
    {
      *(c_ptr++) = *(fmt++);
    }
  }
  *c_ptr = '\0';
finished:
  return c_ptr - buf;
}

int aws_sigv4_sprintf(unsigned char* buf, const char* fmt, ...)
{
  int len = 0;
  va_list args;
  va_start(args, fmt);
  len = aws_sigv4_vslprintf(buf, (void*) -1, fmt, args);
  va_end(args);
  return len;
}

int aws_sigv4_snprintf(unsigned char* buf, unsigned int n, const char* fmt, ...)
{
  int len = 0;
  va_list args;
  va_start(args, fmt);
  len = aws_sigv4_vslprintf(buf, buf + n, fmt, args);
  va_end(args);
  return len;
}
