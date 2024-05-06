/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2009, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/* Base64 decoding
 */


#include <stdlib.h>
#include <string.h>

#include "curl_base64.h"


/* ---- Base64 Encoding/Decoding Table --- */
static const char table64[]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void decodeQuantum(unsigned char *dest, const char *src)
{
  unsigned int x = 0;
  int i;
  char *found;

  for(i = 0; i < 4; i++) {
    if((found = strchr(table64, src[i])))
      x = (x << 6) + (unsigned int)(found - table64);
    else if(src[i] == '=')
      x = (x << 6);
  }

  dest[2] = (unsigned char)(x & 255);
  x >>= 8;
  dest[1] = (unsigned char)(x & 255);
  x >>= 8;
  dest[0] = (unsigned char)(x & 255);
}

/*
 * Curl_base64_decode()
 *
 * Given a base64 string at src, decode it and return an allocated memory in
 * the *outptr. Returns the length of the decoded data.
 */
size_t Curl_base64_decode(const char *src, unsigned char **outptr)
{
  size_t length = 0;
  size_t equalsTerm = 0;
  size_t i;
  size_t numQuantums;
  unsigned char lastQuantum[3];
  size_t rawlen = 0;
  unsigned char *newstr;

  *outptr = NULL;

  while((src[length] != '=') && src[length])
    length++;
  /* A maximum of two = padding characters is allowed */
  if(src[length] == '=') {
    equalsTerm++;
    if(src[length+equalsTerm] == '=')
      equalsTerm++;
  }
  numQuantums = (length + equalsTerm) / 4;

  /* Don't allocate a buffer if the decoded length is 0 */
  if(numQuantums == 0)
    return 0;

  rawlen = (numQuantums * 3) - equalsTerm;

  /* The buffer must be large enough to make room for the last quantum
  (which may be partially thrown out) and the zero terminator. */
  newstr = malloc(rawlen+4);
  if(!newstr)
    return 0;

  *outptr = newstr;

  /* Decode all but the last quantum (which may not decode to a
  multiple of 3 bytes) */
  for(i = 0; i < numQuantums - 1; i++) {
    decodeQuantum(newstr, src);
    newstr += 3; src += 4;
  }

  /* This final decode may actually read slightly past the end of the buffer
  if the input string is missing pad bytes.  This will almost always be
  harmless. */
  decodeQuantum(lastQuantum, src);
  for(i = 0; i < 3 - equalsTerm; i++)
    newstr[i] = lastQuantum[i];

  newstr[i] = '\0'; /* zero terminate */
  return rawlen;
}
