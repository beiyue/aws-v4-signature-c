#include <string.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "aws_sigv4.h"

#define AWS_SIGV4_AUTH_HEADER_NAME            "Authorization"
#define AWS_SIGV4_SIGNING_ALGORITHM           "AWS4-HMAC-SHA256"
#define AWS_SIGV4_HEX_SHA256_LENGTH           SHA256_DIGEST_LENGTH * 2
#define AWS_SIGV4_AUTH_HEADER_MAX_LEN         1024
#define AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN   4096
#define AWS_SIGV4_STRING_TO_SIGN_BUF_LEN      4096
#define AWS_SIGV4_KEY_BUF_LEN                 256


inline aws_sigv4_str_t construct_str2(const unsigned char* cstr)
{
 aws_sigv4_str_t ret = { .data = NULL, .len = 0 };
 if (cstr)
 {
   ret.data = (unsigned char*) cstr;
   ret.len	= strlen(cstr);
 }
 return ret;
}

void get_hexdigest(aws_sigv4_str_t* str_in, aws_sigv4_str_t* hex_out)
{
  static const unsigned char digits[] = "0123456789abcdef";
  unsigned char* c_ptr = hex_out->data;
  for (size_t i = 0; i < str_in->len; i++)
  {
    *(c_ptr++) = digits[(str_in->data[i] & 0xf0) >> 4];
    *(c_ptr++) = digits[str_in->data[i] & 0x0f];
  }
  hex_out->len = str_in->len * 2;
}

void get_hex_sha256(aws_sigv4_str_t* str_in, aws_sigv4_str_t* hex_sha256_out)
{
  unsigned char sha256_buf[SHA256_DIGEST_LENGTH];
  SHA256_CTX ctx;
  SHA256_Init(&ctx);
  SHA256_Update(&ctx, str_in->data, str_in->len);
  SHA256_Final(sha256_buf, &ctx);

  aws_sigv4_str_t sha256_str = { .data = sha256_buf, .len = SHA256_DIGEST_LENGTH };
  get_hexdigest(&sha256_str, hex_sha256_out);
}

void get_signing_key(aws_sigv4_params_t* sigv4_params, aws_sigv4_str_t* signing_key)
{
  unsigned char key_buf[AWS_SIGV4_KEY_BUF_LEN]  = { 0 };
  unsigned char msg_buf[AWS_SIGV4_KEY_BUF_LEN]  = { 0 };
  aws_sigv4_str_t key = { .data = key_buf, .len = 0 };
  aws_sigv4_str_t msg = { .data = msg_buf, .len = 0 };
  /* kDate = HMAC("AWS4" + kSecret, Date) */
  key.len = aws_sigv4_sprintf(key_buf, "AWS4%V", &sigv4_params->secret_access_key);
  /* data in YYYYMMDD format */
  msg.len = aws_sigv4_snprintf(msg_buf, 8, "%V", &sigv4_params->x_amz_date);
  /* get HMAC SHA256 */
  HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
       signing_key->data, &signing_key->len);
  /* kRegion = HMAC(kDate, Region) */
  key.len = aws_sigv4_sprintf(key_buf, "%V", signing_key);
  msg.len = aws_sigv4_sprintf(msg_buf, "%V", &sigv4_params->region);
  HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
       signing_key->data, &signing_key->len);
  /* kService = HMAC(kRegion, Service) */
  key.len = aws_sigv4_sprintf(key_buf, "%V", signing_key);
  msg.len = aws_sigv4_sprintf(msg_buf, "%V", &sigv4_params->service);
  HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
       signing_key->data, &signing_key->len);
  /* kSigning = HMAC(kService, "aws4_request") */
  key.len = aws_sigv4_sprintf(key_buf, "%V", signing_key);
  msg.len = aws_sigv4_sprintf(msg_buf, "aws4_request");
  HMAC(EVP_sha256(), key.data, key.len, msg.data, msg.len,
       signing_key->data, &signing_key->len);
}

void get_credential_scope(aws_sigv4_params_t* sigv4_params,
                          aws_sigv4_str_t* credential_scope)
{
  unsigned char* str = credential_scope->data;
  /* get date in yyyymmdd format */
  str += aws_sigv4_snprintf(str, 8, "%V", &sigv4_params->x_amz_date);
  str += aws_sigv4_sprintf(str, "/%V/%V/aws4_request",
                           &sigv4_params->region, &sigv4_params->service);
  credential_scope->len = str - credential_scope->data;
}

void get_signed_headers(aws_sigv4_params_t* sigv4_params,
                        aws_sigv4_str_t* signed_headers)
{
  /* TODO: Need to support additional headers and header sorting */
  signed_headers->len = aws_sigv4_sprintf(signed_headers->data, "host;x-amz-date;x-amz-security-token");
}

void get_canonical_headers(aws_sigv4_params_t* sigv4_params,
                           aws_sigv4_str_t* canonical_headers)
{
	//  char token[1024] = {0}; 
  //aws_sigv4_str_t v4Token;
  //aws_sigv4_str_t v4date;
  //aws_sigv4_str_t v4content_type;

 // sprintf(token, "x-amz-security-token:%s",g_aws_devma.SessionToken);
  //v4Token = construct_str2(token);
  //v4date = construct_str2(date);
  //v4content_type = construct_str2(content_type);
  /* TODO: Add logic to remove leading and trailing spaces for header values */
	printf("sigv4_params->session_token=%s\n",sigv4_params->session_token);
  canonical_headers->len = aws_sigv4_sprintf(canonical_headers->data,
                                             "host:%V\nx-amz-date:%V\nx-amz-security-token:%V\n",
                                             &sigv4_params->host,
                                             &sigv4_params->x_amz_date,
                                             &sigv4_params->session_token);
}

void get_canonical_request(aws_sigv4_params_t* sigv4_params,
                           aws_sigv4_str_t* canonical_request)
{
  unsigned char* str = canonical_request->data;
  /* TODO: Here we assume the URI and query string have already been encoded.
   *       Add encoding logic in future.
   */
  /* TODO: Need to support sorting on params */
  // str +=  aws_sigv4_sprintf(str, "%V\n%V\n%V\n",
  str +=  aws_sigv4_sprintf(str, "%V\n%V\n\n",
                            &sigv4_params->method,
                            &sigv4_params->uri,
                            &sigv4_params->query_str);

  aws_sigv4_str_t canonical_headers = { .data = str, .len = 0 };
  get_canonical_headers(sigv4_params, &canonical_headers);
  str += canonical_headers.len;
  *(str++) = '\n';

  aws_sigv4_str_t signed_headers = { .data = str, .len = 0 };
  get_signed_headers(sigv4_params, &signed_headers);
  str += signed_headers.len;
  *(str++) = '\n';

  // aws_sigv4_str_t hex_sha256 = { .data = str, .len = 0 };
  // get_hex_sha256(&sigv4_params->payload, &hex_sha256);
  // str += hex_sha256.len;
  char payload[] = "UNSIGNED-PAYLOAD";
  int payloadlen = strlen(payload);
  memcpy(str, payload, payloadlen);
  str += payloadlen;

  canonical_request->len = str - canonical_request->data;
}

void get_string_to_sign(aws_sigv4_str_t* request_date,
                        aws_sigv4_str_t* credential_scope,
                        aws_sigv4_str_t* canonical_request,
                        aws_sigv4_str_t* string_to_sign)
{
  unsigned char* str = string_to_sign->data;
  str +=  aws_sigv4_sprintf(str, "AWS4-HMAC-SHA256\n%V\n%V\n",
                            request_date, credential_scope);

  aws_sigv4_str_t hex_sha256 = { .data = str, .len = 0 };
  get_hex_sha256(canonical_request, &hex_sha256);
  str += hex_sha256.len;

  string_to_sign->len = str - string_to_sign->data;
}

int aws_sigv4_sign(aws_sigv4_params_t* sigv4_params, aws_sigv4_header_t* auth_header)
{
  int rc = AWS_SIGV4_OK;
  if (auth_header == NULL
      || sigv4_params == NULL
      || aws_sigv4_empty_str(&sigv4_params->secret_access_key)
      || aws_sigv4_empty_str(&sigv4_params->access_key_id)
      || aws_sigv4_empty_str(&sigv4_params->method)
      || aws_sigv4_empty_str(&sigv4_params->uri)
      || aws_sigv4_empty_str(&sigv4_params->query_str)
      || aws_sigv4_empty_str(&sigv4_params->host)
      || aws_sigv4_empty_str(&sigv4_params->x_amz_date)
      || aws_sigv4_empty_str(&sigv4_params->region)
      || aws_sigv4_empty_str(&sigv4_params->service)
      || aws_sigv4_empty_str(&sigv4_params->session_token)
      )
  {
    rc = AWS_SIGV4_INVALID_INPUT_ERROR;
    goto err;
  }

  /* TODO: Support custom memory allocator */
  auth_header->value.data = calloc(AWS_SIGV4_AUTH_HEADER_MAX_LEN, sizeof(unsigned char));
  if (auth_header->value.data == NULL)
  {
    rc = AWS_SIGV4_MEMORY_ALLOCATION_ERROR;
    goto err;
  }

  auth_header->name.data  = AWS_SIGV4_AUTH_HEADER_NAME;
  auth_header->name.len   = strlen(AWS_SIGV4_AUTH_HEADER_NAME);

  /* AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/<credential_scope> */
  unsigned char* str = auth_header->value.data;
  str +=  aws_sigv4_sprintf(str, "AWS4-HMAC-SHA256 Credential=%V/",
                            &sigv4_params->access_key_id);

  aws_sigv4_str_t credential_scope = { .data = str, .len = 0 };
  get_credential_scope(sigv4_params, &credential_scope);
  str += credential_scope.len;

  /* SignedHeaders=<signed_headers> */
  str += aws_sigv4_sprintf(str, ", SignedHeaders=", &sigv4_params->access_key_id);
  aws_sigv4_str_t signed_headers = { .data = str, .len = 0 };
  get_signed_headers(sigv4_params, &signed_headers);
  str += signed_headers.len;

  /* Signature=<signature> */
  str += aws_sigv4_sprintf(str, ", Signature=", &sigv4_params->access_key_id);
  /* Task 1: Create a canonical request */
  unsigned char canonical_request_buf[AWS_SIGV4_CANONICAL_REQUEST_BUF_LEN]  = { 0 };
  aws_sigv4_str_t canonical_request = { .data = canonical_request_buf, .len = 0 };
  get_canonical_request(sigv4_params, &canonical_request);
  /* Task 2: Create a string to sign */
  unsigned char string_to_sign_buf[AWS_SIGV4_STRING_TO_SIGN_BUF_LEN]  = { 0 };
  aws_sigv4_str_t string_to_sign = { .data = string_to_sign_buf, .len = 0 };
  get_string_to_sign(&sigv4_params->x_amz_date, &credential_scope,
                     &canonical_request, &string_to_sign);
  /* Task 3: Calculate the signature */
  /* 3.1: Derive signing key */
  unsigned char signing_key_buf[AWS_SIGV4_KEY_BUF_LEN] = { 0 };
  aws_sigv4_str_t signing_key = { .data = signing_key_buf, .len = 0 };
  get_signing_key(sigv4_params, &signing_key);
  /* 3.2: Calculate signature on the string to sign */
  unsigned char signed_msg_buf[HMAC_MAX_MD_CBLOCK] = { 0 };
  aws_sigv4_str_t signed_msg = { .data = signed_msg_buf, .len = 0 };
  /* get HMAC SHA256 */
  HMAC(EVP_sha256(),
       signing_key.data, signing_key.len,
       string_to_sign.data, string_to_sign.len,
       signed_msg.data, &signed_msg.len);
  aws_sigv4_str_t signature = { .data = str, .len = 0 };
  get_hexdigest(&signed_msg, &signature);
  str += signature.len;
  auth_header->value.len = str - auth_header->value.data;
  return rc;
err:
  /* deallocate memory in case of failure */
  if (auth_header && auth_header->value.data)
  {
    free(auth_header->value.data);
    auth_header->value.data = NULL;
  }
  return rc;
}
