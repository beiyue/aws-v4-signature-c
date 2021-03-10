#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <curl/curl.h>
#include "aws_sigv4.h"

//this is sample for test

long put(char* url, FILE* fd,  int fsize, struct curl_slist *headers,char* response);
//curl put callback for response 
size_t write_data(char* buffer, size_t size, size_t nmemb, void* userp){
    memcpy(userp, buffer, size * nmemb);
    return nmemb;
}
//curl put callback for send file data
size_t read_data(char* buffer, size_t size, size_t nitems, void* instream){
    size_t sizes = fread(buffer, size, nitems, (FILE *)instream); 
    return nitems;
}
//get aws v4 struct
static inline aws_sigv4_str_t construct_str(const unsigned char* cstr)
{
  aws_sigv4_str_t ret = { .data = NULL, .len = 0 };
  if (cstr)
  {
    ret.data = (unsigned char*) cstr;
    ret.len  = strlen(cstr);
  }
  return ret;
}
//get aws v4 date param
int getTime(char* timestr)
{
    time_t timep = time(NULL);
    struct tm* utcTime =gmtime(&timep);
	sprintf(timestr, "%04d%02d%02dT%02d%02d%02dZ", utcTime->tm_year+1900, utcTime->tm_mon+1, utcTime->tm_mday, utcTime->tm_hour, utcTime->tm_min, utcTime->tm_sec);
    return 0;
}

int main(int argc, char** argv){
    //**************config your environment**************//
   // char url[150] = "http://xxx.s3.cn-northwest-1.amazonaws.com.cn/xxxx/xxxx.jpeg";
   char url[150] = "http://";
    char url_host[50] = "s3.cn-northwest-1.amazonaws.com.cn";// s3 bucket url 
    char url_request[80] = "s3.cn-northwest-1.amazonaws.com.cn";// s3 bucket endpoint url 
    char target_path[100] = "/<S3-BUCKET-PATH>/myimage.jpg"; // s3 object path
    char aws_secret_access_key[64] ="XXXXXXXXXXXXXXXXXXXXXXXXX";//aws access key
    char aws_access_key_id[32] ="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"; // aws access_key_id
    char *aws_region ="cn-northwest-1";//aws region
    char *aws_service ="s3";   
    char *file_path_local = "./00152212.jpg"; 
	char session_token[1024] = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
    //**************config your environment end**************//
	char response[100000];
    char imageBuffer[100000];
    char time[20];
    FILE* r_file = fopen(file_path_local, "rb"); 
    if (0 == r_file) 
    { 
        printf( "the file %s isnot exit\n",argv[2]); 
        return -1; 
    } 
    fseek(r_file, 0, 2); 
    int file_size = ftell(r_file); 
    rewind(r_file); 

    getTime(time);
    strcat(url, url_request);
    strcat(url, target_path);

    printf("s3 put url   :%s\n", url);
    printf("request date :%s\n", time);
    //aws_v4_Signature code: not support query(aws_sigv4.c(104)) and no get_hex_sha256(payload hash)(aws_sigv4.c(123))
     aws_sigv4_params_t sigv4_params  = {.secret_access_key = construct_str(aws_secret_access_key),
                                        .access_key_id      = construct_str(aws_access_key_id),
                                        .method             = construct_str("PUT"),
                                        .host               = construct_str(url_host),
                                        .x_amz_date         = construct_str(time),
                                        .uri                = construct_str(target_path),
                                        .query_str          = construct_str(" "),
                                        .payload            = construct_str(NULL),
                                        .region             = construct_str(aws_region),
                                        .service            = construct_str(aws_service),
                                        .session_token            = construct_str(session_token)
                                        };
    aws_sigv4_header_t auth_header = {.name = construct_str(NULL), .value=construct_str(NULL) };
    int rc = aws_sigv4_sign(&sigv4_params, &auth_header);
    printf("sigv4        :%s\n",auth_header.value.data);
    printf("*************************\n");
	printf("aws_secret_access_key=%s\n",aws_secret_access_key);
	printf("aws_access_key_id=%s\n",aws_access_key_id);
	printf("url_host=%s\n",url_host);
	printf("target_path=%s\n",target_path);
	printf("url=%s\n",url);
    char request_date[30] = "x-amz-date: ";
    char request_Authorization[200] = "Authorization: ";
    char request_host[100] = "host: ";
	char token[2048] = "x-amz-security-token: ";
	strcat(token,session_token);
    strcat(request_date, time);
    strcat(request_Authorization, auth_header.value.data);
    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "x-amz-content-sha256: UNSIGNED-PAYLOAD");
    headers = curl_slist_append(headers, strcat(request_host, url_host));
    headers = curl_slist_append(headers, request_date);
	headers = curl_slist_append(headers, token);
    headers = curl_slist_append(headers, request_Authorization);
   printf("request_Authorization=%s\n",request_Authorization);
    int status_code = put(url, r_file, file_size, headers, response);// s3 restful api (PUT)
    if ((status_code != CURLE_OK)&&(status_code != 200)) {
		return -1;
	}
    else{

        printf("response code:%d\n", status_code);
        printf("RES          :%s\n", response);
    }
	return 0;
}
//cuel put
long put(char* url, FILE* fd,  int fsize, struct curl_slist *headers,char* response)
{
    CURL *curl;
    curl = curl_easy_init();
    long response_code = 0;
    if (curl)
    { 
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_UPLOAD, 1);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);        //改协议头
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, &read_data);
        curl_easy_setopt(curl, CURLOPT_READDATA, fd);
        curl_easy_setopt(curl, CURLOPT_INFILESIZE, fsize); //上传的字节数
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)response);
        CURLcode ret = curl_easy_perform(curl);                          //执行请求
        if(ret == 0){
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            curl_easy_cleanup(curl); 
            return 0;  
        }
        else{
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
            return response_code;
        }
    }
	else{
        return -1;
	}
}
