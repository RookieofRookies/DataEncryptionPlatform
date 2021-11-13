#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<pthread.h>
#include<string.h>
#include<fcntl.h>
#include<errno.h>

#include "keymngcryptop.h"
#include "keymng_msg.h"
#include "keymnglog.h" 
#include "keymng_shmop.h"
#include "appcryptapi.h"


int MngCrypt_View(int shmhdl, int maxnode)
{
	NodeSHMInfo pNodeInfo;

	char clientId[12];
	char* serverId = "0001";

	int ret = 0;
	int i;

	//获取用户输入
	printf("请输入客户端认证码：\n");
	scanf("%s", clientId);

	//读共享内存
	ret = KeyMng_ShmRead(shmhdl, clientId, serverId,  maxnode, &pNodeInfo);
	if (ret != 0)
	{
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "KeyMng_ShmReade() err:%d", ret);
	}

	//将结果展示
	printf("共享内存中clientId = %s 的密钥：\n", clientId);
	for(i = 0; i < 128; i++){
		printf("%hhc", pNodeInfo.seckey[i]);
	}
	printf("\n");
	getchar();

	return 0;
}

int MngCrypt_Encrypt(int shmkey, int maxnode)
{
	unsigned char	indata[4096];
	int				indatalen = 0;

	unsigned char	outdata[4096];
	int				outdatalen = 4096;
	
	int in_fd;
	int out_fd;
	int ret = 0;

	char infilename[1024];

	char clientId[12];
	char* serverId = "0001";
	
	//读取文件名
	printf("enter filename: \n");
	scanf("%s", infilename);

	//读取客户端id
	printf("请输入客户端认证码：\n");
	scanf("%s", clientId);

	while (1)
	{
		//打开文件
		in_fd = open(infilename, O_RDWR);
		if (in_fd == -1)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "open_in() err:%d", errno);
			break;
		}
		out_fd = open("encrypt_out", O_RDWR | O_CREAT | O_TRUNC, 0664);
		if (out_fd == -1)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "open_out() err:%d", errno);
			break;
		}

		//读取文件
		indatalen = read(in_fd, indata, 4096);
		if (indatalen < 0)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "read() err:%d", errno);
			break;
		}

		//加密
		ret =  AppCryptApi(0, clientId, serverId, indata, indatalen, outdata, &outdatalen, shmkey, maxnode);
		if (ret != 0)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "AppCryptApi() err:%d", ret);
			break;
		}

		//写文件
		ret = write(out_fd, outdata, outdatalen);
		if (ret == -1)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "write() err:%d", errno);
			break;
		}

		printf("加密成功，输出文件：encrypt_out\n");
		getchar();

		return 0;
	}

	printf("加密失败\n");
	getchar();
	
	return ret;
}

int MngCrypt_Decrypt(int shmkey, int maxnode)
{
	unsigned char	indata[4096];
	int				indatalen = 0;

	unsigned char	outdata[4096];
	int				outdatalen = 4096;
	
	int in_fd;
	int out_fd;
	int ret = 0;

	char infilename[1024];

	char clientId[12];
	char* serverId = "0001";
	
	printf("enter filename: \n");
	scanf("%s", infilename);

	//读取客户端id
	printf("请输入客户端认证码：\n");
	scanf("%s", clientId);

	while (1)
	{
		//打开文件
		in_fd = open(infilename, O_RDWR);
		if (in_fd == -1)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "open_in() err:%d", errno);
			break;
		}
		out_fd = open("decrypt_out", O_RDWR | O_CREAT | O_TRUNC, 0664);
		if (out_fd == -1)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "open_out() err:%d", errno);
			break;
		}

		//读取文件
		indatalen = read(in_fd, indata, 4096);
		if (indatalen < 0)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "read() err:%d", errno);
			break;
		}

		//加密
		ret =  AppCryptApi(1, clientId, serverId, indata, indatalen, outdata, &outdatalen, shmkey, maxnode);
		if (ret != 0)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "AppCryptApi() err:%d", ret);
			break;
		}

		//写文件
		ret = write(out_fd, outdata, outdatalen);
		if (ret == -1)
		{
			KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], errno, "write() err:%d", errno);
			break;
		}

		printf("解密成功，输出文件：decrypt_out\n");
		getchar();

		return 0;
	}

	printf("解密失败\n");
	getchar();
	
	return ret;
}