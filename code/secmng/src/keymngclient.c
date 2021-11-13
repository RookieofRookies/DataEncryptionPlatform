#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#include "keymngclientop.h"
#include "keymng_msg.h"
#include "keymnglog.h"

int Usage()
{
    int nSel = -1;
    
    system("clear");    
    printf("\n  /*************************************************************/");
    printf("\n  /*************************************************************/");
    printf("\n  /*     1.密钥协商                                            */");
    printf("\n  /*     2.密钥查看                                            */");
	printf("\n  /*     3.文件加密                                            */");
	printf("\n  /*     4.文件解密                                            */");
    printf("\n  /*     0.退出系统                                            */");
    printf("\n  /*************************************************************/");
    printf("\n  /*************************************************************/");
    printf("\n\n  选择:");
    scanf("%d", &nSel);
    while(getchar() != '\n'); //把应用程序io缓冲器的所有的数据 都读走,避免影响下一次 输入
    
    return nSel;
}

int main()
{
	int 				ret = 0;
	int 				nSel = 0;

	srand((unsigned)time(NULL));
	
	MngClient_Info		mngClientInfo;
	memset(&mngClientInfo, 0, sizeof(MngClient_Info));

	// 初始化客户端结构体信息 / 创建、打开共享内存。
	ret = MngClient_InitInfo(&mngClientInfo);
	if (ret != 0)
	{
		printf("func MngClient_InitInfo() err:%d \n ", ret);
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "func MngClient_InitInfo() err:%d", ret);
	}
	
	while (1)
	{
		// 显示菜单  接收用户选择
		nSel = Usage();
		
		switch (nSel)
		{
		case KeyMng_NEWorUPDATE:	
			//密钥协商
			ret = MngClient_Agree(&mngClientInfo);
			break;
		case KeyMng_View:
			//密钥查看
			ret = MngClient_View(&mngClientInfo);
			break;
		case KeyMng_Encrypt:
			//加密文件
			ret = MngClient_Encrypt(&mngClientInfo);
			break;
		case KeyMng_Decrypt:
			//解密文件
			ret = MngClient_Decrypt(&mngClientInfo);
			break;
		case 0:	
			//退出
			return 0;
			
		default :
			printf("选项不支持\n");
			break;
		}
		
		// 结果展示给用户。
		if (ret)
		{
			printf("\n!!!!!!!!!!!!!!!!!!!!ERROR!!!!!!!!!!!!!!!!!!!!");
			printf("\n错误码是：%x\n", ret);
		}
		else
		{
			printf("\n操作成功，ENTER继续\n");
		}	
		getchar();	
	}
	
	return 0;
}
