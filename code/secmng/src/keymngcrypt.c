#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
#include<pthread.h>
#include<string.h>

#include "keymngcryptop.h"
#include "keymng_msg.h"
#include "keymnglog.h"
#include "keymng_shmop.h"

int Usage()
{
    int nSel = -1;
    
    system("clear");    
    printf("\n  /*************************************************************/");
    printf("\n  /*************************************************************/");
    printf("\n  /*     1.密钥查看                                            */");
	printf("\n  /*     2.文件加密                                            */");
	printf("\n  /*     3.文件解密                                            */");
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
	int 	ret = 0;
	int 	nSel = 0;

	int shmkey = 0x0001;
	int maxnode = 10;
	int shmhdl = 0;

	//初始化共享内存
	ret = KeyMng_ShmInit(shmkey, maxnode, &shmhdl);
	if (ret != 0) {
		printf("---------服务器管理程序创建/打开 共享内存失败-----\n");
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "KeyMng_ShmInit() err:%d", ret);
		return 0;
	}

	while (1)
	{
		// 显示菜单  接收用户选择
		nSel = Usage();

		if (nSel != 0) nSel++;
		
		switch (nSel)
		{
			case KeyMng_View:
				//密钥查看
				ret = MngCrypt_View(shmhdl, maxnode);
				break;
			case KeyMng_Encrypt:
				//加密文件
				ret = MngCrypt_Encrypt(shmkey, maxnode);
				break;
			case KeyMng_Decrypt:
				//解密文件
				ret = MngCrypt_Decrypt(shmkey, maxnode);
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
