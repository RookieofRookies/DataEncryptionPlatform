#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "keymngserverop.h"
#include "keymng_msg.h"
#include "keymnglog.h" 
#include "keymng_shmop.h"

static int	seckeyid = 100;

int MngServer_InitInfo(MngServer_Info *svrInfo)
{
	int ret = 0;
	strcpy(svrInfo->serverId, "0001");
	strcpy(svrInfo->dbuse, "SECMNG");
	strcpy(svrInfo->dbpasswd, "SECMNG");
	strcpy(svrInfo->dbsid, "orcl");
	svrInfo->dbpoolnum = 8;	
	strcpy(svrInfo->serverip, "10.133.29.250");
	svrInfo->serverport = 8001;
	svrInfo->maxnode = 10;
	svrInfo->shmkey = 0x0001;
	svrInfo->shmhdl = 0;
	
	ret = KeyMng_ShmInit(svrInfo->shmkey, svrInfo->maxnode, &svrInfo->shmhdl);
	if (ret != 0) {
		printf("---------服务器创建/打开 共享内存失败-----\n");
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "服务器 KeyMng_ShmInit() err:%d", ret);
		return ret;
	}
	
	return 0;	
}

int MngServer_Agree(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	int ret = 0;
	int i = 0;
	MsgKey_Res msgKey_Res;
	
	NodeSHMInfo nodeSHMInfo;

	//用于生成密钥随机数的数组
	char randkey[] = {'q', 'w', 'e', 'r', 't', 'y', 'u', 'i', 'o', 'p', 
						'a', 's', 'd', 'f', 'g', 'h', 'j', 'k', 'l',
							'z', 'x', 'c', 'v', 'b', 'n', 'm'};
	
	// --结合 r1 r2 生成密钥  ---> 成功、失败 rv
	
	if (strcmp(svrInfo->serverId, msgkeyReq->serverId) != 0) {
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "客户端访问了错误的服务器");
		return -1;	
	}
	
	// 组织 应答结构体 res ： rv r2 clientId serverId  seckeyid
	msgKey_Res.rv = 0; 	//0 成功 1 失败。
	strcpy(msgKey_Res.clientId, msgkeyReq->clientId); 
	strcpy(msgKey_Res.serverId, msgkeyReq->serverId); 
	
	// 生成随机数 r2
	for (i = 0; i < 64; i++) {
		int r = rand() % 26;
		msgKey_Res.r2[i] = randkey[r];		
	}	
	msgKey_Res.seckeyid = seckeyid++;
	
	// 组织密钥节点信息结构体
	for (i = 0; i < 64; i++) {
		nodeSHMInfo.seckey[2*i] = msgkeyReq->r1[i];
		nodeSHMInfo.seckey[2*i+1] = msgKey_Res.r2[i];
	}
	nodeSHMInfo.status = 0;  //0-有效 1无效
	strcpy(nodeSHMInfo.clientId, msgkeyReq->clientId);
	strcpy(nodeSHMInfo.serverId, msgkeyReq->serverId);
	nodeSHMInfo.seckeyid = msgKey_Res.seckeyid;

	// --写入共享内存。
	ret = KeyMng_ShmWrite(svrInfo->shmhdl, svrInfo->maxnode, &nodeSHMInfo);
	if (ret != 0) {
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "服务器 KeyMng_ShmWrite() err:%d", ret);
		return ret;	
	}

	// --写数据库

	// 编码应答报文  传出
	ret = MsgEncode(&msgKey_Res, ID_MsgKey_Res, outData, datalen);
	if (ret != 0) {
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "serverAgree MsgEncode() err:%d", ret);	
		return ret;
	}
	
	return 0;	
}

/*
int MngServer_Check(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	
	
	return 0;	
}
*/