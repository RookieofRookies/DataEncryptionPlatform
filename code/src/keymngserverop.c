#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
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
	strcpy(svrInfo->serverip, "127.0.0.1");
	svrInfo->serverport = 8001;
	svrInfo->maxnode = 10;
	svrInfo->shmkey = 0x0001;
	svrInfo->shmhdl = 0;
	
	ret = KeyMng_ShmInit(svrInfo->shmkey, svrInfo->maxnode, &svrInfo->shmhdl);
	if (ret != 0) {
		printf("---------����������/�� �����ڴ�ʧ��-----\n");
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "������ KeyMng_ShmInit() err:%d", ret);
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
	
	// --��� r1 r2 ������Կ  ---> �ɹ���ʧ�� rv
	
	if (strcmp(svrInfo->serverId, msgkeyReq->serverId) != 0) {
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "�ͻ��˷����˴���ķ�����");
		return -1;	
	}
	
	// ��֯ Ӧ��ṹ�� res �� rv r2 clientId serverId  seckeyid
	msgKey_Res.rv = 0; 	//0 �ɹ� 1 ʧ�ܡ�
	strcpy(msgKey_Res.clientId, msgkeyReq->clientId); 
	strcpy(msgKey_Res.serverId, msgkeyReq->serverId); 
	
	// ��������� r2
	for (i = 0; i < 64; i++) {
		msgKey_Res.r2[i] = 'a' + i;			
	}	
	msgKey_Res.seckeyid = seckeyid++;
	
	// ��֯��Կ�ڵ���Ϣ�ṹ��
	for (i = 0; i < 64; i++) {
		nodeSHMInfo.seckey[2*i] = msgkeyReq->r1[i];
		nodeSHMInfo.seckey[2*i+1] = msgKey_Res.r2[i];
	}
	nodeSHMInfo.status = 0;  //0-��Ч 1��Ч
	strcpy(nodeSHMInfo.clientId, msgkeyReq->clientId);
	strcpy(nodeSHMInfo.serverId, msgkeyReq->serverId);
	nodeSHMInfo.seckeyid = msgKey_Res.seckeyid;

	// --д�빲���ڴ档
	ret = KeyMng_ShmWrite(svrInfo->shmhdl, svrInfo->maxnode, &nodeSHMInfo);
	if (ret != 0) {
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "������ KeyMng_ShmWrite() err:%d", ret);
		return ret;	
	}

	// --д���ݿ�

	// ����Ӧ����  ����
	ret = MsgEncode(&msgKey_Res, ID_MsgKey_Res, outData, datalen);
	if (ret != 0) {
		KeyMng_Log(__FILE__, __LINE__, KeyMngLevel[4], ret, "serverAgree MsgEncode() err:%d", ret);	
		return ret;
	}
	
	return 0;	
}


int MngServer_Check(MngServer_Info *svrInfo, MsgKey_Req *msgkeyReq, unsigned char **outData, int *datalen)
{
	
	
	return 0;	
}