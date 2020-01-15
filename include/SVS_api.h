/*
ECC��Կ���ȣ�64
ECC˽Կ���ȣ�32
RSA��Կ���ȣ�512
RSA˽Կ���ȣ�1408
ECCǩ��ֵ���ȣ�64

*/

//���̼��ܿ�
//////////////////

#ifndef _SVS_API_H_
#define _SVS_API_H_
#define IN		//�������
#define OUT		//�������
#define IOUT	//�����������
//#define SGD_RSA			0x00010000	
//#define SGD_SM2			0x00020100	
//#define SGD_SM3			0x00000001
//#define SGD_SHA1			0x00000002
//#define SGD_SHA256		0x00000004
//#define SGD_SHA512		0x00000008
#define NOT_USE_KEYINDEX		0xFF

typedef void* HANDLE;

typedef struct UnSymmetricAlgo_st
{
	unsigned int flag;		//0x00:����  0x01:����  0x02:ǩ�� 0x03:��ǩ(�Ӵ��㷨��־)
	unsigned int algo;		//�㷨��ʶ��: SGD_SM2 SGD_RSA
	unsigned int keybits;		//��Կ���� :256 1024 2048
}UnSymmetricAlgo;				//��Կ��Ϣ

int InitDevice(	//�豸������ʼ��
				IN		unsigned char *pin,	//��ʼ�����豸PIN��
				IN		unsigned int pinlen	//�豸PIN�볤��
				);


int CheckContent(		//�鿴��Կ����ʹ��״��
				IN		HANDLE SessionHandle	//�Ự���
				);

int ReleaseContent(	//�ͷ���Կ����
				IN		HANDLE SessionHandle,	//�Ự���
				IN		unsigned int algo,		//��Կ��������algo==SGD_SM2 or algo=SGD_RSA
				IN		unsigned int keyindex	//ָ������Կ����
				);

int VerifPin(				//У��PIN��
				IN		HANDLE SessionHandle,	//�Ự���
				IN		unsigned char *Pin,		//�����豸��ȫ��
				IN		unsigned int Pinlen		//��ȫ�볤��
				);
int ResetMoudles();			//�����豸����

int CheckRandom();			//�������������麯��

int CheckDevice();			//�����㷨��麯��

int OpenDevice(				//���豸
				OUT		HANDLE *DeciveHandle,		//�豸���
				OUT		HANDLE *SessionHandle	//�Ự���
				);

int CloseDevice(				//�ر��豸
				IN			HANDLE DeviceHandle,	//�豸���
				IN			HANDLE SessionHandle	//�Ự���
				);
int GenerateRandom(			//���������
				IN			HANDLE SessionHandle, //�Ự���
				IN			unsigned int randlen, //���������
				OUT		unsigned char *rand	 //�����������
				);


int ModifyPin(					//�޸������豸��ȫ��
				IN		HANDLE SessionHandle,	//�Ự���
				IN		unsigned char *OldPin,	//�ɰ�ȫ��
				IN		unsigned int OldLen,		//�ɰ�ȫ�볤��
				IN		unsigned char *NewPin,	//�°�ȫ��
				IN		unsigned int NewLen		//�°�ȫ�볤��
				);

int GenerateKeyPair(			//������Կ�ԣ���Կ����������豸��
				IN		HANDLE SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo algo,	//��Կ��Ϣ
				OUT	unsigned char *pk,		//��Կ������
				IOUT	unsigned int *pklen,		//����ʱΪ��Կ����������
				OUT	unsigned char *vk,		//˽Կ������
				IOUT	unsigned int *vklen		//����ʱΪ˽Կ����������
				);

int AddKeyPair(				//������Կ�Բ�������Կ
				IN		HANDLE SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo algo,	//��Կ��Ϣ
				OUT	unsigned int *keyindex,	//���ɵ���Կ��������Կ�������к�
				OUT	unsigned char *pk,		//��Կ������
				IOUT	unsigned int *pklen		//����ʱΪ��Կ���������ȣ����ʱΪ��Կʵ�ʳ���
				);

int UpdateKeyPair(			//�޸�ָ����Կ��������Կ��(ǩ��)
				IN		HANDLE SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo algo,	//��Կ��Ϣ
				IN		unsigned int keyindex,	//�޸ĵ���Կ�������к�
				IN		unsigned char *oldpk,	//��Կ����ԭ��Կ
				IN		unsigned int oldpklen,	//ԭ��Կ����
				IN		unsigned char *newpk,	//�¹�Կ
				IN		unsigned int newpklen,	//�¹�Կ����
				IN		unsigned char *newvk,	//��˽Կ
				IN		unsigned int newvklen	//��˽Կ����
				);

int ImportKeyPair(					//������ܹ�Կ��
				IN		HANDLE SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo algo,		//��Կ��Ϣ
				IN 	unsigned int keyindex,		//��Կ�������к�
				IN		unsigned char *pk,			//���ܹ�Կ
				IN		unsigned int pklen,			//���ܹ�Կ����
				IN		unsigned char *vk,			//����˽Կ
				IN		unsigned int vklen,			//����˽Կ����
				IN		unsigned char *snpk,			//ǩ����Կ
				IN		unsigned int snpklen			//ǩ����Կ����
				);

int ExportPublicKey(			//����ָ����Կ���������Ĺ�Կ
				IN		HANDLE	SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo keyalgo,//�㷨��ʶ
				IN		unsigned int keyindex,	//��Կ�������к�
				IN		unsigned char *pin,		//��ȫ��
				IN		unsigned int pinlen,		//��ȫ�볤��
				OUT	unsigned char *pk,		//��Կ������
				IOUT	unsigned int *pklen		//����ʱΪ�����Կ���������ȣ����ʱΪ��Կʵ�ʳ���
				);

int ImportKeyPairEnInfo(			//������Կ����������Ӧ��Կ����
				IN		HANDLE SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo algo,		//��Կ��Ϣ
				IN		unsigned char *key,			//�Գ���Կ
				IN		unsigned int keylen,			//�Գ���Կ����
				IN		unsigned char *enkeypair,	//������Կ��
				IN		unsigned int enlen,			//������Կ�Գ���
				IN 	unsigned int keyindex,		//��Կ�������к�
				IN		unsigned char *pin,			//PIN��
				IN		unsigned int pinlen			//PIN�볤��
				);

int ExportKeyPairEnInfo(			//����ָ����Կ��������Կ������
				IN		HANDLE SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo algo,		//��Կ��Ϣ
				IN		unsigned int keyindex,		//��Կ�������к�
				IN		unsigned char *key,			//�Գ���Կ
				IN		unsigned int keylen,			//�Գ���Կ����
				IN		unsigned char *pin,			//PIN��
				IN		unsigned int pinlen,			//PIN�볤��
				IN		unsigned char *pk,			//��Կ������Կ
				IN		unsigned int pklen,			//��Կ����
				OUT	unsigned char *enkeypair,	//������Կ��
				IOUT	unsigned int *enlen			//������Կ�Գ���
				);


int DeleteKeyPair(			//ɾ��ָ����Կ��������Կ��
				IN		HANDLE SessionHandle,	
				IN		UnSymmetricAlgo algo,	//��Կ��Ϣ
				IN		unsigned int keyindex,	//�޸ĵ���Կ�������к�
				IN		unsigned char *oldpk,	//��Կ����ԭ��Կ
				IN		unsigned int oldpklen	//ԭ��Կ����	
				);

int Sign(						//����ǩ����������SM3��
				IN		HANDLE	SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo algo,	//��Կ��Ϣ
				IN		unsigned int keyindex,	//��Կ�������к�
				IN		unsigned char *in,			//ǩ�����ݻ�����
				IN		unsigned int inlen,		//ǩ�����ݻ���������
				OUT	unsigned char *out,		//ǩ��ֵ������
				IOUT	unsigned int *outlen		//ǩ��ֵ���������ȣ�ǩ������Ϊout���������ȣ����Ϊǩ��ֵʵ�ʳ���
				);

int SignEx(						//����ֱ��ǩ������������SM3��
				IN		HANDLE	SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ��Ϣ
				IN		unsigned int keyindex,	//��Կ�������к�
				IN		unsigned char *in,		//ǩ�����ݻ�����
				IN		unsigned int inlen,		//ǩ�����ݻ���������
				OUT	unsigned char *out,		//ǩ��ֵ������
				IOUT	unsigned int *outlen		//ǩ��ֵ���������ȣ�ǩ������Ϊout���������ȣ����Ϊǩ��ֵʵ�ʳ���
				);

int Verify(						//������ǩ��������SM3��
				IN		HANDLE	SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo algo,	//��Կ��Ϣ
				IN		unsigned int keyindex,	//��Կ�������кţ���keyindex==0xFFʱ��ʹ���ⲿ��Կ
				IN		unsigned char *pk,		//��Կ������
				IN		unsigned int pklen,		//��Կ����������
				IN		unsigned char *in,		//ǩ�����ݻ�����
				IN		unsigned int inlen,		//ǩ�����ݻ���������
				IN		unsigned char *out,		//ǩ��ֵ������
				IN		unsigned int outlen		//ǩ��ֵ����������
				);

int VerifyEx(						//����ֱ����ǩ����(����SM3)
				IN		HANDLE	SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo keyalgo,//��Կ��Ϣ
				IN		unsigned int keyindex,	//��Կ�������кţ���keyindex==0xFFʱ��ʹ���ⲿ��Կ
				IN		unsigned char *pk,		//��Կ������
				IN		unsigned int pklen,		//��Կ����������
				IN		unsigned char *in,		//ǩ�����ݻ�����
				IN		unsigned int inlen,		//ǩ�����ݻ���������
				IN		unsigned char *out,		//ǩ��ֵ������
				IN		unsigned int outlen		//ǩ��ֵ����������
				);

int SignInit(						//���ǩ����ʼ��
				IN		HANDLE	SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ��Ϣ
				IN		unsigned int keyindex,		//��Կ�������к�
				IN		unsigned char *id,			//ǩ����ID
				IN		unsigned int idlen,			//ǩ����ID����
				IN		unsigned char *in,			//ǩ�����ݻ�����
				IN		unsigned int inlen,			//ǩ�����ݻ���������
				OUT	unsigned char *out,			//�Ӵ�ֵ������
				IOUT	unsigned int *outlen			//�Ӵ�ֵ���������ȣ�����Ϊ���������ȣ����Ϊ�Ӵ�ֵʵ�ʳ���		
			);

int SignUpdate(					//���ǩ������
				IN		HANDLE	SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ��Ϣ
				IN		unsigned char *hash,			//�Ӵ��м�ֵ
				IN		unsigned int hashlen,		//�Ӵ��м�ֵ����
				IN		unsigned char *in,			//��������
				IN		unsigned int inlen,			//���ݳ���
				OUT	unsigned char *out,			//�Ӵ�ֵ������
				IOUT	unsigned int *outlen			//�Ӵ�ֵ���������ȣ�����Ϊ���������ȣ����Ϊ�Ӵ�ֵʵ�ʳ���
				);

int SignFinal(						//���ǩ������
				IN		HANDLE	SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ��Ϣ
				IN		unsigned int keyindex,		//��Կ�������к�
				IN		unsigned char *hash,			//�Ӵ��м�ֵ
				IN		unsigned int hashlen,		//�Ӵ��м�ֵ����		
				OUT	unsigned char *signature,	//ǩ��ֵ������
				IOUT	unsigned int *signlen		//ǩ��ֵ���������ȣ�����Ϊ���������ȣ����Ϊǩ��ֵʵ�ʳ���
				);
		
int VerifyInit(				//��ǩ��ʼ��
				IN		HANDLE	SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ�㷨��Ϣ	
				IN		unsigned int keyindex,		//��Կ�������кţ���keyindex==0xFFʱ��ʹ���ⲿ��Կ
				IN		unsigned char *pk,			//ǩ���߹�Կ
				IN		unsigned int pklen,			//
				IN		unsigned char *id,			//ǩ����ID
				IN		unsigned int idlen,			//ǩ����ID����
				IN		unsigned char *in,			//ǩ�����ݻ�����
				IN		unsigned int inlen,			//ǩ�����ݻ���������
				OUT	unsigned char *out,			//�Ӵ�ֵ������
				IOUT	unsigned int *outlen			//�Ӵ�ֵ���������ȣ�����Ϊout���������ȣ����Ϊ�Ӵ�ֵʵ�ʳ���	
				);

int VerifyUpdate(					//�����ǩ����
				IN		HANDLE	SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ�㷨��Ϣ
				IN		unsigned char *hash,			//�Ӵ��м�ֵ
				IN		unsigned int hashlen,		//�Ӵ��м�ֵ����
				IN		unsigned char *in,			//��������
				IN		unsigned int inlen,			//���ݳ���
				OUT	unsigned char *out,			//�Ӵ�ֵ������
				IOUT	unsigned int *outlen			//�Ӵ�ֵ����				
				);

int VerifyFinal(						//�����ǩ����
				IN		HANDLE	SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ�㷨��Ϣ
				IN		unsigned int keyindex,		//��Կ���к�
				IN		unsigned char *pk,			//��Կ
				IN		unsigned int pklen,			//��Կ����
				IN		unsigned char *hash,			//�Ӵ��м�ֵ
				IN		unsigned int hashlen,		//�Ӵ��м�ֵ����
				IN		unsigned char *signature,	//ǩ��ֵ
				IN		unsigned int signlen			//ǩ��ֵ����
				);


int Crypt(						//�ӽ��ܺ���
				IN		HANDLE	SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo algo,	//��Կ��Ϣ
				IN		unsigned int keyindex,	//��Կ�������кţ�keyindex==0xFF����˽Կ�ⲿ���� ,keyindex<16 �ڲ���˽Կ
				IN		unsigned char *pk,		//��Կ����������keyindex==0xFFʱ�������ж�
				IN		unsigned int pklen,		//��Կ���������ȣ���keyindex==0xFFʱ�������ж�
				IN		unsigned char *vk,		//˽Կ����������keyindex==0xFFʱ�������ж�
				IN		unsigned int vklen,		//˽Կ���������ȣ���keyindex==0xFFʱ�������ж�
				IN		unsigned char *indata,	//�������ݻ�����
				IN		unsigned int inlen,		//�������ݳ���
				OUT	unsigned char *outdata,	//������ݻ�����
				IOUT	unsigned int *outlen		//����ʱΪ������ݻ��������ȣ����ʱΪ�������ʵ�ʳ���
				);
int Hash(						//�Ӵպ���
				IN		HANDLE	SessionHandle,	//�Ự���
				IN		unsigned int algo,		//�Ӵ��㷨��ʶ
				IN		unsigned int keyindex,
				IN		unsigned char *indata,	//�������ݻ�����
				IN		unsigned int inlen,		//�������ݻ���������
				OUT	unsigned char *hash,		//������ݻ�����
				IOUT	unsigned int *hashlen	//����ʱΪ������ݻ��������ȣ����ʱΪ�������ʵ�ʳ���
				);

int CryptSM1(					//SM1�ӽ���
				IN		HANDLE SessionHandle,	//�Ự���
				IN		unsigned int type,		//0.���� 1.����
				IN		unsigned char *key,		//��Կ
				IN		unsigned int keylen,		//��Կ����Ϊ16��������
				IN		unsigned char *in,		//�������ݻ�����
				IN		unsigned int inlen,		//�������ݻ���������
				OUT	unsigned char *out,		//������ݻ�����
				OUT	unsigned int *outlen		//������ݻ���������
				);
int CryptSM4(					//SM4�ӽ���
				IN		HANDLE SessionHandle,	//�Ự���
				IN		unsigned int type,		//0.���� 1.����
				IN		unsigned char *key,		//��Կ
				IN		unsigned int keylen,		//��Կ����Ϊ16��������
				IN		unsigned char *in,		//�������ݻ�����
				IN		unsigned int inlen,		//�������ݻ���������
				OUT	unsigned char *out,		//������ݻ�����
				OUT	unsigned int *outlen		//������ݻ���������
				);


int AddServerKeyPair(				//������Կ�Բ�������Կ(ǩ����Կ��)
				IN		HANDLE SessionHandle,	//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ��Ϣ
				OUT	unsigned char *pk,		//��Կ������
				IOUT	unsigned int *pklen		//����ʱΪ��Կ���������ȣ����ʱΪ��Կʵ�ʳ���
				);

int ImportServerKeyPair(					//������ܹ�Կ��
				IN		HANDLE SessionHandle,		//�Ự���
				IN		UnSymmetricAlgo keyalgo,	//��Կ��Ϣ
				IN		unsigned char *newpk,		//���ܹ�Կ
				IN		unsigned int newpklen,		//���ܹ�Կ����
				IN		unsigned char *newvk,		//����˽Կ
				IN		unsigned int newvklen,		//����˽Կ����
				IN		unsigned char *snpk,			//ǩ����Կ
				IN		unsigned int snpklen			//ǩ����Կ����
				);

int InitSM2_CPin(					//�޸������豸��ȫ��///���KEY����Ա
				IN		unsigned char *Pin,	//��ȫ��
				IN		unsigned int PinLen,		//��ȫ�볤��
				IN		unsigned int Pinindex,		//u32PinFlag����0��u32PinIndex���÷�ΧΪ1-30,����i�Ŷ�Ӧ���ܿ���2*i��2*i+1������Ϊǩ����Կ��ż��Ϊ������Կ������Ӧ����2-61����Կ��
				IN		unsigned int Pinflag		//pinflag,SM2,0,RSA,1
				);

				
#endif

