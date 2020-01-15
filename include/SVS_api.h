/*
ECC公钥长度：64
ECC私钥长度：32
RSA公钥长度：512
RSA私钥长度：1408
ECC签名值长度：64

*/

//渔翁加密卡
//////////////////

#ifndef _SVS_API_H_
#define _SVS_API_H_
#define IN		//输入参数
#define OUT		//输出参数
#define IOUT	//输入输出参数
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
	unsigned int flag;		//0x00:加密  0x01:解密  0x02:签名 0x03:验签(杂凑算法标志)
	unsigned int algo;		//算法标识符: SGD_SM2 SGD_RSA
	unsigned int keybits;		//密钥长度 :256 1024 2048
}UnSymmetricAlgo;				//密钥信息

int InitDevice(	//设备出厂初始化
				IN		unsigned char *pin,	//初始化的设备PIN码
				IN		unsigned int pinlen	//设备PIN码长度
				);


int CheckContent(		//查看密钥容器使用状况
				IN		HANDLE SessionHandle	//会话句柄
				);

int ReleaseContent(	//释放密钥容器
				IN		HANDLE SessionHandle,	//会话句柄
				IN		unsigned int algo,		//密钥容器类型algo==SGD_SM2 or algo=SGD_RSA
				IN		unsigned int keyindex	//指定的密钥容器
				);

int VerifPin(				//校验PIN码
				IN		HANDLE SessionHandle,	//会话句柄
				IN		unsigned char *Pin,		//密码设备安全码
				IN		unsigned int Pinlen		//安全码长度
				);
int ResetMoudles();			//密码设备重启

int CheckRandom();			//随机数发生器检查函数

int CheckDevice();			//密码算法检查函数

int OpenDevice(				//打开设备
				OUT		HANDLE *DeciveHandle,		//设备句柄
				OUT		HANDLE *SessionHandle	//会话句柄
				);

int CloseDevice(				//关闭设备
				IN			HANDLE DeviceHandle,	//设备句柄
				IN			HANDLE SessionHandle	//会话句柄
				);
int GenerateRandom(			//产生随机数
				IN			HANDLE SessionHandle, //会话句柄
				IN			unsigned int randlen, //随机数长度
				OUT		unsigned char *rand	 //随机数缓冲区
				);


int ModifyPin(					//修改密码设备安全码
				IN		HANDLE SessionHandle,	//会话句柄
				IN		unsigned char *OldPin,	//旧安全码
				IN		unsigned int OldLen,		//旧安全码长度
				IN		unsigned char *NewPin,	//新安全码
				IN		unsigned int NewLen		//新安全码长度
				);

int GenerateKeyPair(			//生成密钥对，密钥不存放密码设备内
				IN		HANDLE SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo algo,	//密钥信息
				OUT	unsigned char *pk,		//公钥缓冲区
				IOUT	unsigned int *pklen,		//输入时为公钥缓冲区长度
				OUT	unsigned char *vk,		//私钥缓冲区
				IOUT	unsigned int *vklen		//输入时为私钥缓冲区长度
				);

int AddKeyPair(				//生成密钥对并导出公钥
				IN		HANDLE SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo algo,	//密钥信息
				OUT	unsigned int *keyindex,	//生成的密钥对所在密钥容器序列号
				OUT	unsigned char *pk,		//公钥缓冲区
				IOUT	unsigned int *pklen		//输入时为公钥缓冲区长度，输出时为公钥实际长度
				);

int UpdateKeyPair(			//修改指定密钥容器的密钥对(签名)
				IN		HANDLE SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo algo,	//密钥信息
				IN		unsigned int keyindex,	//修改的密钥容器序列号
				IN		unsigned char *oldpk,	//密钥容器原公钥
				IN		unsigned int oldpklen,	//原公钥长度
				IN		unsigned char *newpk,	//新公钥
				IN		unsigned int newpklen,	//新公钥长度
				IN		unsigned char *newvk,	//新私钥
				IN		unsigned int newvklen	//新私钥长度
				);

int ImportKeyPair(					//导入加密公钥对
				IN		HANDLE SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo algo,		//密钥信息
				IN 	unsigned int keyindex,		//密钥容器序列号
				IN		unsigned char *pk,			//加密公钥
				IN		unsigned int pklen,			//加密公钥长度
				IN		unsigned char *vk,			//加密私钥
				IN		unsigned int vklen,			//加密私钥长度
				IN		unsigned char *snpk,			//签名公钥
				IN		unsigned int snpklen			//签名公钥长度
				);

int ExportPublicKey(			//导出指定密钥容器的明文公钥
				IN		HANDLE	SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo keyalgo,//算法标识
				IN		unsigned int keyindex,	//密钥容器序列号
				IN		unsigned char *pin,		//安全码
				IN		unsigned int pinlen,		//安全码长度
				OUT	unsigned char *pk,		//公钥缓冲区
				IOUT	unsigned int *pklen		//输入时为输出公钥缓冲区长度，输出时为公钥实际长度
				);

int ImportKeyPairEnInfo(			//导入密钥对密文至对应密钥容器
				IN		HANDLE SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo algo,		//密钥信息
				IN		unsigned char *key,			//对称密钥
				IN		unsigned int keylen,			//对称密钥长度
				IN		unsigned char *enkeypair,	//密文密钥对
				IN		unsigned int enlen,			//密文密钥对长度
				IN 	unsigned int keyindex,		//密钥容器序列号
				IN		unsigned char *pin,			//PIN码
				IN		unsigned int pinlen			//PIN码长度
				);

int ExportKeyPairEnInfo(			//导出指定密钥容器的密钥对密文
				IN		HANDLE SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo algo,		//密钥信息
				IN		unsigned int keyindex,		//密钥容器序列号
				IN		unsigned char *key,			//对称密钥
				IN		unsigned int keylen,			//对称密钥长度
				IN		unsigned char *pin,			//PIN码
				IN		unsigned int pinlen,			//PIN码长度
				IN		unsigned char *pk,			//密钥容器公钥
				IN		unsigned int pklen,			//公钥长度
				OUT	unsigned char *enkeypair,	//密文密钥对
				IOUT	unsigned int *enlen			//密文密钥对长度
				);


int DeleteKeyPair(			//删除指定密钥容器的密钥对
				IN		HANDLE SessionHandle,	
				IN		UnSymmetricAlgo algo,	//密钥信息
				IN		unsigned int keyindex,	//修改的密钥容器序列号
				IN		unsigned char *oldpk,	//密钥容器原公钥
				IN		unsigned int oldpklen	//原公钥长度	
				);

int Sign(						//单包签名函数（带SM3）
				IN		HANDLE	SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo algo,	//密钥信息
				IN		unsigned int keyindex,	//密钥容器序列号
				IN		unsigned char *in,			//签名数据缓冲区
				IN		unsigned int inlen,		//签名数据缓冲区长度
				OUT	unsigned char *out,		//签名值缓冲区
				IOUT	unsigned int *outlen		//签名值缓冲区长度，签名输入为out缓冲区长度，输出为签名值实际长度
				);

int SignEx(						//单包直接签名函数（不带SM3）
				IN		HANDLE	SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥信息
				IN		unsigned int keyindex,	//密钥容器序列号
				IN		unsigned char *in,		//签名数据缓冲区
				IN		unsigned int inlen,		//签名数据缓冲区长度
				OUT	unsigned char *out,		//签名值缓冲区
				IOUT	unsigned int *outlen		//签名值缓冲区长度，签名输入为out缓冲区长度，输出为签名值实际长度
				);

int Verify(						//单包验签函数（带SM3）
				IN		HANDLE	SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo algo,	//密钥信息
				IN		unsigned int keyindex,	//密钥容器序列号，当keyindex==0xFF时，使用外部公钥
				IN		unsigned char *pk,		//公钥缓冲区
				IN		unsigned int pklen,		//公钥缓冲区长度
				IN		unsigned char *in,		//签名数据缓冲区
				IN		unsigned int inlen,		//签名数据缓冲区长度
				IN		unsigned char *out,		//签名值缓冲区
				IN		unsigned int outlen		//签名值缓冲区长度
				);

int VerifyEx(						//单包直接验签函数(不带SM3)
				IN		HANDLE	SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo keyalgo,//密钥信息
				IN		unsigned int keyindex,	//密钥容器序列号，当keyindex==0xFF时，使用外部公钥
				IN		unsigned char *pk,		//公钥缓冲区
				IN		unsigned int pklen,		//公钥缓冲区长度
				IN		unsigned char *in,		//签名数据缓冲区
				IN		unsigned int inlen,		//签名数据缓冲区长度
				IN		unsigned char *out,		//签名值缓冲区
				IN		unsigned int outlen		//签名值缓冲区长度
				);

int SignInit(						//多包签名初始化
				IN		HANDLE	SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥信息
				IN		unsigned int keyindex,		//密钥容器序列号
				IN		unsigned char *id,			//签名者ID
				IN		unsigned int idlen,			//签名者ID长度
				IN		unsigned char *in,			//签名数据缓冲区
				IN		unsigned int inlen,			//签名数据缓冲区长度
				OUT	unsigned char *out,			//杂凑值缓冲区
				IOUT	unsigned int *outlen			//杂凑值缓冲区长度，输入为缓冲区长度，输出为杂凑值实际长度		
			);

int SignUpdate(					//多包签名更新
				IN		HANDLE	SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥信息
				IN		unsigned char *hash,			//杂凑中间值
				IN		unsigned int hashlen,		//杂凑中间值长度
				IN		unsigned char *in,			//输入数据
				IN		unsigned int inlen,			//数据长度
				OUT	unsigned char *out,			//杂凑值缓冲区
				IOUT	unsigned int *outlen			//杂凑值缓冲区长度，输入为缓冲区长度，输出为杂凑值实际长度
				);

int SignFinal(						//多包签名结束
				IN		HANDLE	SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥信息
				IN		unsigned int keyindex,		//密钥容器序列号
				IN		unsigned char *hash,			//杂凑中间值
				IN		unsigned int hashlen,		//杂凑中间值长度		
				OUT	unsigned char *signature,	//签名值缓冲区
				IOUT	unsigned int *signlen		//签名值缓冲区长度，输入为缓冲区长度，输出为签名值实际长度
				);
		
int VerifyInit(				//验签初始化
				IN		HANDLE	SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥算法信息	
				IN		unsigned int keyindex,		//密钥容器序列号，当keyindex==0xFF时，使用外部公钥
				IN		unsigned char *pk,			//签名者公钥
				IN		unsigned int pklen,			//
				IN		unsigned char *id,			//签名者ID
				IN		unsigned int idlen,			//签名者ID长度
				IN		unsigned char *in,			//签名数据缓冲区
				IN		unsigned int inlen,			//签名数据缓冲区长度
				OUT	unsigned char *out,			//杂凑值缓冲区
				IOUT	unsigned int *outlen			//杂凑值缓冲区长度，输入为out缓冲区长度，输出为杂凑值实际长度	
				);

int VerifyUpdate(					//多包验签更新
				IN		HANDLE	SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥算法信息
				IN		unsigned char *hash,			//杂凑中间值
				IN		unsigned int hashlen,		//杂凑中间值长度
				IN		unsigned char *in,			//输入数据
				IN		unsigned int inlen,			//数据长度
				OUT	unsigned char *out,			//杂凑值缓冲区
				IOUT	unsigned int *outlen			//杂凑值长度				
				);

int VerifyFinal(						//多包验签结束
				IN		HANDLE	SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥算法信息
				IN		unsigned int keyindex,		//公钥序列号
				IN		unsigned char *pk,			//公钥
				IN		unsigned int pklen,			//公钥长度
				IN		unsigned char *hash,			//杂凑中间值
				IN		unsigned int hashlen,		//杂凑中间值长度
				IN		unsigned char *signature,	//签名值
				IN		unsigned int signlen			//签名值长度
				);


int Crypt(						//加解密函数
				IN		HANDLE	SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo algo,	//密钥信息
				IN		unsigned int keyindex,	//密钥容器序列号，keyindex==0xFF，公私钥外部传入 ,keyindex<16 内部公私钥
				IN		unsigned char *pk,		//公钥缓冲区，当keyindex==0xFF时，参数判断
				IN		unsigned int pklen,		//公钥缓冲区长度，当keyindex==0xFF时，参数判断
				IN		unsigned char *vk,		//私钥缓冲区，当keyindex==0xFF时，参数判断
				IN		unsigned int vklen,		//私钥缓冲区长度，当keyindex==0xFF时，参数判断
				IN		unsigned char *indata,	//输入数据缓冲区
				IN		unsigned int inlen,		//输入数据长度
				OUT	unsigned char *outdata,	//输出数据缓冲区
				IOUT	unsigned int *outlen		//输入时为输出数据缓冲区长度，输出时为输出数据实际长度
				);
int Hash(						//杂凑函数
				IN		HANDLE	SessionHandle,	//会话句柄
				IN		unsigned int algo,		//杂凑算法标识
				IN		unsigned int keyindex,
				IN		unsigned char *indata,	//输入数据缓冲区
				IN		unsigned int inlen,		//输入数据缓冲区长度
				OUT	unsigned char *hash,		//输出数据缓冲区
				IOUT	unsigned int *hashlen	//输入时为输出数据缓冲区长度，输出时为输出数据实际长度
				);

int CryptSM1(					//SM1加解密
				IN		HANDLE SessionHandle,	//会话句柄
				IN		unsigned int type,		//0.加密 1.解密
				IN		unsigned char *key,		//密钥
				IN		unsigned int keylen,		//密钥长度为16的整数倍
				IN		unsigned char *in,		//输入数据缓冲区
				IN		unsigned int inlen,		//输入数据缓冲区长度
				OUT	unsigned char *out,		//输出数据缓冲区
				OUT	unsigned int *outlen		//输出数据缓冲区长度
				);
int CryptSM4(					//SM4加解密
				IN		HANDLE SessionHandle,	//会话句柄
				IN		unsigned int type,		//0.加密 1.解密
				IN		unsigned char *key,		//密钥
				IN		unsigned int keylen,		//密钥长度为16的整数倍
				IN		unsigned char *in,		//输入数据缓冲区
				IN		unsigned int inlen,		//输入数据缓冲区长度
				OUT	unsigned char *out,		//输出数据缓冲区
				OUT	unsigned int *outlen		//输出数据缓冲区长度
				);


int AddServerKeyPair(				//生成密钥对并导出公钥(签名密钥对)
				IN		HANDLE SessionHandle,	//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥信息
				OUT	unsigned char *pk,		//公钥缓冲区
				IOUT	unsigned int *pklen		//输入时为公钥缓冲区长度，输出时为公钥实际长度
				);

int ImportServerKeyPair(					//导入加密公钥对
				IN		HANDLE SessionHandle,		//会话句柄
				IN		UnSymmetricAlgo keyalgo,	//密钥信息
				IN		unsigned char *newpk,		//加密公钥
				IN		unsigned int newpklen,		//加密公钥长度
				IN		unsigned char *newvk,		//加密私钥
				IN		unsigned int newvklen,		//加密私钥长度
				IN		unsigned char *snpk,			//签名公钥
				IN		unsigned int snpklen			//签名公钥长度
				);

int InitSM2_CPin(					//修改密码设备安全码///针对KEY管理员
				IN		unsigned char *Pin,	//安全码
				IN		unsigned int PinLen,		//安全码长度
				IN		unsigned int Pinindex,		//u32PinFlag设置0，u32PinIndex设置范围为1-30,（第i号对应加密卡的2*i和2*i+1，奇数为签名密钥，偶数为加密密钥，即对应卡上2-61号密钥）
				IN		unsigned int Pinflag		//pinflag,SM2,0,RSA,1
				);

				
#endif

