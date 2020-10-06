package online.smyhw.localnet.plugins.RSA_AES_encryption;

import online.smyhw.localnet.LN;
import online.smyhw.localnet.message;
import online.smyhw.localnet.command.cmdManager;
import online.smyhw.localnet.data.DataManager;
import online.smyhw.localnet.data.DataPack;
import online.smyhw.localnet.data.DocManager;
import online.smyhw.localnet.data.config;
import online.smyhw.localnet.event.*;
import online.smyhw.localnet.lib.Json;
import online.smyhw.localnet.lib.Exception.Json_Parse_Exception;
import online.smyhw.localnet.lib.encryption.AES;
import online.smyhw.localnet.lib.encryption.RSA;
import online.smyhw.localnet.network.Client_sl;

import java.io.File;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

/**
 * 
 * @author eternal_life_end
 *
 */
public class lnp 
{
	static config cfg = new config();
	static boolean fin = false;//是否准备就绪，若没有准备就绪，不会执行任何加密
	static byte[] rsa_key;
	public static void plugin_loaded()
	{
		message.info("RSA_AES加密插件加载");
		try 
		{
			cmdManager.add_cmd("ra", lnp.class.getMethod("cmd", new Class[]{Client_sl.class,String.class}));//注册指令ra，
			EventManager.AddListener("DataDecrypt", lnp.class.getMethod("doEncryption", new Class[] {DataDecryptEvent.class}));//注册加密事件监听器
			EventManager.AddListener("ClientConnect", lnp.class.getMethod("ClientConnectListener", new Class[] {ClientConnect_Event.class}));//注册连接事件
			//注册文档
			String docString = "RSA_AES_encryption文档\n"
					+ "1.配置文件\n"
					+ "  配置文件位置:<./configs/RSA_AES_encryption/config.cfg>\n"
					+ "  样板配置:"
					+ "    keyPath=./configs/RSA_AES_encryption/key.pem   #密钥(公钥或私钥)位置\n"
					+ "    mode=1  \n"
					+ "        #mode=1   主动生成AES密钥并使用本地密钥加密后发送给对方(一般作为客户端,本地密钥为公钥)\n"
					+ "        #mode=2   接受对方发送的AES密钥并使用本地密钥解密(一般作为服务端)"
					+ "2.协议定义\n"
					+ "  根据配置文件中的mode，"
					+ "  mode=1时"
					+ "    {\"aes_key\":\"<生成的AES密钥>\"}\n"
					+ "  此AES密钥为经过RSA加密后再BASE64编码出的String\n"
					+ "  解密步骤应为1.反编码BASE64|2.RSA解密|3.BASE64编码|4.得到String类型的密钥"
					+ "  如果mode=2，则静默接收这段数据包\n"
					+ "  双方在发送/接收这段数据包后，握手阶段结束\n"
					+ "";
			DocManager.setRunTimeDoc(docString,"ra");
		} 
		catch (Exception e) 
		{
			message.warning("RSA_AES加密插件加载错误{ 注册事件错误,请检查插件版本和localnet本体版本是否相容}",e);
		}
		cfg = DataManager.LoadConfig("./configs/RSA_AES_encryption/config.cfg");
		if(cfg.get_String("keyPath", "none") == "none" )
		{message.warning("RSA_AES加密插件加载错误，未检测到密钥路径配置");return;}
		if( !((new File(cfg.get_String("keyPath", "none"))).exists()))
		{
			{message.warning("RSA_AES加密插件加载错误，密钥路径所指文件不存在");return;}
		}
		int mode = cfg.get_int("mode", 1);
		try {
			if(mode == 1 ) 
			{
				rsa_key = RSA.readPublicKey(cfg.get_String("keyPath", "none"));
			}
			else
			{
				rsa_key = RSA.readPrivateKey(cfg.get_String("keyPath", "none"));
			}
		} catch (Exception e) {
			message.warning("RSA_AES加密插件加载错误,密钥加载失败,请检查密钥文件或密钥类型(公钥/私钥)是否正确", e);
			return;
		}
		fin = true;
	}
	
	public static void cmd(Client_sl User,String cmd)
	{
//TODO 如果你需要处理指令的话
	}
	
	//加密或解密数据
	//加密出错数据包不会发，解密出错连接直接断开
	public static void doEncryption(DataDecryptEvent dd)
	{
		switch(cfg.get_int("mode", 1))
		{
		case 1:
		{
			if(dd.Decrypt_type==0 && ((String)dd.cl.GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready")).equals("RE")) 
			{//接收到第一个数据包，协议进入正常状态
				dd.cl.PutTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready", "OK");
				break;
			}
			else if(dd.Decrypt_type==1 && ((String)dd.cl.GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready")).equals("NO"))
			{//在握手没发之前，除了握手包什么都不让发
				try {
					if(Json.Parse(new String(dd.input)).get("aes_key")==null) {
						dd.Error=true;
						return;
					}
					else
					{//如果是我们自己的握手包，放掉
						dd.output=dd.input;
						return;
					}
				} catch (Json_Parse_Exception e) {
					//本地来的包，不应该没法解析
					message.warning("离谱的错误", e);
					dd.Error=true;
					return;
				}
			}
			else if(((String)dd.cl.GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready")).equals("OK")) 
			{//协议进入正常状态
				break;
			}
			else
			{//其他情况，收发都不让
				dd.Error=true;
				return;
			}
//			break;
		}
		case 2:
		{
			if(dd.Decrypt_type==0 && ((String)dd.cl.GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready")).equals("NO")) 
			{//收到包直接放走，去判断是不是握手包
				dd.output=dd.input;
				return;
			}
			else if(dd.Decrypt_type==1 && ((String)dd.cl.GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready")).equals("NO"))
			{//在收到握手包之前，什么都不能发
				dd.Error=true;
				return;
			}
			else if(((String)dd.cl.GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready")).equals("OK")) 
			{//协议进入正常状态
				break;
			}
			else 
			{//其他情况，收发都不让
				dd.Error=true;
				return;
			}
//			break;
		}
		}

		
		String aes_key = (String) dd.cl.GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "aes_key");
//		message.info("需要加密或解密数据时调用");
		
		//可能需要用到的数据
		int a = dd.Decrypt_type;//该值为0时解密,为1时加密
		byte[] b = dd.input;//需要处理的数据
		byte[] c = dd.output;//处理完成的数据
		//如果处理失败，则将这个值置为true
		//如果是发送数据时加密出错，那么数据将不会被发送
		//如果是接收数据时解密出错，那么该连接将出错并废止
		dd.Error = false;
		
		if(a==1)
		{
			try 
			{
				dd.output = AES.encryption(b, aes_key.getBytes());
			} catch (Exception e) {
				message.warning("RSA_AES加密插件加密数据发生异常", e);
				dd.Error = true;
			}
		}
		else
		{
			try 
			{
				dd.output = AES.decryption(b, aes_key.getBytes());
			} catch (Exception e) {
				message.warning("RSA_AES加密插件解密数据发生异常", e);
				dd.Error = true;
			}
		}
		
		return;
	}
	
	/**
	 * 握手</br>
	 * 目的是获取AES密钥
	 * @param dd
	 * @throws InterruptedException 
	 */
	public static void ClientConnectListener(ClientConnect_Event dd)
	{
		if(!dd.getClient().protocolType.equals("localnetTCP")) {return;}//如果终端类型不是"localnetTCP"，则跳过
		if(!fin) 
		{
			dd.setCancel(); 
			message.warning("RSA_AES_encryption加密插件尚未初始化完成或已经出错，将禁止客户端连接"); 
		}
		dd.getClient().PutTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready", "NO");
		DataPack dp = new DataPack();
		switch(cfg.get_int("mode", 1))
		{
		case 1:
		{//主动生成AES密钥并使用本地密钥加密后发送给对方
			//生成AES密钥
			byte[] get_aes_key = new byte[128];
			( new SecureRandom()).nextBytes(get_aes_key);
			String fin_key = Base64.getEncoder().encodeToString(get_aes_key).substring(0, 16);
			message.info("生成aes密钥:"+fin_key);
			//密钥数据包
			try 
			{
				byte[] rsa_aes_key = RSA.encryption(Base64.getDecoder().decode(fin_key),rsa_key);
				dp.add("aes_key", Base64.getEncoder().encodeToString(rsa_aes_key));
			} 
			catch (Exception e)
			{
				message.warning("[RSA_AES]加密AES密钥时出错,断开连接", e);
				dd.setCancel();
				return;
			}
			dd.getClient().PutTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "aes_key", fin_key);
			dd.getClient().sendData(dp);
			dd.getClient().PutTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready", "RE");//进入准备状态，等服务器发第一个包过来
			while(true)
			{//等待服务端发第一个包过来,这里是为了卡住这个事件，等服务器第一个包发过来之后，再结束这个事件，以便发送localnet握手包
				try {Thread.sleep(1000);} 
				catch (InterruptedException e) {message.warning("[RSA_AES_encryption]一个Client_sl线程在握手时被结束线程", e);}
				if(dd.getClient().GetTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready").equals("OK"))
				{
					break;
				}
			}
			return;
		}
		case 2:
		{//接受对方发送的AES密钥并使用本地密钥解密
			int time_out = 0;
			while(true) 
			{
				time_out++;
				if(time_out>10) 
				{//超时,防止卡住事件总线
					dd.setCancel();
					return;
				}
				for(DataPack i :dd.getClient().reReadyMsg)
				{
					if(i.getValue("aes_key")==null) 
					{
						continue;
					}
					else 
					{
						dd.getClient().reReadyMsg.remove(i);
						String re_aes_key =  i.getValue("aes_key");
						byte[] b_key = Base64.getDecoder().decode(re_aes_key);//BASE64反编码
						byte[] re_rsa_key;
						try 
						{//RSA解密
							re_rsa_key = RSA.decryption(b_key, rsa_key);
						}
						catch (Exception e)
						{
							message.warning("[RSA_AES]解密AES密钥时出错,断开连接", e);
							dd.setCancel();
							return;
						}
						String aes_key = Base64.getEncoder().encodeToString(re_rsa_key);//BASE重编码
						dd.getClient().PutTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "aes_key",aes_key );
						message.info("获得AES密钥<"+aes_key+">");
						dd.getClient().PutTempClientData("online.smyhw.localnet.plugins.RSA_AES_encryption", "ready", "OK");
						return;
					}
				}
				try {Thread.sleep(1000);} 
				catch (InterruptedException e) {message.warning("[RSA_AES_encryption]一个Client_sl线程在握手时被结束线程", e);}
			}
		}
		}
	}
}
