package online.smyhw.localnet.plugins.RSAencryption;

import java.io.UnsupportedEncodingException;

import online.smyhw.localnet.message;
import online.smyhw.localnet.command.cmdManager;
import online.smyhw.localnet.data.DataManager;
import online.smyhw.localnet.data.config;
import online.smyhw.localnet.event.*;
import online.smyhw.localnet.event.EventManager;
import online.smyhw.localnet.lib.CommandFJ;
import online.smyhw.localnet.network.Client_sl;

public class lnp 
{
	public static void plugin_loaded()
	{
		message.info("RSA加密插件加载");
		try 
		{
			cmdManager.add_cmd("rsa", lnp.class.getMethod("cmd", new Class[]{Client_sl.class,String.class}));//注册指令RSA，
			EventManager.AddListener("DataDecrypt", lnp.class.getMethod("lr", new Class[] {DataDecryptEvent.class}));//注册加密事件监听器
			EventManager.AddListener("ConnectServerEvent", lnp.class.getMethod("ConnectServer", new Class[] {ConnectServerEvent.class}));//注册连接至远程服务器事件监听器
			EventManager.AddListener("Client_connect", lnp.class.getMethod("ClientConnect", new Class[] {ClientConnect_Event.class}));//注册远程客户端连接至本机事件监听器
		} 
		catch (Exception e) 
		{
			message.warning("加密插件加载错误!",e);
		}
	}
	
	public static void cmd(Client_sl User,String cmd)
	{
//TODO 如果你需要处理指令的话
	}
	
	//加密或解密数据
	public static void lr(DataDecryptEvent dd)
	{
		message.info("需要加密或解密数据时调用");
		
		//可能需要用到的数据
		int a = dd.Decrypt_type;//该值为0时解密,为1时加密
		byte[] b = dd.input;//需要处理的数据
		byte[] c = dd.output;//处理完成的数据
		//如果处理失败，则将这个值置为true
		//如果是发送数据时加密出错，那么数据将不会被发送
		//如果是接收数据时解密出错，那么该连接将出错并废止
		dd.Error = false;
		
		//TODO 从<dd.input>中取得需要处理的数据 ，<dd.Decrypt_type>表示需要加密还是解密，将处理完的数据放入<dd.output>中即可
		
		dd.output=dd.input;//测试代码
		
		return;
	}
	
	/**
	 * 当本机作为客户端连接至其他服务器时被调用，可以在这里来完成与服务器的握手
	 * @param dd
	 */
	public static void ConnectServer(ConnectServerEvent dd)
	{
		message.info("当本机作为客户端连接至其他服务器时被调用，可以在这里来完成与服务器的握手");
		
	}
	
	/**
	 * 当本机作为服务器，其他客户端连接至此服务器时，此方法将被调用，可以在这里来完成与客户端的握手
	 * @param dd
	 */
	public static void ClientConnect(ClientConnect_Event dd)
	{
		message.info("当本机作为服务器，其他客户端连接至此服务器时，此方法将被调用，可以在这里来完成与客户端的握手");
	}
}
