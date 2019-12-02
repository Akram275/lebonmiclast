import java.io.*;
import java.net.*;
import java.lang.*;
import java.util.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.spec.SecretKeySpec;
public class UDPListenThread implements Runnable{
	ClientUDP c;

	public UDPListenThread(ClientUDP c){
		this.c = c;
	}

	public String encryptRSA(byte[] plainText, PublicKey publicKey) throws Exception {
		 Cipher encryptCipher = Cipher.getInstance("RSA/ECB/NOPADDING");
		 encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

		 byte[] cipherText = encryptCipher.doFinal(plainText);

		 return Base64.getEncoder().encodeToString(cipherText);
 }

 public static String decryptRSA(String cipherText, PrivateKey privateKey) throws Exception {
			 byte[] bytes = Base64.getDecoder().decode(cipherText);

			 Cipher decriptCipher = Cipher.getInstance("RSA/ECB/NOPADDING");
			 decriptCipher.init(Cipher.DECRYPT_MODE, privateKey);

			 return new String(decriptCipher.doFinal(bytes));
	 }

	 public static String encryptAES(String strToEncrypt, SecretKeySpec secret){
		try{

				Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
				cipher.init(Cipher.ENCRYPT_MODE, secret);
				return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
		}catch(Exception e){System.out.println("erreur de chiffrement aes");}
		return null;
}

public static String decryptAES(String strToDecrypt, SecretKeySpec secret){
		try{

				Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
				cipher.init(Cipher.DECRYPT_MODE, secret);
				return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
		}catch(Exception e){System.out.println("Error de déchiffrement");}
		return null;
}


	User		AddUser(String username, int port, String ip, Key RSA_pub)
	{
		User	u = new User(username, port, ip, RSA_pub);

		this.c.contacts.add(u);
		System.out.println("\n****************************************************");
		System.out.println("*       Un nouveau contact à été ajouté              *");
		System.out.println("*       son username : "+username+"                  *");
		System.out.println("******************************************************");
		return (u);
	}

	User		FindUser(String username, int port, String ip, Key RSA_pub)
	{
		User	u;

		for (int i = 0; i < this.c.contacts.size(); i++){
			u = this.c.contacts.get(i);
			if (username.equals(u.get_username())){
				//user update ? -> refresh eventuel de ip/port/Key ?
				return (u);
			}
		}
		if (port > 0){
			return (AddUser(username, port, ip, RSA_pub));
		}else {
			return (null);
		}
	}

	public void	run(){

		try{
			DatagramSocket dso = new DatagramSocket(this.c.udp_listen);
			byte[] data = new byte[1024];
			DatagramPacket paquet = new DatagramPacket(data,data.length);
			String st;
			boolean flag;
			PublicKey k;
			RSAPrivateKey privRSA;
			User u;
			String cle_chiffree;
			String id_emetteur;
			String id_receveur;
			int port_;
			String[] cnx;
			String[] cnx2;
			String username;
			String ip;
			Base64.Decoder decoder = Base64.getDecoder();
			/*************************Premier paquet = Clé privé RSA*********************/
			dso.receive(paquet);
			st = new String(paquet.getData(), 0, paquet.getLength());
			KeyFactory kf = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(st));
		  privRSA = (RSAPrivateKey)kf.generatePrivate(keySpecPKCS8);
			this.c.k = privRSA;
			/*****************************************************************************/


			while(true){
				flag = false;
				dso.receive(paquet);
				st = new String(paquet.getData(), 0, paquet.getLength());
				cnx = st.split("\n");
				cnx2 = st.split("\\*+\\*+\\*");
				if (cnx.length == 5){//CAS: Client nous envoie SPEAK
					ip = cnx[1].substring(1);
					port_ = Integer.parseInt(cnx[2]);
					username = cnx[3];
					/**********************Clé public du client distant*************************************************/
					//System.out.println("j'ai reçu la clé public "+cnx[4]);
					k = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoder.decode(cnx[4])));  /*
					//////////////////////////////////////////////////////////////////////////////////////////////*/
					if (cnx[0].equals("OK")){ // message de contact bien formate
						//System.out.println("je reçois un retour de speak");
						u = FindUser(username, port_, ip, k); //On aura plus besoin de la clé RSA public
						byte[] data1;
						/**************** Creation de la clé AES *************************/
						KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(128);
            SecretKey secretKey = keyGen.generateKey();
						u.setAES(secretKey);
						/*************************Envoie de la clé*********************/
						byte[] encodedKey = secretKey.getEncoded();
						//String key_sent = Base64.getEncoder().encode(encodedKey);
						//System.out.println("clé envoyé est = "+new String(Base64.getEncoder().encode(encodedKey)));
						cle_chiffree = encryptRSA(Base64.getEncoder().encode(encodedKey), k);
						//System.out.println("clé aes chiffré = "+cle_chiffree);
						String mess = cle_chiffree+"***"+username+"***"+this.c.username;
						data1 = mess.getBytes();
						DatagramSocket		dso1 = new DatagramSocket();
						InetSocketAddress	ia = new InetSocketAddress(ip,port_);
						DatagramPacket		paquet2 = new DatagramPacket(data1,data1.length,ia);
						dso.send(paquet2);

					 continue;
				  }
				}
				/****************************************************************************************/
				else if (cnx2.length == 3){//Connection depuis un client
					//System.out.println("j'ai reçu une demande de connexion d'un autre client");
					username = cnx2[2];
					ip = paquet.getAddress().toString();
					port_ = paquet.getPort();
					System.out.println(port_);
					//System.out.println("decoded key received = "+cnx2[0]);
					String AES_DECHIFFREE = decryptRSA(cnx2[0], privRSA);
					//System.out.println("aes key decrypted = "+AES_DECHIFFREE);
					//byte[] decodedKey = Base64.getDecoder().decode(AES_DECHIFFREE.substring(0));
					SecretKeySpec aes_key = new SecretKeySpec(AES_DECHIFFREE.getBytes(), 0, AES_DECHIFFREE.getBytes().length, "AES");
					//SecretKey aes_key = KeyFactory.getInstance("AES").generatePrivate(new X509EncodedKeySpec(Base64.getDecoder().decode(AES_DECHIFFREE)))
					System.out.println("AES KEY-EXCHANGE SUCCESS");
					u = FindUser(username, port_, ip, null);
					u.setAES(aes_key);
					/**************************************************************************************/
					continue;
				}else if (cnx2.length == 2){ // Cas Client connu (a priori) et message chiffre
					username = cnx2[0];
					u = FindUser(username, 0, null, null); //seuls des contacts avec cle peuvent nous parler
					if(u != null){
						SecretKeySpec k_aes = u.getAES();
						System.out.println(username + ">"+decryptAES(cnx2[1], k_aes));
						continue;
					}
					System.out.println("message reçu d'un user dont la clé est non connue");
					continue;
				}

				else if (cnx2.length == 4 && cnx2[1].equals("CLIENT")
						&& cnx2[2].equals("UDP") && cnx2[3].equals("END")){ //Cas de deconnection
					username = cnx2[0];
					for(int i = 0;i<this.c.contacts.size();i++){
						if(username.equals(this.c.contacts.get(i).get_username())){
							this.c.contacts.remove(i);
						}
					}
				}
			}
		} catch(Exception e){e.printStackTrace();}
	}

}
