import java.io.*;
import java.net.*;
import java.lang.*;
import java.util.*;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.RSAPrivateKey;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

public class ClientUDP{
	ArrayList<User>	contacts; //Liste des locuteurs
	int				udp_listen;
	String			username;
	RSAPrivateKey k;                    //Notre clé RSA privée

	public ClientUDP(int udp_listen, String username){
		this.udp_listen = udp_listen;
		this.username = username;
		contacts = new ArrayList<User>();
	}


	public static String encryptAES(String strToEncrypt, SecretKey secreta){
	 try{
		 SecretKeySpec secret = new SecretKeySpec(secreta.getEncoded(), "AES");
			 Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
			 cipher.init(Cipher.ENCRYPT_MODE, secret);
			 return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes()));
	 }catch(Exception e){System.out.println("erreur de chiffrement aes");e.printStackTrace();}
	 return null;
}


	public static void main(String[] args){
		if (args.length != 2){
			System.out.println("Error occured");
			System.exit(1);
		}
		/*On récupére le port sur lequel on va écouter les Communications*/
		int			udp_int = Integer.parseInt(args[0]);
		String		username = args[1];
		ClientUDP	cl_udp = new ClientUDP(udp_int, username);
		Thread		t = new Thread(new UDPListenThread(cl_udp));
		t.start();   //Lancement du thread d'écoute
		Scanner		sc = new Scanner(System.in);
		String		s;
		User		u = null;
		byte[]		data;

		System.out.println("---------------------Communications de "+cl_udp.username+"-----------");
		try{
			DatagramSocket		dso = new DatagramSocket();
			while (true){
				if (cl_udp.contacts.size() == 0){
					System.out.println("Vous n'avez pour l'instant pas de contacts");
					while (cl_udp.contacts.size() == 0){
						Thread.sleep(1000);
					}
				}
				if (cl_udp.contacts.size() > 0){
					System.out.println("A qui voulez vous envoyer de message ? : ");
					for (int i = 0;i<cl_udp.contacts.size();i++){
						System.out.println(" "+i+") "+cl_udp.contacts.get(i).get_username());
					}
				}
				System.out.print("username : ");
				username = sc.nextLine();
				for (int i = 0; i < cl_udp.contacts.size(); i++){
					if (username.equals(cl_udp.contacts.get(i).get_username())){
						u = cl_udp.contacts.get(i);
					}
				}
				if (u == null){
					System.out.println("Cet utilisateur ne fait pas parti de vos contacts\n");
					continue ;
				}
				//Envoi
				System.out.print("message : ");
				s = sc.nextLine();
				System.out.println(u.AES.getEncoded());
				s = cl_udp.username+"***"+encryptAES(s, u.AES);
				System.out.println("message ciphered = "+cl_udp.username+"***"+s);
				data = s.getBytes();
				InetSocketAddress	ia = new InetSocketAddress(u.get_ip().substring(1),u.get_port());
				DatagramPacket		paquet = new DatagramPacket(data,data.length,ia);
				dso.send(paquet);
				u = null;
			}
		}catch(Exception e){e.printStackTrace();}
	}
}
