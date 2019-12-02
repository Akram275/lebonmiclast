import java.io.*;
import java.net.*;
import java.lang.*;
import java.util.*;
import java.security.*;
import java.lang.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.interfaces.RSAPrivateKey;

public class Client{

//On pourrait fctoriser la lecture d'erreur ?
//						while (!rep.equals("***")){
//							rep = br.readLine();
//							if (!rep.equals("***")){
//								System.out.print("->" + rep + "\n");
//							}
//						}


	public static void main(String args[]){
		try{
			Scanner sc = new Scanner(System.in);
			String username = "-"; //Sera modifiée par la suite car dans SPEAK on suppose qu'elle initialisée
			String username2;
			String ip;
			String domaine;
			/***********************Elements de securité***********************/
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp;
			Key pub;
			String key_pub;
			String key_priv;
			String key_pub_distant;
			PrivateKey pvt;
			Base64.Encoder encoder = Base64.getEncoder();
			/****************************************************************/
			String name;
			boolean connected = false;
			String desc;
			int prix;
			int id;
			String rep = "";
			Thread t = new Thread();
			int port;
			LauncherThread launch = null;
			int udp_listen = 0;
			String cmd;
			Socket so = new Socket("localhost", 4450); //172.28.173.21
			BufferedReader br = new BufferedReader(new InputStreamReader(so.getInputStream()));
			PrintWriter pw = new PrintWriter(new OutputStreamWriter(so.getOutputStream()));
			so.setTcpNoDelay(true);
			//String fst = br.readLine();
			System.out.print("*****************Bienvenu sur le bon mic*******************\n");
			System.out.println(">  : ligne de commande ");
			System.out.println("-> : réponses serveur ");
			while(true){
				System.out.print(">");
				cmd = sc.nextLine();
				//System.out.println(cmd);
				switch(cmd){
					case "SIGNUP" :
						System.out.print("username : ");
						username = sc.nextLine();
						//System.out.println ("username = {" + username + "} + len = " + username.length());

						System.out.print("udp port n° generated : ");
						port = 0;
						try{
							DatagramSocket portsocket = new DatagramSocket();
						  //port = Integer.parseInt(sc.nextLine());
							port = portsocket.getLocalPort();
							portsocket.close();
							System.out.println(port);
						}catch(Exception e){System.out.println("Error while generating port");break;}
						udp_listen = port;
						/****Key generation *********************/
						kpg.initialize(1024);
						kp = kpg.generateKeyPair();
						pub = kp.getPublic();
						pvt = kp.getPrivate();
						//pvt.getModulus();
						key_pub = encoder.encodeToString(pub.getEncoded());
						key_priv = encoder.encodeToString(pvt.getEncoded());
						/****************************************/
						System.out.println("clé RSA bien génrée");
						pw.println(cmd);
						pw.flush();
						pw.println(username);
						pw.flush();
						pw.println(port);
						pw.flush();
						pw.println(key_pub);
						pw.flush();
						pw.print("***\n");
						pw.flush();
						//System.out.println("on est al");
						//System.out.println ("AZPOEIZAPOIEPOZAIEPOZA");
						rep = "";
						while(!rep.equals("***")){

							rep = br.readLine();
							if (rep.equals("OK")){
								connected = true;
								launch = new LauncherThread(udp_listen, username);
								t = new Thread(launch);
								t.start();
								Thread.sleep(500); // le temps que thread se lancer et soit à l'ecoute
								byte[]		data;
								String		mess = key_priv;
								//System.out.println("mess = "+ mess);
								//System.out.println("j'envoie "+mess);
								data = mess.getBytes();
								try{
									DatagramSocket		dso = new DatagramSocket();
									//System.out.println(ip.substring(1));
									InetSocketAddress	ia = new InetSocketAddress("localhost",udp_listen);
									DatagramPacket		paquet = new DatagramPacket(data,data.length,ia);
									dso.send(paquet);
								}catch (Exception e){e.printStackTrace();}
							}
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;

					case "LOGIN" :
						System.out.print("username : ");
						username = sc.nextLine();
						//System.out.println ("username = {" + username + "} + len = " + username.length());
						System.out.print("udp port n° generated: ");
						try{
							DatagramSocket portsoket = new DatagramSocket();
							port = portsoket.getLocalPort();
						  //port = Integer.parseInt(sc.nextLine());
							portsoket.close();
							System.out.println(port);
						}catch(Exception e){System.out.println("Le numéro de port doit étre un numéro ...");break;}
						udp_listen = port;

						/***********************generation de clé **************************/
						kpg.initialize(1024);
						kp = kpg.generateKeyPair();
						pub = kp.getPublic();
						pvt = kp.getPrivate();
						key_pub = encoder.encodeToString(pub.getEncoded());
						key_priv = encoder.encodeToString(pvt.getEncoded());
						/*******************************************************************/
						System.out.println("clé RSA bien génrée");
						pw.println(cmd);
						pw.flush();
						pw.println(username);
						pw.flush();
						pw.println(port);
						pw.flush();
						pw.println(key_pub);
						pw.flush();
						pw.print("***\n");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = br.readLine();
							if (rep.equals("OK")){
								connected = true;
								launch = new LauncherThread(udp_listen, username);
								t = new Thread(launch);
								t.start();
								Thread.sleep(500);
								byte[]		data;
								String		mess = key_priv;
								//System.out.println("j'envoie "+mess);
								data = mess.getBytes();
								try{
									DatagramSocket		dso = new DatagramSocket();
									//System.out.println(ip.substring(1));
									InetSocketAddress	ia = new InetSocketAddress("localhost",udp_listen);
									DatagramPacket		paquet = new DatagramPacket(data,data.length,ia);
									dso.send(paquet);
								}catch (Exception e){e.printStackTrace();}

							}
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;

					case "ADDARTICLE" :
						pw.println(cmd);
						pw.flush();
						System.out.print("domain : ");
						domaine = sc.nextLine();
						pw.println(domaine);
						pw.flush();
						System.out.print("name : ");
						name = sc.nextLine();
						pw.println(name);
						pw.flush();
						System.out.print("price : ");
						prix = 0;
						try{
						  prix = Integer.parseInt(sc.nextLine());
						}catch(Exception e){System.out.println("Le prix est une valeur numérique");}
						pw.println(prix);
						pw.flush();
						System.out.print("desc : ");
						desc = sc.nextLine();
						pw.println(desc);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = br.readLine();
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;

					case "ASKARTICLES" :
						pw.println(cmd);
						pw.flush();
						System.out.print("domain : ");
						domaine = sc.nextLine();
						pw.println(domaine);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = br.readLine();
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;

					case "ASKDOMAIN" :
						pw.println(cmd);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = br.readLine();
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;

					case "ASKMYARTICLES" :
						pw.println(cmd);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = "";
							rep += br.readLine();
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;

					case "LOGOUT" :
						pw.println(cmd);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while(!rep.equals("***")){
							rep = "";
							rep += br.readLine();
							if (rep.equals("OK")){
								connected = false;
								launch.proc.destroy();
							}
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;

					case "DELARTICLE":
						pw.println(cmd);
						pw.flush();
						System.out.print("product id : ");
						id = Integer.parseInt(sc.nextLine());
						pw.println(id);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = br.readLine();
							System.out.print("->" + rep + "\n");
						}
						break;

					case "QUIT" :
						pw.println(cmd);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = br.readLine();
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						if(connected)
						  launch.proc.destroy();
						return;

					case "SPEAK":
						pw.println(cmd);
						pw.flush();
						System.out.print("product id : ");
						id = Integer.parseInt(sc.nextLine());
						pw.println(id);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = br.readLine();
						if(rep.equals("ERROR")){
							while(!rep.equals("***")){
								System.out.print("->" + rep + "\n");
								rep = br.readLine();
							}
							break;
						}
						ip = br.readLine();
						String		port_s = br.readLine();
						username2 = br.readLine();
						key_pub_distant = br.readLine();
						//System.out.println("la clé du gars a qui je veux parler "+key_pub_distant);
						br.readLine(); // Les 3 étoiles
						byte[]		data;
						String		mess = "OK\n"+ip+"\n"+Integer.parseInt(port_s)+"\n"+username2+"\n"+key_pub_distant;
						//System.out.println("j'envoie "+mess);
						data = mess.getBytes();
						try{
							DatagramSocket		dso = new DatagramSocket();
							//System.out.println(ip.substring(1));
							InetSocketAddress	ia = new InetSocketAddress("localhost",udp_listen);
							DatagramPacket		paquet = new DatagramPacket(data,data.length,ia);
							dso.send(paquet);
						}catch (Exception e){e.printStackTrace();}
						//Thread t = new Thread(new ClientUDP(ip, port, username));
						//t.start();
						//Thread t = new Thread(new LauncherThread(udp_listen));
						//t.start();
						//Runtime.getRuntime().exec(command);
						//Runtime.getRuntime().exec("/bin/bash -c ls");
						//Runtime.getRuntime().exec("../../../../../../usr/bin/x-terminal-emulator");
						break;
				  case "ADDDOMAIN" :
						pw.println(cmd);
						pw.flush();
						System.out.print("->name du domaine : ");
						String dom_name = sc.nextLine();
						pw.println(dom_name);
						pw.flush();
						pw.println("***");
						pw.flush();
						rep = "";
						while (!rep.equals("***")){
							rep = br.readLine();
							if (!rep.equals("***")){
								System.out.print("->" + rep + "\n");
							}
						}
						break;
					case "" : //Enter
						break;

					default :
						System.out.println ("UNKNOWN_COMMAND");
						System.out.print("SUPPORTED COMMANDS : ");
						System.out.print("SIGN UP -");
						System.out.print(" LOGIN -");
						System.out.print(" LOGOUT -");
						System.out.print(" ASKDOMAIN -");
						System.out.print(" ASKARTICLES -");
						System.out.print(" ASKMYARTICLES -");
						System.out.print(" ADDDOMAIN -");
						System.out.print(" ADDARTICLE -");
						System.out.print(" DELARTICLE -");
						System.out.print(" SPEAK \n");
						break;
				}
			}
		}catch(Exception e){e.printStackTrace();}

	}

}
