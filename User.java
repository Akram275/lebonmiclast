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
public class User{
  private String username;
  private int UDP; //port udp
  private boolean connected;
  private boolean superuser;
  private ArrayList<Article> products;
  private String IP;
  private Key RSA; //La clé public RSA
  public SecretKey AES; //La clé AES

  public User(String username, int port, String ip, Key k){
    this.username = username;
    this.UDP = port;
    this.connected = true;
    this.products = new ArrayList<Article>();
    this.IP = ip;
    this.RSA = k;
    this.superuser = false;
    //this.keys = new KeyPairGenerator("RSA");
  }

  public String get_username(){
    return this.username;
  }
  public ArrayList<Article> get_products(){
    return this.products;
  }
  public int get_port(){
    return this.UDP;
  }
  public void set_port(int d){
    this.UDP = d;
  }
  public boolean is_connected(){
    return this.connected;
  }
  public void set_connected(boolean b){
    this.connected =b;
  }
  public ArrayList<Article> get_articles(){
    return this.products;
  }
  public String get_ip(){
    return this.IP;
  }
  public void set_ip(String ip){
    this.IP = ip;
  }
  public Key getRSA(){
    return this.RSA;
  }
  public void setRSA(PublicKey k){
    this.RSA = k;
  }
  public void setAES(SecretKey k){
    this.AES = AES;
  }
  public SecretKey getAES(){
    return this.AES;
  }
  public boolean is_superuser(){
    return this.superuser;
  }
  public void set_superuser(){
    this.superuser = true;
  }
}
