/* Network Security And Cryptography Assignment
Made by - Kunal
Roll No. - 2019085
Email - 
2019085@iiitdmj.ac.in 
tulsidasanikunal@gmail.com

File - Client.java
*/

import java.util.*;
import java.net.*;
import java.io.*;

public class Client {

    //Message to be sent and Its binary conversion
    private static String msg, msgb;
    //RSA Input- p, q(two primes) & e(public key)
    private static String p, q, e;
    //RSA private key
    private static String d;
    //n = p*q
    private static String n;
    //
    private static RSA rsa = null;
    //
    private static CustomAES aes = null;
    //AES secret key
    private static String key;
    
    //Server Public Key (e,n)
    //Server Public Key - e
    private static String serverPublicKey;
    //Server Public Key - n
    private static String serverN;

    //Socket Object for Connection
    private static Socket socket = null;
    //DataOutputStream Object to send message to server
    private static DataOutputStream outToServer = null;
    //BufferedReader Object to recieve message from server
    public static BufferedReader inFromServer = null;
    //Scanner Class
    public static Scanner sc = null;

    //Function to Take Message Input from user
    public static void msgInput(){
         
        System.out.print("Message:");
        //Input Message
        msg = sc.nextLine();
        //Convert Message to Binary String
        msgb = strBin.stringToBin(msg);
    }

    //Input Function to take all inputs from user - Secret Key, p, q, e
    public static void input(){        
        
        //Input 16 bit Binary Key
        System.out.print("16 bit Binary Secret Key:");
        key = sc.next();

        //Initialize CustomAES with secret key
        aes = new CustomAES(key);
        
        //Input 1st prime
        System.out.print("1st Prime in Hexadecimal, p: ");
        p = sc.next();
        //Check till prime is atleast 13 byte
        while(p.length()<6){
            System.out.println("ERROR: Prime too small use prime greater than 0xFFFFF (hexadecimal)");
            p = sc.next();
        }
        
        //Input 2nd Prime
        System.out.print("2nd prime in Hexadecimal, q: ");
        q = sc.next();
        //Check till prime is atleast 13 byte
        while(q.length() < 6){
            System.out.print("ERROR: Prime too small use prime greater than 0xFFFFF (hexadecimal)");
            q = sc.next();
        }
        
        //Input Public Key
        System.out.print("Public Key in Hexadecimal, e: ");
        e = sc.next();
        //Initialize RSA Object with p, q, e as Input
        rsa = new RSA(p, q, e);
        //If e is not coprime with phi(n)
        if(rsa.getPrivateKey()== "-1"){
            System.out.println("Invalid set of <p, q, e>");
            System.exit(0);
        }
        //RSA Private Key
        d = rsa.getPrivateKey();
        //RSA n
        n = rsa.getN();

    }

    //Setup Connection with the server
    public static void setupConnection(String address, int port){
        try{
            //Socket Object Intialization to Setup Connection
            socket = new Socket(address, port);
            //outToServer Initialization
            outToServer = new DataOutputStream(socket.getOutputStream());
            //outToServer Initialization
            inFromServer = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            System.out.println("Connected with Server.....");
        }
        catch(Exception e){
            System.out.println(e);
        }
    }

    //Function to request Server Public Key
    public static void requestServerPublicKey() throws Exception{
        try{
            System.out.println("Requested Server Public Key");
            //Send Request to Server
            outToServer.writeBytes("Request For Server Public Key \n");
            //Input Server Public Key recieved from Server e,n
            serverPublicKey = inFromServer.readLine();
            //Extract n
            serverN = serverPublicKey.split(",")[1];
            //Extract e
            serverPublicKey = serverPublicKey.split(",")[0];
            System.out.println("Recieved Server Public Key");           
        }
        catch(Exception e){
            throw e;
        }
    }

    //Function to send Encrypted Message to Server
    public static void sendEncMsgToServer() throws Exception{
        try{
            //Encrypt Secret Key using RSA with server public key
            //Convert Secret Key to Hex String and then Pass to RSA
            String encSecKey = rsa.HexEncrypt(Integer.toHexString(Integer.parseInt(key,2)), serverPublicKey, serverN);
            System.out.println("Encrypted Secret Key in HexaDecimal: "+ encSecKey);

            //Encrypt Message using AES to Get cipher Text
            String cipherText = aes.binStringEncrypt(msgb);
            System.out.println("Cipher Text: "+cipherText);

            //Hash the Message to get the digest
            String digest = HashGenerator.generateCustomMD5(msg);
            System.out.println("Digest: "+digest);

            //Encrypt Hash using RSA with client private key to get Digital Signature
            String sign = rsa.HexEncrypt(digest,d,n);
            System.out.println("Digital Signature: "+sign);

            //String to be sent with Comma (",") seperated values
            String M = cipherText + "," + encSecKey + "," + sign + "," + e + "," + n;
            
            //Send to server
            outToServer.writeBytes(M+"\n");
            System.out.println("Sent to Server");
        }
        catch(Exception e){
            throw e;
        }
    }
    public static void main(String[] args) throws Exception {
        System.out.println("Name: Kunal");
        System.out.println("Roll: 2019085\n");
        
        sc = new Scanner(System.in);
        
        setupConnection("127.0.0.1", 6789);
        requestServerPublicKey();
        System.out.println("Input: ");
        msgInput();
        input();
        System.out.println("Output: ");
        sendEncMsgToServer();
        sc.close();

    }
}