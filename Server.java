/* Network Security And Cryptography Assignment
Made by - Kunal
Roll No. - 2019085
Email - 
2019085@iiitdmj.ac.in 
tulsidasanikunal@gmail.com

File - Server.java
*/

import java.util.*;
import java.net.*;
import java.io.*;

public class Server {

    //Recieved Cipher text from client
    private static String cipherText;
    //PlainText Decrypted from cipherText, B -> in binary
    private static String plainTextB, plainText;
    //RSA variable 2 primes and public key
    private static String p, q, e;
    //private key
    private static String d;
    //n= p*q
    private static String n;
    //Secret Key
    private static String key;
    //Client public key
    private static String clientPublicKey;
    //Client n
    private static String clientN;
    //Digital sign from client
    private static String clientSign;

    //Socket Object for Connection
    private static Socket socket = null;
    //Server Socket for Accepting connection as server
    private static ServerSocket server = null;
    //inFromClient to get input from client
    private static BufferedReader inFromClient = null;
    //outToClient to send to client
    private static DataOutputStream outToClient = null;
    //RSA Object 
    private static RSA rsa = null;
    //CustomAES Object
    private static CustomAES aes = null;
    //Scanner Object
    public static Scanner sc = null;


    //Input Function to take all inputs from user - p, q, e
    public static void input(){
        //Input 1st prime
        System.out.print("1st Prime in Hexadecimal, p: ");
        p = sc.next();
        //Check till prime is atleast 6 byte
        while(p.length()<6){
            System.out.println("ERROR: Prime too small use prime greater than 0xFFFFF (hexadecimal)");
            p = sc.next();
        }
        
        //Input 2nd Prime
        System.out.print("2nd prime in Hexadecimal, q: ");
        q = sc.next();
        //Check till prime is atleast 3 byte i.e
        while(q.length()<6){
            System.out.println("ERROR: Prime too small use prime greater than 0xFFFFF (hexadecimal)");
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
        //Initialize n and private key
        n = rsa.getN();
        d = rsa.getPrivateKey();
    }

    //Function to setup server on the port number
    public static void setupConnection(int port){
        try{
            //Server socket on port number
            server = new ServerSocket(port);
            System.out.println("Server started");
            System.out.println("Waiting for a client ...");

            //Accept client
            socket = server.accept();
            System.out.println("Client Accepted.....");
            //Set input and output streams
            //for sending out to client 
            outToClient = new DataOutputStream(socket.getOutputStream());
            //for recieving in from client
            inFromClient = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        }
        catch(Exception e){
            System.out.println(e);
        }
    }

    public static void giveServerPublicKey() throws Exception{
        try{
            //Client req message
            String clientReq;
            //Read Client request
            clientReq = inFromClient.readLine();
            System.out.println("From Client: " + clientReq);
            
            //Provide Server public key
            outToClient.writeBytes(e + "," + n + "\n");
            System.out.println("Sent Server Public Key to Client");           
        }
        catch(Exception e){
            throw e;
        }
    }

    //Function to recieve Enctrypted message from client
    public static void recEncMsgFromClient() throws Exception{
        try{
            String encM = inFromClient.readLine();
            String[] Mspl = encM.split(","); 

            //cipher text
            cipherText = Mspl[0];

            //encrypted secret key
            String encSecKey = Mspl[1];
            //Decrypt Secret key
            key = rsa.HexDecrypt(encSecKey);
            //Convert key to binary string
            key = Integer.toBinaryString(Integer.parseInt(key, 16));
            //Add 0's in front, if less than 16 bits
            if(key.length()<16){
                int num = 16 - key.length();
                for(int i=0;i<num;i++){
                    key = "0"+key;
                }
            }
            System.out.println("Decrypted Secret key: "+key);

            //Initialize CustomAES Object with Secret Key
            aes = new CustomAES(key);
            //Decrypt cipher text
            plainTextB = aes.binStringDecrypt(cipherText);
            //Convert binary plain text to text
            plainText = strBin.binToString(plainTextB);

            System.out.println("Decrypted PlainText: "+plainText);

            //Generate Digest using HashGenerator Class
            String digest = HashGenerator.generateCustomMD5(plainText);
            System.out.println("Message digest: "+digest);

            //Client digital signature
            clientSign = Mspl[2];
            //client public key
            clientPublicKey = Mspl[3];
            //client n
            clientN = Mspl[4];
            
            //Decrypt client sign using client public key
            String decSign = rsa.HexDecrypt(clientSign, clientPublicKey, clientN);
            if(decSign.length()<5){
                int num = 5-decSign.length();
                for(int i=0;i<num;i++){
                    decSign = "0"+ decSign;
                }
            }
            System.out.println("Intermediate Verification Code: "+decSign);
            //If sign equals to 
            if(decSign.compareTo(digest)==0){
                System.out.println("Signature Verified");
            }
            else{
                System.out.println("Signature Not Verified");
            }
        }
        catch(Exception e){
            throw e;
        }
    }

    public static void main(String[] args) throws Exception {
        System.out.println("Name: Kunal");
        System.out.println("Roll: 2019085\n");
        sc = new Scanner(System.in);

        setupConnection(6789);
        System.out.println("Input: \n");
        input();
        giveServerPublicKey();
        recEncMsgFromClient();
        sc.close();
    }
}
