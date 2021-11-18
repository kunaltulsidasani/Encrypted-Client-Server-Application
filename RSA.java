/* Network Security And Cryptography Assignment
Made by - Kunal
Roll No. - 2019085
Email - 
2019085@iiitdmj.ac.in 
tulsidasanikunal@gmail.com

File - RSA.java
*/

import java.math.BigInteger;

public class RSA{
    //1st prime number
    public BigInteger p;
    //2nd prime number
    public BigInteger q;
    //public key
    public BigInteger e;
    //n
    public BigInteger n;
    //phi(n)
    private BigInteger phin;
    //private key
    private BigInteger d;

    //constructor to take p, q, e as input in form of Hexadecimal Strings
    public RSA(String p, String q, String e){
        this.p = new BigInteger(p, 16);
        this.q = new BigInteger(q, 16);
        this.e = new BigInteger(e, 16);
        //n = p*q
        this.n = (this.p).multiply(this.q);
        //phin = (p-1)*(q-1)
        this.phin = (this.p.subtract(BigInteger.valueOf(1))).multiply(this.q.subtract(BigInteger.valueOf(1)));
        //get private key
        this.d = RSAKeyGen();
    }

    //Generate private key
    public BigInteger RSAKeyGen(){
        //return -1 if gcd(phin,e) = 0
        if((phin.gcd(e)).compareTo(BigInteger.valueOf(1L)) != 0){
            return BigInteger.valueOf(-1L);
        }
        // d = e^-1 mod phin
        BigInteger privatekey;
        privatekey = e.modInverse(phin);
        return privatekey;
    }

    //Encrypt Hex String 
    public String HexEncrypt(String P){
        //C = P^e mod n
        BigInteger Plain = new BigInteger(P, 16);
        BigInteger C = Plain.modPow(e, n);
        return C.toString(16);
    }

    //Encrypt Hex string with provided hex Key string, and hex n string
    public String HexEncrypt(String P, String k, String n){
        //C = P^k mod n
        BigInteger Plain = new BigInteger(P, 16);
        BigInteger Key = new BigInteger(k, 16);
        BigInteger N = new BigInteger(n, 16);
        BigInteger C = Plain.modPow(Key, N);
        return C.toString(16);
    }

    // //
    // public String HexEncryptPvt(String P){
    //     BigInteger Plain = new BigInteger(P, 16);
    //     BigInteger C = Plain.modPow(d, n);
    //     return C.toString(16);
    // }

    //Decrypt Hex String with private key 
    public String HexDecrypt(String C){
        //P = C^d mod n
        BigInteger Cipher = new BigInteger(C, 16);
        BigInteger P = Cipher.modPow(d,n);
        return P.toString(16);
    }

    //Decrypt Hex string with provided hex Key string , and hex n string
    public String HexDecrypt(String C, String k, String n){
        //P = C^k mod n
        BigInteger Cipher = new BigInteger(C, 16);
        BigInteger Key = new BigInteger(k, 16);
        BigInteger N = new BigInteger(n, 16);
        BigInteger P = Cipher.modPow(Key,N);
        return P.toString(16);
    }

    // public String HexDecryptPub(String C){
    //     BigInteger Cipher = new BigInteger(C, 16);
    //     BigInteger P = Cipher.modPow(e,n);
    //     return P.toString(16);
    // }

    //Return private key
    public String getPrivateKey(){
        return this.d.toString(16);
    }

    //Return n
    public String getN(){
        return this.n.toString(16);
    }
    
}