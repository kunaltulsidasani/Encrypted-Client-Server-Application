/* Network Security And Cryptography Assignment
Made by - Kunal
Roll No. - 2019085
Email - 
2019085@iiitdmj.ac.in 
tulsidasanikunal@gmail.com

File - HashGenerator.java
*/

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashGenerator {

    //Generate MD5 of length 5 by taking first 5 letters of md5 
    public static String generateCustomMD5(String message) throws Exception{
        return hashString(message, "MD5").substring(0,5);
    }
 
    //Generate Hash String
    private static String hashString(String message, String algorithm) throws Exception{

        try {
            //Get message digest
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            byte[] hashedBytes = digest.digest(message.getBytes("UTF-8"));
 
            return convertByteArrayToHexString(hashedBytes);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException ex) {
            System.out.println(ex);
            throw new Exception("Could not generate hash from String",ex);
        }
    }
 
    //Convert Byte array to Hex String
    private static String convertByteArrayToHexString(byte[] arrayBytes){
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i < arrayBytes.length; i++) {
            stringBuffer.append(Integer.toString((arrayBytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return stringBuffer.toString();
    }
}