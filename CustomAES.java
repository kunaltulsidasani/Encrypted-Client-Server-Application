/* Network Security And Cryptography Assignment
Made by - Kunal
Roll No. - 2019085
Email - 
2019085@iiitdmj.ac.in 
tulsidasanikunal@gmail.com

File - CustomAES.java
*/

public class CustomAES {
    
    //Substitution Box
    private static String[] Sbox = {"1001","0100","1010","1011","1101","0001","1000","0101","0110","0010","0000","0011","1100","1110","1111","0111"};
    //Inverse Substituiton Box
    private static String[] invSbox = {"1010","0101","1001","1011","0001","0111","1000","1111","0110","0000","0010","0011","1100","0100","1101","1110"};
    //Round Keys
    private String key0, key1, key2;
    //Key
    private String key;
    //Mix Coloumn Matrix for Encryption
    private static String Me[][] = {{"0001","0100"},{"0100","0001"}};
    //Mix Coloumn Matrix for Decryption
    private static String Md[][] = {{"1001","0010"},{"0010","1001"}};

    //Constructor
    public CustomAES(String k){
        this.key = k;
        //Generate all round Keys
        keyGen();
    }
    
    // Rotate/Swap Word For Key
    private String rotNib(String w){
        String p1 = w.substring(0,4);
        String p2 = w.substring(4,8);
        return p2 + p1;
    }

    //Substitute Nibble from Given Substituion Box
    private String subNib(String n, String[] box){
        int i = Integer.parseInt(n,2);
        n = box[i];
        return n;
    }

    //Substitute Nibble in Key
    private String subNibKey(String w){
        String p1 = w.substring(0,4);
        String p2 = w.substring(4,8);
        p1 = subNib(p1, Sbox);
        p2 = subNib(p2, Sbox);
        return p1 + p2;
    }

    //returns XOR of two binary strings
    private String XOR(String a, String b){
        StringBuffer XR=new StringBuffer();
        for (int i = 0; i < a.length(); i++) {
            XR.append(a.charAt(i)^b.charAt(i));
        }
        return XR.toString();
    }

    //Generate All round Keys
    private void keyGen(){
        //W0 and W1
        String w0 = key.substring(0, 8);
        String w1 = key.substring(8, 16);
        //W2
        String w2 = XOR(XOR(w0, "10000000"),subNibKey(rotNib(w1)));
        //W3
        String w3 = XOR(w2, w1);
        //W4
        String w4 = XOR(XOR(w2, "00110000"),subNibKey(rotNib(w3)));
        //W5
        String w5 = XOR(w4, w3);
        //Key0 = W0W1
        key0 = w0+ w1;
        //Key1 = W2W3
        key1 = w2 + w3;
        //Key2 = W4W5
        key2 = w4 + w5;
    }

    //Print All Round Keys
    public void printKey(){
        System.out.println(key0);
        System.out.println(key1);
        System.out.println(key2);
    }

    //Round Key XOR and return XOR string
    private String addRoundKey(String P, String K){
        return XOR(P, K);
    }

    //Substitute all nibbles in State Array
    private String[][] sub(String[][] SA){
        for(int i=0;i<2;i++){
            for(int j=0;j<2;j++){
                SA[i][j] = subNib(SA[i][j],Sbox);
            }
        }
        return SA;
    }

    //Inverse Substitute all nibbles in State Array
    private String[][] invSub(String[][] SA){
        for(int i=0;i<2;i++){
            for(int j=0;j<2;j++){
                SA[i][j] = subNib(SA[i][j],invSbox);
            }
        }
        return SA;
    }

    //Shift 2nd Row of State Array
    private String[][] shiftRow(String[][] SA){
        String temp;
        temp = SA[1][0];
        SA[1][0] = SA[1][1];
        SA[1][1] = temp;
        return SA;
    }

    //Inverse Shift 2nd Row of State Array
    private String[][] invShiftRow(String[][] SA){
        String temp;
        temp = SA[1][0];
        SA[1][0] = SA[1][1];
        SA[1][1] = temp;
        return SA;
    }

    //Multiplication in Galoi's Field (2^4) of Two Binary Strings
    //Modified peasant's algorithm
    private String gmul(String a, String b){
        //Convert Binary String to Integer
        int A = Integer.parseInt(a, 2);
        int B = Integer.parseInt(b, 2);
        //Product of Both Strings
        int p = 0;

        //While one of A or B is zero
        while(A != 0 && B != 0){
            //If B is Odd
            if(B%2 != 0){
                //XOR A in Product
                p = p^A;
            }
            //Right Shift B
            B = B >> 1;
            //Left Shift A
            A = A << 1;
            //If A exceeds 2^4 i.e 16 ~ 15(When Begining Count from 0)
            if(A>15){
                //XOR With Primitive Equation - X^4 + x + 1 = 10011 = 19
                A = A^19;
            }
        }
        //Convert result Integer to binary string 
        String res = Integer.toBinaryString(p);
        //If Binary String is less than 4 digits Add 0 before
        if(res.length()<4){
            int c = 4 - res.length();
            for(int i=0;i<c;i++){
                res = "0"+res;
            }
        }
        return res;
    }

    //Perform Mix Columns on State Array For Encryption
    private String[][] mixCol(String[][] SA){
        String[][] newSA = new String[2][2];
        //newSA 0,0 = (SA 0,0 * Me 0,0) + (SA 1,0 * Me 0,1)
        newSA[0][0] = XOR(gmul(SA[0][0],Me[0][0]),gmul(SA[1][0],Me[0][1]));

        //newSA 1,0 = (SA 0,0 * Me 1,0) + (SA 1,0 * Me 1,1)
        newSA[1][0] = XOR(gmul(SA[0][0],Me[1][0]),gmul(SA[1][0],Me[1][1]));
        
        //newSA 0,1 = (SA 0,1 * Me 0,0) + (SA 1,1 * Me 0,1)
        newSA[0][1] = XOR(gmul(SA[0][1],Me[0][0]),gmul(SA[1][1],Me[0][1]));
        
        //newSA 1,1 = (SA 0,1 * Me 1,0) + (SA 1,1 * Me 1,1)
        newSA[1][1] = XOR(gmul(SA[0][1],Me[1][0]),gmul(SA[1][1],Me[1][1]));
        return newSA;
    }

    //Perform Inverse Mix Columns on State Array For Decryption
    private String[][] invMixCol(String[][] SA){
        String[][] newSA = new String[2][2];
        //newSA 0,0 = (SA 0,0 * Md 0,0) + (SA 1,0 * Md 0,1)
        newSA[0][0] = XOR(gmul(SA[0][0],Md[0][0]),gmul(SA[1][0],Md[0][1]));
        
        //newSA 1,0 = (SA 0,0 * Md 1,0) + (SA 1,0 * Md 1,1)
        newSA[1][0] = XOR(gmul(SA[0][0],Md[1][0]),gmul(SA[1][0],Md[1][1]));
        
        //newSA 0,1 = (SA 0,1 * Md 0,0) + (SA 1,1 * Md 0,1)
        newSA[0][1] = XOR(gmul(SA[0][1],Md[0][0]),gmul(SA[1][1],Md[0][1]));
        
        //newSA 1,1 = (SA 0,1 * Md 1,0) + (SA 1,1 * Md 1,1)
        newSA[1][1] = XOR(gmul(SA[0][1],Md[1][0]),gmul(SA[1][1],Md[1][1]));
        return newSA;
    }

    //Make and Return State Array From 16 bit Binary String
    private String[][] makeSA(String P){
        String[][] SA = new String[2][2];
        SA[0][0] = P.substring(0,4);
        SA[1][0] = P.substring(4,8);
        SA[0][1] = P.substring(8,12);
        SA[1][1] = P.substring(12,16);
        return SA;
    }

    //Make binary String from a State Array
    private String makeString(String[][] SA){
        String S;
        S = SA[0][0] + SA[1][0] + SA[0][1] + SA[1][1];
        return S;
    }

    //Encrypt a 16 bit Binary number using S-AES
    public String Encrypt(String plainText){
        String cipherText;
        String intermediate;
        System.out.println("Cipher text intermediate computation process:\n");

        //XOR Round Key 0
        intermediate = addRoundKey(plainText, key0);
        System.out.println("After Pre-round transformation: "+intermediate);
        System.out.println("Round Key K0: "+key0);
        String[][] SA = new String[2][2];
        //Convert To a State Array
        SA = makeSA(intermediate);
    
        //Round 1 of Encryption
        //Substitution
        SA = sub(SA);
        System.out.println("After Round 1 Substitute nibbles: "+makeString(SA));
        //Shift Row
        SA = shiftRow(SA);
        System.out.println("After Round 1 Shift Rows: "+makeString(SA));
        //Mix Coloumns
        SA = mixCol(SA);
        System.out.println("After Round 1 Mix columns: "+makeString(SA));
        
        
        //Convert State Array to string
        intermediate = makeString(SA);
        //XOR Round Key 1
        intermediate = addRoundKey(intermediate, key1);  
        System.out.println("After Round 1 Add round key: "+intermediate);
        System.out.println("Round Key K1: "+key1);
        //Conver to State Array
        SA = makeSA(intermediate);

        //Round 2 of Encryption
        //Substituion
        SA = sub(SA);
        System.out.println("After Round 2 Substitute nibbles: "+makeString(SA));
        //Shift Row
        SA = shiftRow(SA);
        System.out.println("After Round 2 Shift Rows: "+makeString(SA));
        //Convert State Array To String
        intermediate = makeString(SA);
        //XOR round Key2
        intermediate = addRoundKey(intermediate, key2);
        System.out.println("After Round 1 Add round key: "+intermediate);
        System.out.println("Round Key K2: "+key2);
        //Convert String to state array
        SA = makeSA(intermediate);

        //Convert to string
        //Cipher Text
        cipherText = makeString(SA);
        return cipherText;
    }

    public String Decrypt(String cipherText){
        String plainText;
        String intermediate;
        System.out.println("Decryption intermediate process:\n");

        //XOR round Key2
        intermediate = addRoundKey(cipherText, key2);
        System.out.println("After Pre-round transformation: "+intermediate);
        System.out.println("Round Key K2: "+key2);

        //Convert String to state array
        String[][] SA = new String[2][2];
        SA = makeSA(intermediate);
    
        //Round 1 of Decryption
        //Inverse Shift Row
        SA = invShiftRow(SA);
        System.out.println("After Round 1 InvShift rows: "+makeString(SA));
        // Inverse Substituion
        SA = invSub(SA);
        System.out.println("After Round 1 InvSubstituion rows: "+makeString(SA));

        //Convert State Array To String
        intermediate = makeString(SA);
        //XOR Round Key 1
        intermediate = addRoundKey(intermediate, key1);   
        System.out.println("After Round 1 Add Round Key: "+intermediate);
        System.out.println("Round Key K1: "+key1);
        //Convert String to state array
        SA = makeSA(intermediate);

        //Round 2 of Decryption
        //Inverse of Mix COloumns
        SA = invMixCol(SA);      
        System.out.println("After Round 2 InvMix columns: "+makeString(SA));
        //Inverse Shift Row
        SA = invShiftRow(SA);
        System.out.println("After Round 2 InvShift rows: "+makeString(SA));
        //Inverse Substituion
        SA = invSub(SA);
        System.out.println("After Round 2 InvSubstitute nibbles: "+makeString(SA));
        
        //Convert State Array To String
        intermediate = makeString(SA);
        //XOR Round Key 0
        intermediate = addRoundKey(intermediate, key0);
        System.out.println("After Round 2 Add Round Key: "+intermediate);
        System.out.println("Round Key K0: "+key0);
        //Convert String to state array
        SA = makeSA(intermediate);

        //Convert to string
        //Plain Text
        plainText = makeString(SA);
        return plainText;
    }

    public String binStringEncrypt(String P){
        System.out.println("\nTo handle Input Message which are greater than 2 letters i.e 16 bits, The string is divided into pair 2 letters and then Encrypted");
        System.out.println("For odd letter words 00000000 is padded with the single letter");
        System.out.println("S-AES block is converted to stream cipher\n");
        
        //Check number of 2 letter pairs
        int n = P.length()/16;
        String temp;
        //Final Cipher
        String C = "";
        for(int i=0;i<n;i++){
            System.out.println("\nPair "+i+":\n");
            //Extract 16 bits
            temp = P.substring(0, 16);
            //Remove extracted from plain text
            P = P.substring(16);
            //Encrypt extracted
            temp = Encrypt(temp);
            //append encrypted to cipher
            C = C + temp;
        }
        //To deal with padding bits
        if(P.length()%16 == 8){
            C = C + Encrypt(P+"00000000");
        }
        return C;
    }

    public String binStringDecrypt(String P){
        System.out.println("\nTo handle Input Message which are greater than 2 letters i.e 16 bits, The string is divided into pair 2 letters and then Decrypted");
        System.out.println("For odd letter words 00000000 is padded with the single letter");
        System.out.println("S-AES block is converted to stream cipher\n");

        //Check number of 2 letter pairs
        int n = P.length()/16;
        String temp;
        //final Plaintext
        String C = "";
        for(int i=0;i<n;i++){
            System.out.println("\nPair "+i+":\n");
            //Extract 16 bits
            temp = P.substring(0, 16);
            //Remove extracted from cipher text
            P = P.substring(16);
            //Decrypt extracted
            temp = Decrypt(temp);
            //append decrypted to plain
            C = C + temp;
        }
        //To deal with padding bits
        if(C.substring(C.length()-8)=="00000000"){
            C = C.substring(0,C.length()-8);
        }
        return C;
    }
    
}
