/* Network Security And Cryptography Assignment
Made by - Kunal
Roll No. - 2019085
Email - 
2019085@iiitdmj.ac.in 
tulsidasanikunal@gmail.com

File - strBin.java
*/

//Class to handle Binary string and text inter-conversion
public class strBin {
    //Convert String to binary string by taking each characters ascii code
    public static String stringToBin(String M){
        int n = M.length();
        
        String res = "";
        for (int i = 0; i < n; i++)
        {
            // convert each char to
            // ASCII value
            int val = (int)M.charAt(i);

            // Convert ASCII value to binary
            String bin = "";
            while (val > 0)
            {
                if(val % 2 == 1){ 
                    bin = "1" + bin;
                }
                else{
                    bin = "0" + bin;
                }
                val /= 2;
            }
            //make each binary string from each character of 8 bits
            //padding with 0
            if(bin.length()<8){
                int num= 8-bin.length();
                for(int k=0;k<num;k++){
                    bin = "0" + bin;
                }
            }
            //Append binary string of each character to result
            res = res + bin;
        }
        return res;
    }

    //Convert binary String to string by taking binary ascii and converting to characters
    public static String binToString(String M){
        
        int n = M.length();
        n = n/8;
        
        String res = "";
        for (int i = 0; i < n; i++)
        {
            String s = M.substring(0, 8);
            M = M.substring(8);
            //Take ascii values
            int v = Integer.parseInt(s, 2);
            //if ASCII is not zero
            if(v!=0){
                //Convert ascii to character
                char val = (char)v;
                //Append character in final result
                res = res + val;
            }
        }
        return res;
    }
}
