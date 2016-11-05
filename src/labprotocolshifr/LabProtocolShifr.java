/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package labprotocolshifr;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.Arrays;
import java.util.Collections;
import java.util.Scanner;

/**
 *
 * @author user
 */
public class LabProtocolShifr {

    public static String fileTextPath = System.getProperty("user.dir") + "/source.txt";
    private static final String file1Path = System.getProperty("user.dir") + "/packet.txt";
    private static final String file2Path = System.getProperty("user.dir") + "/packet2.txt";
    
    public static void main(String[] args) throws IOException {
        // TODO code application logic here
        
        User u1 = new User();
        User u2 = new User();
        //Протокол Диффи - Хеллмана             
        System.out.println("==================== Protocol Diffie Hellman ====================");
        // для примера простые чилса 3 и 17
        String tmp = "";
        tmp += Integer.toString(processDiffieHellman(u1, u2)) + ",";
        tmp += Integer.toString(processDiffieHellman(u1, u2)) + ",";
        tmp += Integer.toString(processDiffieHellman(u1, u2)) + ",";
//        tmp = "12,3,5,20";
//        System.out.println("CODE:"+tmp);
        FileHelper.writeString(encrypt(tmp, FileHelper.getString(fileTextPath)),file1Path,true);
        System.out.println("============================= END ===============================");
        // Протокол RSA
        System.out.println("\n========================= RSA Protocol ==========================");
        
        processRSA(u1, u2, tmp);
        System.out.println("============================= END ===============================");
    }
    
    
    private static int processDiffieHellman(User u1, User u2) throws IOException {
        clearPacket(file1Path);
        System.out.println("Protocol Diffie-Hellman.");
        System.out.println("Enter public keys 'p' and 'n' for user #1.");
        Scanner sc = new Scanner(System.in);
        String tmp;
        u1.resetKeys();
        u2.resetKeys();
        do {            
            System.out.print("p> ");
            tmp = sc.nextLine();
        } while (!tmp.matches("[0-9]+"));
        u1.setPKey(Integer.parseInt(tmp));
        do {            
            System.out.print("n> ");
            tmp = sc.nextLine();
        } while (!tmp.matches("[0-9]+"));
        u1.setNKey(Integer.parseInt(tmp));
        ProtocolDiffieHellman pdh = new ProtocolDiffieHellman(u1, u2, file1Path);
        
        return pdh.processProtocol();
    }
    
    private static void processRSA (User u1, User u2, String srcText) throws IOException {
        clearPacket(file2Path);
        RSA rsa = new RSA(u1, u2, file2Path);
        rsa.processProtocol();
    }
    
    private static void clearPacket (String fPath) {
        File file = new File(fPath);
        Writer writer = null;
        try {
            FileWriter fw = new FileWriter(file);
            writer = new BufferedWriter(fw);
            writer.write("");
            System.out.println("File was cleared.");
        } catch (Exception e) {
            
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (Exception e) {
                }
            }
        }
    }
    
    private static String encrypt (String code, String srcText) {
        char[] srcArr = "abcdefghijklmnopqrstuvwxyz".toCharArray();
        String[] codeArr = code.split(",");
        String encryptedText = "";
        char c;
        boolean swap = false;
        System.out.print("\nSource alphabet: ");
        for (char q : srcArr) {
            System.out.print(""+String.valueOf(q));
        }
        Collections.reverse(Arrays.asList(codeArr));
        for (String s : codeArr) {
            for (int i = srcArr.length - 1; i >= 0; i--) {
                if (swap){
                    srcArr[i+1] = srcArr[i];
                } else if ((char)((int)'a' + Integer.parseInt(s) - 1) == srcArr[i]) {
                    swap = true;
                }
            }
            srcArr[0] = (char)((int)'a' + Integer.parseInt(s) - 1);
            swap = false;
        }
        System.out.print("\nCoded alphabet:  ");
        for (char e : srcArr) {
            System.out.print(""+String.valueOf(e));
        }
        srcText = srcText.toLowerCase();
        int l = srcText.length();
        for (int i = 0; i < l; i++) {
            c = srcText.charAt(i);
            if (Character.toString(c).matches("[a-z]"))  {
                c = srcArr[(int)c - (int)'a'];
            }
            encryptedText += c;
        }
        
        System.out.println("\n\nSource text: \t"+srcText);
        System.out.println("\nEncrypted text: "+encryptedText);
        return encryptedText;
    }
}
