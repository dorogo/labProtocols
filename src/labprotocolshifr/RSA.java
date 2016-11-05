/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package labprotocolshifr;

import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

/**
 *
 * @author user
 */
public class RSA {
    
    private final User u1;
    private final User u2;
    
    public RSA (User u1, User u2, String fPath) {
        this.u1 = u1;       //main user
        this.u2 = u2;       //second user
        u1.setPacketPath(fPath);
        u2.setPacketPath(fPath);
    }
    
    private boolean isPrime(int num) {
        int temp;
	boolean _isPrime=true;
        
	for(int i=2;i<=num/2;i++)
	{
           temp=num%i;
	   if(temp==0)
	   {
	      _isPrime=false;
	      break;
	   }
	}
        return _isPrime;
    }
    
    public void processProtocol() throws IOException {
        //генерим 2 случайных числа для открытых ключей
        int p,q,n,k,e;
        List<Integer> list = new ArrayList();
        BigInteger db;
        do {    
            p = (int)(Math.random() * 2000) + 2000;
            q = (int)(Math.random() * 2000) + 2000;
        } while ((p == q) || !isPrime(p) || !isPrime(q));
        n = p * q;
        k = (p - 1) * (q - 1);
        do {            
            e = (int)(Math.random() * (k - 1)) + 1;
        } while (gcd(e, k) != 1);
        db = BigInteger.valueOf(e).modInverse(BigInteger.valueOf(k));
        System.out.println("Generate completed.");
        System.out.println("Public: {" + e + ", " + n + "}");
        System.out.println("Secret: {" + db.toString() + ", " + n + "}");
        //сообщаем другим пользователям открытые ключи через файл
        u1.setSecretKey(db.intValue());
        u1.setNKey(n);
        u1.setPKey(e);
        list.clear();
        list.add(u1.getPKey());
        list.add(u1.getNKey());
        u1.writeData(list);
        //u2 читает открытые ключи, шифрует текст и отправляет u1
        u2.readData();
        
//        u1.showMap();
//        u2.showMap();

        FileHelper.writeString(u2.encryptRSA(FileHelper.getString(LabProtocolShifr.fileTextPath)), u2.getPacketPath(), true);
        //u1 считывает, расшифровывает, и записывает результат
        FileHelper.writeString(u1.decryptRSA(FileHelper.getString(u1.getPacketPath())), u1.getPacketPath(), true);
    }
    
    //НОД
    private int gcd(int a, int b) {
        if (b == 0) return a;
        int x = a % b;
        return gcd(b, x);
    }
   
    
}
