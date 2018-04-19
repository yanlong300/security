package symmetrickey;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;


/**
 * 对称加密算法 AES
 * 三重DES处理速度快，未被破解
 * SSH协议软件加密
 *
 */
public class AES {

    private static final String BASE_STRING ="security AESTest";

    public static void main(String[] args) throws Exception {
        jdkAES(BASE_STRING);
    }

    /**
     *
     */
    public static void jdkAES(String str) throws Exception {
        //系统自动生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        byte[] key = keyGenerator.generateKey().getEncoded();

        //转换秘钥
        Key convertSecretKey = new SecretKeySpec(key, "AES");

        //加密
        //加密模式 DES
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        //初始化加密工具
        cipher.init(Cipher.ENCRYPT_MODE, convertSecretKey);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        //展示
        System.out.println("Jdk DES Encrypt:" + Hex.toHexString(enBytes));

        //解密
        cipher.init(Cipher.DECRYPT_MODE, convertSecretKey);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("Jdk DES Decrypt:" + new String(deBytes));
    }


}
