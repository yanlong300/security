package symmetrickey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.security.Security;

/**
 * 三重DES加密
 */
public class TripleDES {

    private static final String BASE_STRING ="security TripleDESTest";

    public static void main(String[] args) throws Exception {
        jdkTripleDES(BASE_STRING);
        BCTripleDES(BASE_STRING);
    }

    public static void  jdkTripleDES(String str) throws Exception{
        //系统自动生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        //依据算法自定义Key长度 init(168);
        keyGenerator.init(new SecureRandom());
        byte[] key = keyGenerator.generateKey().getEncoded();

        //转换秘钥
        DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DESede");
        Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

        //加密
        //加密模式 DES
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        //初始化加密工具
        cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        //展示
        System.out.println("Jdk TripleDES Encrypt:"+ Hex.toHexString(enBytes));

        //解密
        cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("Jdk TripleDES Decrypt:"+new String(deBytes));
    }

    public static void  BCTripleDES(String str) throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        //系统自动生成key
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
        //依据算法自定义Key长度 init(168);
        keyGenerator.init(new SecureRandom());
        byte[] key = keyGenerator.generateKey().getEncoded();

        //转换秘钥
        DESedeKeySpec desKeySpec = new DESedeKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DESede");
        Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

        //加密
        //加密模式 DES
        Cipher cipher = Cipher.getInstance("DESede/ECB/PKCS5Padding");
        //初始化加密工具
        cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        //展示
        System.out.println("BC+Jdk TripleDES Encrypt:"+ Hex.toHexString(enBytes));

        //解密
        cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("BC+Jdk TripleDES Decrypt:"+new String(deBytes));
    }
}
