package symmetrickey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import java.security.Key;
import java.security.Security;

/**
 * 对称加密算法 DES
 */
public class DES {
    /**
     * 加密字符串
     */
    private static final String BASE_STRING ="security DESTest";

    public static void main(String[] args) throws Exception {
        jdkDES(BASE_STRING);
    }

    public static void jdkDES(String str) throws Exception {
        //系统自动生成key
        byte[] key = KeyGenerator.getInstance("DES").generateKey().getEncoded();

        //转换秘钥
        DESKeySpec desKeySpec = new DESKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

        //加密
        //加密模式 DES
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //初始化加密工具
        cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        //展示
        System.out.println("Jdk DES Encrypt:"+ Hex.toHexString(enBytes));
        
        //解密
        cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("Jdk DES Decrypt:"+new String(deBytes));

    }


    public static void BCDES(String str) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        //系统自动生成key
        byte[] key = KeyGenerator.getInstance("DES").generateKey().getEncoded();

        //转换秘钥
        DESKeySpec desKeySpec = new DESKeySpec(key);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("DES");
        Key convertSecretKey = secretKeyFactory.generateSecret(desKeySpec);

        //加密
        //加密模式 DES
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        //初始化加密工具
        cipher.init(Cipher.ENCRYPT_MODE,convertSecretKey);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        //展示
        System.out.println("BC+Jdk DES Encrypt:"+ Hex.toHexString(enBytes));

        //解密
        cipher.init(Cipher.DECRYPT_MODE,convertSecretKey);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("BC+Jdk DES Decrypt:"+new String(deBytes));

    }
}
