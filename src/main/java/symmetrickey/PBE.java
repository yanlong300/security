package symmetrickey;

import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * 基于口令的对称加密算法PBE
 */
public class PBE {

    private static final String BASE_STRING ="security PBETest";

    private static final String BASE_PWD="security Pwd";

    public static void main(String[] args) throws Exception {
        jdkPBE(BASE_STRING);

    }

    public static void jdkPBE(String str) throws Exception {
        //初始化盐
        SecureRandom random = new SecureRandom();
        byte[] salt = random.generateSeed(8);

        //口令于秘钥
        PBEKeySpec pbeKeySpec = new PBEKeySpec(BASE_PWD.toCharArray());
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBEWITHMD5andDES");
        Key key = factory.generateSecret(pbeKeySpec);

        //加密
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt,100);
        Cipher cipher = Cipher.getInstance("PBEWITHMD5andDES");
        cipher.init(Cipher.ENCRYPT_MODE,key,pbeParameterSpec);
        byte[] enBytes = cipher.doFinal(str.getBytes());
        System.out.println("JDK PBE 加密："+ Base64.encodeBase64String(enBytes));

        cipher.init(Cipher.DECRYPT_MODE,key,pbeParameterSpec);
        byte[] deBytes = cipher.doFinal(enBytes);
        System.out.println("JDK PBE 解密："+new String(deBytes));
    }
}
