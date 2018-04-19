package messagedigest;



import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * 摘要算法 MAC
 * 附带秘钥的摘要算法
 */
public class MAC {
    /**
     * 加密的字符串
     */
    private static final String BASE_STRING ="security MACTest";
    /**
     * 秘钥
     */
    private static final String BASE_KEY ="aaaaaaaa";


    public static void main(String[] args) throws Exception {
        jdkHmacMD5(BASE_STRING);
        BCHmacMD5(BASE_STRING,BASE_KEY);
    }

    /**
     * JDK MAC摘要算法
     * 系统生成秘钥
     */
    public static void jdkHmacMD5(String str) throws Exception {
        //初始化 KeyGenerator
        KeyGenerator keyGenerator = KeyGenerator.getInstance("HmacMD5");
        //生成秘钥
        SecretKey secretKey = keyGenerator.generateKey();
        //获取秘钥
        byte[] key = secretKey.getEncoded();

        //还原秘钥
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "HmacMD5");
        //获取mac实例 初始化MAC
        Mac mac = Mac.getInstance(secretKeySpec.getAlgorithm());
        mac.init(secretKey);
        //执行摘要算法
        byte[] encBytes = mac.doFinal(str.getBytes());
        System.out.println(Hex.toHexString(encBytes));
    }

    /**
     * bouncyCastle 摘要算法
     */
    public static void BCHmacMD5(String str,String baseKey){

        HMac hMac = new HMac(new MD5Digest());
        hMac.init(new KeyParameter(Hex.decode(baseKey)));
        hMac.update(str.getBytes(),0,str.getBytes().length);
        byte[] hmacMD5 = new byte[hMac.getMacSize()];
        hMac.doFinal(hmacMD5,0);
        System.out.println(Hex.toHexString(hmacMD5));

    }

}
