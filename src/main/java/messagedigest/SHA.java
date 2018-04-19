package messagedigest;



import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * 摘要算法SHA
 */
public class SHA {
    private static final String BASE_STRING ="security SHATest";

    public static void main(String[] args) throws NoSuchAlgorithmException {
        jdkSHA1(BASE_STRING);
        BCSHA1(BASE_STRING);
        CCSHA1(BASE_STRING);
        BCSHA224(BASE_STRING);
        jdkAndBCSHA224(BASE_STRING);
    }

    /**
     * JDK实现SHA1
     * @param str 加密字段
     * @throws NoSuchAlgorithmException 算法未发现异常
     */
    public static void jdkSHA1(String str) throws NoSuchAlgorithmException {
        MessageDigest messageDigest = MessageDigest.getInstance("SHA");
        byte[] enStr = messageDigest.digest(str.getBytes());
        //将二进制转换为16进制输出
        System.out.println("JDK的SHA1摘要:"+new String(Hex.encodeHex(enStr)));
    }

    /**
     * BouncyCastle实现SHA1
     * @param str 加密字段
     */
    public static void BCSHA1(String str){
        Digest digest = new SHA1Digest();
        byte[] b = str.getBytes();
        digest.update(b,0,b.length);
        byte[] enStr = new byte[digest.getDigestSize()];
        digest.doFinal(enStr,0);
        //将二进制转换为16禁止输出
        System.out.println("B C的SHA1摘要:"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
    }

    /**
     * commonsCodec实现SHA1
     * @param str 加密字段
     */
    public static void CCSHA1(String str){
        String enStr = DigestUtils.sha1Hex(BASE_STRING.getBytes());
        System.out.println("C C的SHA1摘要:"+enStr);

    }

    /**
     * JDK实现SHA224
     * @param str 加密字段
     */
    public static void BCSHA224(String str) {
        Digest digest = new SHA224Digest();
        byte[] b = str.getBytes();
        digest.update(b,0,b.length);
        byte[] enStr = new byte[digest.getDigestSize()];
        digest.doFinal(enStr,0);
        //将二进制转换为16禁止输出
        System.out.println("B C的SHA224摘要   :"+new String(org.bouncycastle.util.encoders.Hex.toHexString(enStr)));
    }


    /**
     * JDK算法工具传入方式实现SHA224
     * @param str 加密字段
     * @throws NoSuchAlgorithmException 算法发现异常
     */
    public static void jdkAndBCSHA224(String str) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        MessageDigest messageDigest = MessageDigest.getInstance("SHA224");
        byte[] enStr = messageDigest.digest(str.getBytes());
        //将二进制转换为16禁止输出
        System.out.println("JDK+BC的SHA224摘要:"+new String(Hex.encodeHex(enStr)));
    }
}
