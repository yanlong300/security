package base64;

import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.io.IOException;

/**
 * Jdk 实现Base64
 * Jdk1.7
 */
public class JdkBase64 {

    private static final String BASE_STRING ="security base64";

    public static void main(String[] args) throws IOException {
        System.out.println("原始字符串： " + BASE_STRING);
        String enStr = jdkBase64Encoder(BASE_STRING);
        System.out.println("Base64编码后： " + enStr);
        String deStr = jdkBase64(enStr);
        System.out.println("Base64解码后： "+deStr);
    }

    public static String jdkBase64Encoder(String str){
        BASE64Encoder encoder = new BASE64Encoder();
        return encoder.encode(str.getBytes());
    }

    public static String jdkBase64(String str) throws IOException {
        BASE64Decoder decoder = new BASE64Decoder();
        return new String(decoder.decodeBuffer(str));
    }


}
