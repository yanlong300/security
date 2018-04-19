package base64;

import org.apache.commons.codec.binary.Base64;

import java.io.IOException;

/**
 * CommonCodec 实现 Base64
 */
public class CCBase64 {
    private static final String BASE_STRING ="security base64";

    public static void main(String[] args) throws IOException {
        System.out.println("原始字符串： " + BASE_STRING);
        byte[] encStr = Base64.encodeBase64(BASE_STRING.getBytes());
        System.out.println("Base64编码后： " + new String(encStr));
        String deStr = new String(Base64.encodeBase64(encStr));
        System.out.println("Base64解码后： "+deStr);
    }
}
