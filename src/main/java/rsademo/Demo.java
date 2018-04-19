package rsademo;

/**
 * 用于演示调用
 */
public class Demo {
    /**
     * 甲方发送操作：
     1. 甲方 组织报文
     2. 使用甲方私钥签名报文（摘要算法）
     3. 将报文和签名合并
     4. 使用乙方公钥将合并后的数据加密（非对称加密）
     5. 传输到乙方

     乙方接收操作：
     1. 使用乙方私钥将加密数据打开 （非对称加密）
     2. 分开报文和签名
     3. 使用甲方公钥重新签名报文（摘要算法）
     4. 验证乙方签名后的报文和甲方传输的报文是否一样
     5. 如果一样接收数据成功
     */

    public static void main(String[] args) throws Exception {
        //创建发送接收对象
        Sender sender = new Sender();
        Receiver receiver = new Receiver();

        //发送方操作
        //组织报文
        String sendMessage = "msg=发送了一条数据";
        //签名报文
        String signMsg = sender.sign(sendMessage);
        //合并报文和签名
        sendMessage = sendMessage+",sign="+signMsg;
        System.out.println("发送方发送的数据是："+sendMessage);
        //获取接收方的公钥
        String receiverPublicKey = receiver.getPublicKey();
        //接收方公钥加密报文
        String finalMsg = sender.encode(receiverPublicKey, sendMessage);
        System.out.println("--------------发送数据：从发送方到接收方"+finalMsg+"----------------");

        //接收方操作
        //使用私钥解密报文
        String receiverMsg = receiver.decoder(finalMsg);
        //获取对方公钥
        String senderPublicKey = sender.getPublicKey();
        //验签
        boolean res = receiver.verify(senderPublicKey, receiverMsg);
        System.out.println("接收方验证签名结果:" + res);
    }
}
