package bouncer.demo;

import java.nio.file.Files;
import java.nio.file.Paths;

public final class Demo {
    public static void main(String[] args) throws Exception {
        System.out.println("before: " + Score.value());
        if (args.length > 0) {
            ReplacementAgent.replace(Score.class, Files.readAllBytes(Paths.get(args[0])));
        }
        System.out.println("after: " + Score.value());
    }
}
