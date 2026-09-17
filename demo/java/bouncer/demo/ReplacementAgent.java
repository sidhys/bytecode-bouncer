package bouncer.demo;

import java.lang.instrument.ClassDefinition;
import java.lang.instrument.Instrumentation;

public final class ReplacementAgent {
    private static Instrumentation instrumentation;

    public static void premain(String options, Instrumentation instance) {
        if (!instance.isRedefineClassesSupported()) {
            throw new IllegalStateException("This JVM does not support class redefinition");
        }
        instrumentation = instance;
    }

    static void replace(Class<?> type, byte[] bytes) throws Exception {
        if (instrumentation == null) {
            throw new IllegalStateException("Start with the demo replacement Java agent");
        }
        instrumentation.redefineClasses(new ClassDefinition(type, bytes));
    }
}
