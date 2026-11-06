package c8fixture;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;

/**
 * C8 verification fixture entry point.
 *
 * Runs the real {@code OpenTelemetryMetricController} (and the real
 * {@code OtlpTraceHttpAdmissionFilter} as the sibling control) on a real
 * embedded Tomcat. Pinot/Kafka/HBase are NOT started: the claim under test
 * is what happens between the socket and the parsed message, which is
 * entirely in the servlet + converter + controller path. The metric
 * service bean is a counting stub; the mapper chain is the real one.
 *
 * Start with a bounded heap (e.g. -Xmx128m) so the buffering behavior of
 * oversized bodies is directly observable without harming anything: this
 * is a process the fixture author owns, on 127.0.0.1.
 */
@SpringBootApplication(exclude = DataSourceAutoConfiguration.class)
public final class App {
    public static void main(String[] args) {
        SpringApplication.run(App.class, args);
    }
}
