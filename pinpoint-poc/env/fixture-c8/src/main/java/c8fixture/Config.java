package c8fixture;

import com.navercorp.pinpoint.otlp.collector.controller.OpenTelemetryMetricController;
import com.navercorp.pinpoint.otlp.collector.mapper.ExponentialHistogramMapper;
import com.navercorp.pinpoint.otlp.collector.mapper.GaugeMapper;
import com.navercorp.pinpoint.otlp.collector.mapper.HistogramMapper;
import com.navercorp.pinpoint.otlp.collector.mapper.OtlpMetricDataMapper;
import com.navercorp.pinpoint.otlp.collector.mapper.OtlpMetricMapper;
import com.navercorp.pinpoint.otlp.collector.mapper.SumMapper;
import com.navercorp.pinpoint.otlp.collector.mapper.SummaryMapper;
import com.navercorp.pinpoint.otlp.collector.model.OtlpMetricData;
import com.navercorp.pinpoint.otlp.collector.service.OtlpMetricCollectorService;
import com.navercorp.pinpoint.otlp.trace.collector.controller.OtlpTraceHttpAdmissionFilter;
import com.navercorp.pinpoint.otlp.trace.collector.service.OtlpIngestAdmissionMetrics;
import com.navercorp.pinpoint.otlp.trace.collector.service.OtlpRequestRejectReason;
import com.navercorp.pinpoint.otlp.trace.collector.service.OtlpTransport;
import com.navercorp.pinpoint.pinot.tenant.TenantProvider;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.protobuf.ProtobufHttpMessageConverter;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.IntSupplier;
import java.util.function.LongSupplier;

@Configuration(proxyBeanMethods = false)
public class Config {

    /** Counts what the real controller hands to the storage service. */
    static final AtomicInteger SAVED_DATAPoints = new AtomicInteger();
    static final AtomicLong RECEIVED_METRIC_BYTES = new AtomicLong();

    @Bean
    public OtlpMetricCollectorService countingService() {
        return new OtlpMetricCollectorService() {
            @Override
            public void save(OtlpMetricData otlpMetricData) {
                SAVED_DATAPoints.incrementAndGet();
            }
        };
    }

    @Bean
    public OtlpMetricMapper realMapper() {
        TenantProvider tenant = () -> "default";
        OtlpMetricDataMapper[] mappers = {
                new GaugeMapper(), new SumMapper(), new HistogramMapper(),
                new ExponentialHistogramMapper(), new SummaryMapper(),
        };
        return new OtlpMetricMapper(tenant, mappers);
    }

    @Bean
    public OpenTelemetryMetricController metricController(OtlpMetricCollectorService service,
                                                          OtlpMetricMapper mapper) {
        return new OpenTelemetryMetricController(service, mapper);
    }

    /**
     * Sibling control: the real admission filter registered on /v1/traces
     * exactly as OtlpTraceCollectorHttpModule wires it (4 MiB / 256 MiB /
     * 64 / retry-after 1), with a trivial downstream handler. The filter
     * rejects over-cap bodies BEFORE the chain, so the handler only proves
     * admitted requests complete.
     */
    @Bean
    public FilterRegistrationBean<OtlpTraceHttpAdmissionFilter> traceAdmissionControl() {
        OtlpTraceHttpAdmissionFilter filter = new OtlpTraceHttpAdmissionFilter(
                4 << 20, 256 << 20, 64, 1, new NoopMetrics());
        FilterRegistrationBean<OtlpTraceHttpAdmissionFilter> reg =
                new FilterRegistrationBean<>(filter);
        reg.addUrlPatterns("/v1/traces");
        reg.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return reg;
    }

    // TraceControlEndpoint is picked up by the @SpringBootApplication scan.

    /** Adds the protobuf converter the metric controller binds through. */
    @Bean
    public WebMvcConfigurer protobufConverter() {
        return new WebMvcConfigurer() {
            @Override
            public void extendMessageConverters(List<HttpMessageConverter<?>> converters) {
                converters.add(new ProtobufHttpMessageConverter());
            }
        };
    }

    static final class NoopMetrics implements OtlpIngestAdmissionMetrics {
        @Override
        public void requestRejected(OtlpTransport transport, OtlpRequestRejectReason reason) {
        }

        @Override
        public void requestBytes(OtlpTransport transport, long bytes) {
            RECEIVED_METRIC_BYTES.addAndGet(bytes);
        }

        @Override
        public void registerInFlightBytes(OtlpTransport transport, LongSupplier reservedBytes,
                                          long limitBytes) {
        }

        @Override
        public void registerInFlightRequests(OtlpTransport transport,
                                             IntSupplier inFlightRequests, int limitRequests) {
        }
    }
}
