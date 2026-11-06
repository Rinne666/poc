package c8fixture;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.lang.management.ManagementFactory;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Downstream handler for the /v1/traces control path (the filter rejects
 * over-cap bodies before this runs) and a /stats probe that reports the
 * fixture's counters and live heap after each experiment step.
 */
@RestController
public class TraceControlEndpoint {

    @PostMapping("/v1/traces")
    public Map<String, Object> traces(@RequestBody byte[] body) {
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("acceptedBytes", body.length);
        return out;
    }

    @GetMapping(value = "/stats", produces = "application/json")
    public Map<String, Object> stats() {
        long heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage().getUsed();
        Map<String, Object> out = new LinkedHashMap<>();
        out.put("savedDatapoints", Config.SAVED_DATAPoints.get());
        out.put("filterSeenTraceBytes", Config.RECEIVED_METRIC_BYTES.get());
        out.put("heapUsedBytes", heap);
        return out;
    }
}
