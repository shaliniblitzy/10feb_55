package mx.com.gnp.gae.facultativo.procesos;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Spring Boot application entry point for the GAE-GNP Facultativo
 * Procesos (Processes) microservice module.
 *
 * <p>Bootstraps the Spring application context for the reinsurance
 * process management module, which includes offer, policy, and
 * master data maintenance services.
 */
@SpringBootApplication
public class ProcesosApplication {

    /**
     * Application entry point.
     *
     * @param args command-line arguments
     */
    public static void main(String[] args) {
        SpringApplication.run(ProcesosApplication.class, args);
    }
}
