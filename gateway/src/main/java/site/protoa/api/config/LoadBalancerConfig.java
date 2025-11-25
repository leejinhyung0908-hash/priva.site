package site.protoa.api.config;

import org.springframework.cloud.client.DefaultServiceInstance;
import org.springframework.cloud.client.ServiceInstance;
import org.springframework.cloud.loadbalancer.core.ServiceInstanceListSupplier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import reactor.core.publisher.Flux;

import java.util.Arrays;
import java.util.List;

@Configuration
public class LoadBalancerConfig {

    @Bean
    @Primary
    public ServiceInstanceListSupplier serviceInstanceListSupplier() {
        return new ServiceInstanceListSupplier() {
            @Override
            public String getServiceId() {
                return "auth-service";
            }

            @Override
            public Flux<List<ServiceInstance>> get() {
                // auth-service를 authservice:8081로 매핑
                // Docker 컨테이너 이름과 포트 사용
                return Flux.just(Arrays.asList(
                        new DefaultServiceInstance(
                                "auth-service-1",
                                "auth-service",
                                "authservice", // Docker 컨테이너 이름
                                8081, // 포트
                                false // secure
                )));
            }
        };
    }
}
