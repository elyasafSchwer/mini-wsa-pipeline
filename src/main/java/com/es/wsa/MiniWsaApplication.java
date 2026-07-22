package com.es.wsa;

import com.es.wsa.config.WsaPolicyProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(WsaPolicyProperties.class)
public class MiniWsaApplication {

	public static void main(String[] args) {
		SpringApplication.run(MiniWsaApplication.class, args);
	}

}
