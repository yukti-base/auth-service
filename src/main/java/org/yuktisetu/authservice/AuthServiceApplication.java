package org.yuktisetu.authservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.persistence.autoconfigure.EntityScan;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
// Scoped to the contexts this service owns or reaches, instead of the old
// blanket org.yuktisetu.db. The blanket scan mapped every entity on the
// classpath, so one bad column broke startup in four services at once.
// These lists shrink on their own as cross-context dependencies are cut.
@EntityScan(basePackages = {"org.yuktisetu.identity.db", "org.yuktisetu.institute.db", "org.yuktisetu.profile.db"})
@EnableJpaRepositories(basePackages = {"org.yuktisetu.identity.repository", "org.yuktisetu.institute.repository", "org.yuktisetu.profile.repository"})
@ComponentScan(basePackages = {"org.yuktisetu.authservice", "org.yuktisetu.core"})
@EnableMethodSecurity
public class AuthServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthServiceApplication.class, args);
    }

}
