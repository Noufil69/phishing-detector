package com.noufil.phishingdetector.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import com.noufil.phishingdetector.service.ScoringConfig;

/** Reads the scoring settings (scoring.* properties) once, at startup. */
@Configuration
public class ScoringConfiguration {

    @Bean
    public ScoringConfig scoringConfig(Environment environment) {
        return ScoringConfig.fromProperties(environment::getProperty);
    }
}