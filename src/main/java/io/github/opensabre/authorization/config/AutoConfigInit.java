package io.github.opensabre.authorization.config;

import io.github.opensabre.common.web.rest.ResponseAdvice;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * 初使化配置 初使化统一报文配置、审计字段自动注入
 */
@Configuration
@Import({ResponseAdvice.class})
public class AutoConfigInit {

}