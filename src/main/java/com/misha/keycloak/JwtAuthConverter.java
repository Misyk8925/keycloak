package com.misha.keycloak;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    // Конвертер для извлечения стандартных полномочий из JWT
    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();

    // Чтение пользовательского атрибута principle-attribute из конфигурации
    @Value("${jwt.auth.converter.principle-attribute}")
    private String principleAttribute;

    // Чтение идентификатора ресурса resource-id из конфигурации
    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        // Комбинирование стандартных и специфичных для ресурса полномочий
        Collection<GrantedAuthority> authorities = Stream.concat(
                        jwtGrantedAuthoritiesConverter.convert(jwt).stream(), // Извлечение стандартных полномочий
                        extractResourceRoles(jwt).stream()) // Извлечение ролей, специфичных для ресурса
                .collect(Collectors.toSet());

        // Создание токена аутентификации с полномочиями и именем пользователя
        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipleclaimName(jwt)
        );
    }

    // Получение имени пользователя (принципала) из JWT
    private String getPrincipleclaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB; // Использование стандартного атрибута "sub" по умолчанию
        if (principleAttribute != null) {
            claimName = principleAttribute; // Замена на пользовательский атрибут, если указан
        }
        return (String) jwt.getClaim(claimName);
    }

    // Извлечение ролей, специфичных для ресурса, из JWT
    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {

        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;

        // Проверка, содержит ли JWT информацию о доступе к ресурсам
        if (jwt.getClaim("resource_access") == null) return Set.of();

        resourceAccess = jwt.getClaim("resource_access");

        // Проверка, содержит ли ресурс доступ к указанному resourceId
        if (resourceAccess.get(resourceId) == null) return Set.of();

        resource = (Map<String, Object>) resourceAccess.get(resourceId);

        // Извлечение ролей ресурса
        resourceRoles = (Collection<String>) resource.get("roles");

        // Конвертация ролей в объекты GrantedAuthority с префиксом "ROLE_"
        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}