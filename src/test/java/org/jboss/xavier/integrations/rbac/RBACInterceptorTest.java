package org.jboss.xavier.integrations.rbac;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.camel.Exchange;
import org.apache.camel.Route;
import org.apache.camel.builder.AdviceWithRouteBuilder;
import org.apache.camel.component.rest.RestEndpoint;
import org.jboss.xavier.Application;
import org.jboss.xavier.integrations.route.XavierCamelTest;
import org.jboss.xavier.integrations.util.TestUtil;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = {Application.class}, webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class RBACInterceptorTest extends XavierCamelTest {

    @Autowired
    private TestRestTemplate restTemplate;

    @Value("${camel.component.servlet.mapping.context-path}")
    String camel_context;

    @Before
    public void setup() {
        camel_context = camel_context.substring(0, camel_context.indexOf("*"));
    }

    private String buildJSONStringRBACResponse(String permission) {
        RbacResponse rbacResponse = new RbacResponse(
                new RbacResponse.Meta(1, 10, 0),
                new RbacResponse.Links(null, null, null, null),
                Collections.singletonList(
                        new Acl(permission, Collections.emptyList()))
        );
        try {
            return new ObjectMapper().writeValueAsString(rbacResponse);
        } catch (JsonProcessingException e) {
            e.printStackTrace();
            throw new IllegalStateException(e);
        }
    }

    /***
     * The Min user permissions is: 'api:read'. If user has not at least min permissions then Forbidden
     * */
    @Test
    public void xmlRouteBuilder_RestEndpoints_NoMinUserPermissions_ShouldReturnForbidden() throws Exception {
        //Given
        camelContext.getRouteDefinition("fetch-rbac-user-access").adviceWith(camelContext, new AdviceWithRouteBuilder() {
            @Override
            public void configure() throws Exception {
                weaveById("fetch-rbac-user-access-endpoint").replace()
                        .setHeader(Exchange.HTTP_RESPONSE_CODE, simple("200"))
                        .setBody(exchange -> buildJSONStringRBACResponse("migration-analytics:someResource:write"));
            }
        });


        final AtomicInteger restEndpointsTested = new AtomicInteger(0);

        //When
        camelContext.start();
        TestUtil.startUsernameRoutes(camelContext);

        Supplier<Stream<Route>> streamRestRouteSupplier = () -> camelContext.getRoutes().stream()
                .filter(route -> route.getEndpoint() instanceof RestEndpoint);

        long expectedRestEndpointsTested = streamRestRouteSupplier.get().count();
        streamRestRouteSupplier.get()
                .forEach(route -> {
                    try {
                        camelContext.startRoute(route.getId());

                        // RH Identity
                        HttpHeaders headers = new HttpHeaders();
                        headers.set(TestUtil.HEADER_RH_IDENTITY, TestUtil.getBase64RHIdentity());
                        HttpEntity<String> entity = new HttpEntity<>(null, headers);

                        Map<String, Object> variables = new HashMap<>();
                        Long one = 1L;
                        variables.put("id", one);

                        RestEndpoint restEndpoint = (RestEndpoint) route.getEndpoint();
                        String url = camel_context + restEndpoint.getPath();
                        if (restEndpoint.getUriTemplate() != null) url += restEndpoint.getUriTemplate();

                        // Call endpoint
                        ResponseEntity<String> result = restTemplate.exchange(
                                url,
                                HttpMethod.resolve(restEndpoint.getMethod().toUpperCase()),
                                entity,
                                String.class,
                                variables);

                        //Then
                        assertThat(result).isNotNull();
                        assertThat(result.getStatusCodeValue()).isEqualByComparingTo(403);
                        assertThat(result.getBody()).isEqualTo("Forbidden");

                        restEndpointsTested.incrementAndGet();

                        camelContext.stopRoute(route.getId());
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                });

        assertThat(expectedRestEndpointsTested).isGreaterThanOrEqualTo(1);
        assertThat(restEndpointsTested.get()).isEqualTo(expectedRestEndpointsTested);

        camelContext.stop();
    }

}
