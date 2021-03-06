package org.jboss.xavier.integrations.route;

import org.apache.camel.Exchange;
import org.jboss.xavier.integrations.util.TestUtil;
import org.junit.Test;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

public class MainRouteBuilder_DirectAddUsernameHeaderTest extends XavierCamelTest {

    @Test
    public void mainRouteBuilder_routeDirectAddUsernameHeader_ContentGiven_ShouldAddHeaderInExchange() throws Exception {
        //When
        camelContext.start();
        camelContext.startRoute("add-username-header");

        String x_rh_identity= Base64.getEncoder().encodeToString("{\"entitlements\":{\"insights\":{\"is_entitled\":true},\"openshift\":{\"is_entitled\":true},\"smart_management\":{\"is_entitled\":false},\"hybrid_cloud\":{\"is_entitled\":true}},\"identity\":{\"internal\":{\"auth_time\":0,\"auth_type\":\"jwt-auth\",\"org_id\":\"6340056\"},\"account_number\":\"1460290\",\"user\":{\"first_name\":\"Marco\",\"is_active\":true,\"is_internal\":true,\"last_name\":\"Rizzi\",\"locale\":\"en_US\",\"is_org_admin\":false,\"username\":\"mrizzi@redhat.com\",\"email\":\"mrizzi+qa@redhat.com\"},\"type\":\"User\"}}".getBytes());
        Map<String, Object> headers = new HashMap<>();
        headers.put("x-rh-identity", x_rh_identity);

        Exchange result = camelContext.createProducerTemplate().request("direct:add-username-header",  exchange -> {
            exchange.getIn().setBody(null);
            exchange.getIn().setHeaders(headers);
        });

        //Then
        assertThat(result.getIn().getHeader("analysisUsername")).isEqualTo("mrizzi@redhat.com");
        camelContext.stop();
    }

    @Test
    public void mainRouteBuilder_routeDirectAddUsernameHeader_NoContentGiven_ShouldAddNullHeadersInExchange() throws Exception {
        //When
        camelContext.start();
        camelContext.startRoute("add-username-header");

        Exchange result = camelContext.createProducerTemplate().request("direct:add-username-header",  exchange -> {
            exchange.getIn().setBody(null);
            exchange.getIn().setHeaders(new HashMap<String, Object>());
        });

        //Then
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USERNAME)).isNull();
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USER_ACCOUNT_NUMBER)).isNull();
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.X_RH_IDENTITY_JSON_NODE)).isNull();
        camelContext.stop();
    }

    @Test
    public void mainRouteBuilder_routeDirectAddUsernameHeader_MissingUsernameContentGiven_ShouldAddNullUsernameHeaderInExchange() throws Exception {
        //When
        camelContext.start();
        camelContext.startRoute("add-username-header");

        String x_rh_identity= Base64.getEncoder().encodeToString("{\"entitlements\":{\"insights\":{\"is_entitled\":true},\"openshift\":{\"is_entitled\":true},\"smart_management\":{\"is_entitled\":false},\"hybrid_cloud\":{\"is_entitled\":true}},\"identity\":{\"internal\":{\"auth_time\":0,\"auth_type\":\"jwt-auth\",\"org_id\":\"6340056\"},\"account_number\":\"1460290\",\"user\":{\"first_name\":\"Marco\",\"is_active\":true,\"is_internal\":true,\"last_name\":\"Rizzi\",\"locale\":\"en_US\",\"is_org_admin\":false,\"email\":\"mrizzi+qa@redhat.com\"},\"type\":\"User\"}}".getBytes());
        Map<String, Object> headers = new HashMap<>();
        headers.put("x-rh-identity", x_rh_identity);

        Exchange result = camelContext.createProducerTemplate().request("direct:add-username-header",  exchange -> {
            exchange.getIn().setBody(null);
            exchange.getIn().setHeaders(headers);
        });

        //Then
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USERNAME)).isNull();
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USER_ACCOUNT_NUMBER)).isEqualTo("1460290");
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.X_RH_IDENTITY_JSON_NODE)).isNotNull();
        camelContext.stop();
    }

    @Test
    public void mainRouteBuilder_routeDirectAddUsernameHeader_MissingUserContentGiven_ShouldAddEmptyHeaderInExchange() throws Exception {
        //When
        camelContext.start();
        camelContext.startRoute("add-username-header");

        String x_rh_identity= Base64.getEncoder().encodeToString("{\"entitlements\":{\"insights\":{\"is_entitled\":true},\"openshift\":{\"is_entitled\":true},\"smart_management\":{\"is_entitled\":false},\"hybrid_cloud\":{\"is_entitled\":true}},\"identity\":{\"internal\":{\"auth_time\":0,\"auth_type\":\"jwt-auth\",\"org_id\":\"6340056\"},\"account_number\":\"1460290\",\"type\":\"User\"}}".getBytes());
        Map<String, Object> headers = new HashMap<>();
        headers.put("x-rh-identity", x_rh_identity);

        Exchange result = camelContext.createProducerTemplate().request("direct:add-username-header",  exchange -> {
            exchange.getIn().setBody(null);
            exchange.getIn().setHeaders(headers);
        });

        //Then
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USERNAME)).isNull();
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USER_ACCOUNT_NUMBER)).isEqualTo("1460290");
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.X_RH_IDENTITY_JSON_NODE)).isNotNull();
        camelContext.stop();
    }

    @Test
    public void mainRouteBuilder_routeDirectAddUsernameHeader_BadContentGiven_ShouldAddNullHeadersInExchange() throws Exception {
        //When
        camelContext.start();
        camelContext.startRoute("add-username-header");

        String x_rh_identity= Base64.getEncoder().encodeToString("BadContentGiven".getBytes());
        Map<String, Object> headers = new HashMap<>();
        headers.put("x-rh-identity", x_rh_identity);

        Exchange result = camelContext.createProducerTemplate().request("direct:add-username-header",  exchange -> {
            exchange.getIn().setBody(null);
            exchange.getIn().setHeaders(headers);
        });

        //Then
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USERNAME)).isNull();
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USER_ACCOUNT_NUMBER)).isNull();
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.X_RH_IDENTITY_JSON_NODE)).isNull();
        camelContext.stop();
    }

    @Test
    public void mainRouteBuilder_xRhIdentityHeaderProcessor_givenValidHeader_shouldAllRequiredHeaders() throws Exception {
        // Given

        //When
        camelContext.start();
        camelContext.startRoute("add-username-header");

        Map<String, Object> headers = new HashMap<>();
        headers.put(MainRouteBuilder.X_RH_IDENTITY, TestUtil.getBase64RHIdentity());

        Exchange result = camelContext.createProducerTemplate().request("direct:add-username-header",  exchange -> {
            exchange.getIn().setBody(null);
            exchange.getIn().setHeaders(headers);
        });

        //Then
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USERNAME)).isEqualTo("mrizzi@redhat.com");
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.USER_ACCOUNT_NUMBER)).isEqualTo("1460290");
        assertThat(result.getIn().getHeader(RouteBuilderExceptionHandler.X_RH_IDENTITY_JSON_NODE)).isNotNull();
        camelContext.stop();
    }
}
