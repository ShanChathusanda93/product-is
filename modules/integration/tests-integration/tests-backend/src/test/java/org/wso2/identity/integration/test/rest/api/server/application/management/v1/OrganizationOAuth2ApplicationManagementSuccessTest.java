package org.wso2.identity.integration.test.rest.api.server.application.management.v1;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationGrant;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ResourceOwnerPasswordCredentialsGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import org.json.JSONObject;
import org.testng.Assert;
import org.testng.annotations.AfterClass;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Factory;
import org.testng.annotations.Test;
import org.wso2.carbon.automation.engine.context.TestUserMode;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.ApplicationResponseModel;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.AssociatedRolesConfig;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.InboundProtocolListItem;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.InboundProtocols;
import org.wso2.identity.integration.test.rest.api.server.application.management.v1.model.OpenIDConnectConfiguration;
import org.wso2.identity.integration.test.rest.api.server.organization.management.v1.OrganizationManagementBaseTest;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.Audience;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.Permission;
import org.wso2.identity.integration.test.rest.api.server.roles.v2.model.RoleV2;
import org.wso2.identity.integration.test.restclients.OAuth2RestClient;
import org.wso2.identity.integration.test.restclients.OrgMgtRestClient;
import org.wso2.identity.integration.test.utils.OAuth2Constant;

import java.net.URI;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class OrganizationOAuth2ApplicationManagementSuccessTest extends OrganizationManagementBaseTest {

    private static final String AUTHORIZED_APIS_JSON = "org-based-authorized-apis.json";
    private static final String SUB_ORG_NAME = "subOrg";

    private OrgMgtRestClient orgMgtRestClient;
    private OAuth2RestClient oAuth2RestClient;
    private String subOrgId;
    private String switchedM2MToken;
    private String subOrgAppToken;

    @Factory(dataProvider = "restAPIUserConfigProvider")
    public OrganizationOAuth2ApplicationManagementSuccessTest(TestUserMode userMode) throws Exception {

        super.init(userMode);
        this.context = isServer;
        this.authenticatingUserName = context.getContextTenant().getTenantAdmin().getUserName();
        this.authenticatingCredential = context.getContextTenant().getTenantAdmin().getPassword();
        this.tenant = context.getContextTenant().getDomain();
    }

    @BeforeClass(alwaysRun = true)
    public void initClass() throws Exception {

        super.testInit("v1", swaggerDefinition, tenant);
        oAuth2RestClient = new OAuth2RestClient(serverURL, tenantInfo);

        orgMgtRestClient = new OrgMgtRestClient(isServer, tenantInfo, serverURL,
                new JSONObject(readResource(AUTHORIZED_APIS_JSON, this.getClass())));
        subOrgId = orgMgtRestClient.addOrganization(SUB_ORG_NAME);
        switchedM2MToken = orgMgtRestClient.switchM2MToken(subOrgId);
        orgMgtRestClient.addOrganizationUser("sub-org-user", "SubOrgUser@123");
    }

    @AfterClass(alwaysRun = true)
    public void atEnd() throws Exception {

        orgMgtRestClient.deleteOrganization(subOrgId);
        orgMgtRestClient.closeHttpClient();
        oAuth2RestClient.closeHttpClient();
    }

    @Test
    public void testCreateOAuth2ApplicationInOrganization() throws Exception {

        String body = readResource("create-basic-oauth2-application.json", this.getClass());

        oAuth2RestClient.createApplicationInSubOrganization(body, switchedM2MToken);
        System.out.println("Sub Organization Application ID : " + oAuth2RestClient.getAppIdUsingAppNameInOrganization("My SAMPLE APP", switchedM2MToken));
        String subOrganizationAppId = oAuth2RestClient.getAppIdUsingAppNameInOrganization("My SAMPLE APP",
                switchedM2MToken);

        // Authorizing the APIs to the sub organization application
        authorizeSystemAPIsToSubOrganizationApp(oAuth2RestClient, subOrganizationAppId,
                new ArrayList<>(Arrays.asList("/o/scim2/Roles", "/o/oauth2/introspect")), switchedM2MToken);

        // Creating an application role for the sub organization application
        RoleV2 role;
        String displayName;
        List<String> schemas = Collections.emptyList();
        List<Permission> permissions = new ArrayList<>();
        permissions.add(new Permission("internal_org_role_mgt_create"));
        permissions.add(new Permission("internal_org_role_mgt_view"));
        displayName = "Application Role";
        Audience roleAudience = new Audience("APPLICATION", subOrganizationAppId);
        role = new RoleV2(roleAudience, displayName, permissions, schemas);
        oAuth2RestClient.createV2RolesInSubOrganization(role, switchedM2MToken);
        ApplicationResponseModel subOrgAppModel = oAuth2RestClient.getSubOrgApplication(subOrganizationAppId,
                switchedM2MToken);

        // Validate application details
        Assert.assertEquals(subOrgAppModel.getName(), "My SAMPLE APP");

        // Validate application role audience and roles
        AssociatedRolesConfig associatedRolesConfig = subOrgAppModel.getAssociatedRoles();
        Assert.assertEquals(associatedRolesConfig.getAllowedAudience().toString(), "APPLICATION");
        Assert.assertEquals(associatedRolesConfig.getRoles().get(0).getName(), "Application Role");

        // Validate application inbound protocols
        List<InboundProtocolListItem> inboundProtocols = subOrgAppModel.getInboundProtocols();
        Assert.assertEquals(inboundProtocols.size(), 1);
    }

    @Test(dependsOnMethods = "testCreateOAuth2ApplicationInOrganization")
    public void testIssueAccessTokenFromSubOrgApplicationFromCCGrant() throws Exception {

        String subOrganizationAppId = oAuth2RestClient.getAppIdUsingAppNameInOrganization("My SAMPLE APP",
                switchedM2MToken);
        OpenIDConnectConfiguration oidcConfig = oAuth2RestClient.getOIDCInboundDetailsForSubOrgApplications(
                subOrganizationAppId, switchedM2MToken);
        String subOrgAppClientId = oidcConfig.getClientId();
        String clientSecret = oidcConfig.getClientSecret();

        // Issue access token from sub organization application
        AccessTokenResponse accessTokenResponse = getSubOrgApplicationToken("client_credentials", subOrgAppClientId, clientSecret, subOrgId);
        subOrgAppToken = accessTokenResponse.getTokens().getAccessToken().getValue();
        Assert.assertNotNull(subOrgAppToken);
        String scopes = accessTokenResponse.getTokens().getAccessToken().getScope().toString();
        String[] scopeArray = scopes.split(" ");
        Assert.assertEquals(scopeArray.length, 6);
        Assert.assertTrue(Arrays.asList(scopeArray).contains("internal_org_role_mgt_create"));
        Assert.assertTrue(Arrays.asList(scopeArray).contains("internal_org_role_mgt_view"));
        Assert.assertTrue(Arrays.asList(scopeArray).contains("internal_org_role_mgt_update"));
        Assert.assertTrue(Arrays.asList(scopeArray).contains("internal_org_role_mgt_delete"));
    }

    public void testAccessResourcesFromTokensIssuedFromSubOrgApplication() throws Exception {

        // Access resources from tokens issued from sub organization application
        oAuth2RestClient.getRoles(subOrgAppToken);
    }

    private AccessTokenResponse getSubOrgApplicationToken(String grantType, String clientId, String clientSecretStr, String orgId) throws Exception {

        URI tokenEndpoint = new URI("https://localhost:9853/t/carbon.super/o/" + orgId + "/oauth2/token");

        ClientID clientID = new ClientID(clientId);
        Secret clientSecret = new Secret(clientSecretStr);
        ClientAuthentication clientAuth = new ClientSecretBasic(clientID, clientSecret);

        AuthorizationGrant authorizationGrant;
        switch (grantType) {
            case OAuth2Constant.OAUTH2_GRANT_TYPE_CLIENT_CREDENTIALS:
                authorizationGrant = new ClientCredentialsGrant();
                break;
            case OAuth2Constant.OAUTH2_GRANT_TYPE_RESOURCE_OWNER:
                authorizationGrant = new ResourceOwnerPasswordCredentialsGrant(null, null);
                break;
            default:
                throw new Exception("Unsupported grant type");
        }
        Scope scope = new Scope("SYSTEM");

        TokenRequest request = new TokenRequest(tokenEndpoint, clientAuth, authorizationGrant, scope);
        HTTPResponse tokenHTTPResp = request.toHTTPRequest().send();
        TokenResponse tokenResponse = TokenResponse.parse(tokenHTTPResp);
        return tokenResponse.toSuccessResponse();
    }

    @DataProvider(name = "restAPIUserConfigProvider")
    public static Object[][] restAPIUserConfigProvider() {

        return new Object[][]{
                {TestUserMode.SUPER_TENANT_ADMIN}
//                {TestUserMode.TENANT_ADMIN}
        };
    }
}
