package io.github.hectorvent.floci.services.secretsmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.*;

class SecretsManagerJsonHandlerTest {

    private static final String REGION = "us-east-1";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SecretsManagerJsonHandler handler;

    @BeforeEach
    void setUp() {
        SecretsManagerService service = new SecretsManagerService(new InMemoryStorage<>(), 30);
        handler = new SecretsManagerJsonHandler(service, MAPPER);
    }

    private String getRandomPassword(ObjectNode request) {
        Response response = handler.handle("GetRandomPassword", request, REGION);
        assertThat(response.getStatus(), is(200));
        return ((ObjectNode) response.getEntity()).get("RandomPassword").asText();
    }

    @Test
    void defaultLengthIs32() {
        assertThat(getRandomPassword(MAPPER.createObjectNode()), hasLength(32));
    }

    @Test
    void customLength() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("PasswordLength", 20);
        assertThat(getRandomPassword(request), hasLength(20));
    }

    @Test
    void lengthAbove4096Returns400() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("PasswordLength", 4097);
        assertThat(handler.handle("GetRandomPassword", request, REGION).getStatus(), is(400));
    }

    @Test
    void lengthBelowOneReturns400() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("PasswordLength", 0);
        assertThat(handler.handle("GetRandomPassword", request, REGION).getStatus(), is(400));
    }

    @Test
    void excludeLowercase() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("ExcludeLowercase", true);
        assertThat(getRandomPassword(request), not(matchesPattern(".*[a-z].*")));
    }

    @Test
    void excludeUppercase() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("ExcludeUppercase", true);
        assertThat(getRandomPassword(request), not(matchesPattern(".*[A-Z].*")));
    }

    @Test
    void excludeNumbers() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("ExcludeNumbers", true);
        assertThat(getRandomPassword(request), not(matchesPattern(".*[0-9].*")));
    }

    @Test
    void excludePunctuation() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("ExcludePunctuation", true);
        assertThat(getRandomPassword(request), not(matchesPattern(".*[!\"#$%&'()*+,\\-./:;<=>?@\\[\\\\\\]^_`{|}~].*")));
    }

    @Test
    void includeSpace() {
        // Only spaces are possible, so every char must be a space
        ObjectNode request = MAPPER.createObjectNode();
        request.put("IncludeSpace", true);
        request.put("ExcludeLowercase", true);
        request.put("ExcludeUppercase", true);
        request.put("ExcludeNumbers", true);
        request.put("ExcludePunctuation", true);
        request.put("RequireEachIncludedType", true);
        request.put("PasswordLength", 5);
        assertThat(getRandomPassword(request), is("     "));
    }

    @Test
    void excludeCharacters() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("ExcludeCharacters", "aeiouAEIOU");
        assertThat(getRandomPassword(request), not(matchesPattern(".*[aeiouAEIOU].*")));
    }

    @Test
    void requireEachIncludedTypeDefaultsTrue() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("PasswordLength", 100);
        String password = getRandomPassword(request);
        assertThat(password, matchesPattern(".*[a-z].*"));
        assertThat(password, matchesPattern(".*[A-Z].*"));
        assertThat(password, matchesPattern(".*[0-9].*"));
        assertThat(password, hasLength(100));
    }

    @Test
    void requireEachIncludedTypeFalse() {
        ObjectNode request = MAPPER.createObjectNode();
        request.put("ExcludeLowercase", true);
        request.put("ExcludeUppercase", true);
        request.put("ExcludePunctuation", true);
        request.put("RequireEachIncludedType", false);
        assertThat(getRandomPassword(request), matchesPattern("[0-9]+"));
    }

    @Test
    void describeSecretResponseIncludesKmsKeyId() {
        ObjectNode createReq = MAPPER.createObjectNode();
        createReq.put("Name", "kms-secret");
        createReq.put("KmsKeyId", "my-kms-key");
        handler.handle("CreateSecret", createReq, REGION);

        ObjectNode describeReq = MAPPER.createObjectNode();
        describeReq.put("SecretId", "kms-secret");
        Response response = handler.handle("DescribeSecret", describeReq, REGION);
        
        assertThat(response.getStatus(), is(200));
        ObjectNode body = (ObjectNode) response.getEntity();
        assertThat(body.get("KmsKeyId").asText(), is("my-kms-key"));
    }

    @Test
    void listSecretsResponseIncludesKmsKeyId() {
        ObjectNode createReq = MAPPER.createObjectNode();
        createReq.put("Name", "list-kms-secret");
        createReq.put("KmsKeyId", "list-kms-key");
        handler.handle("CreateSecret", createReq, REGION);

        Response response = handler.handle("ListSecrets", MAPPER.createObjectNode(), REGION);
        
        assertThat(response.getStatus(), is(200));
        ObjectNode body = (ObjectNode) response.getEntity();
        ObjectNode secret = (ObjectNode) body.get("SecretList").get(0);
        assertThat(secret.get("KmsKeyId").asText(), is("list-kms-key"));
        assertThat(secret.has("CreatedDate"), is(true));
    }

    @Test
    void listSecretsMaxResultsPaginates() {
        for (int i = 1; i <= 5; i++) {
            ObjectNode req = MAPPER.createObjectNode();
            req.put("Name", "secret-" + i);
            handler.handle("CreateSecret", req, REGION);
        }

        ObjectNode page1Req = MAPPER.createObjectNode();
        page1Req.put("MaxResults", 2);
        Response page1Resp = handler.handle("ListSecrets", page1Req, REGION);
        assertThat(page1Resp.getStatus(), is(200));
        ObjectNode page1Body = (ObjectNode) page1Resp.getEntity();
        assertThat(page1Body.get("SecretList").get(0).get("Name").asText(), is("secret-1"));
        assertThat(page1Body.get("SecretList").get(1).get("Name").asText(), is("secret-2"));
        assertThat(page1Body.has("NextToken"), is(true));

        ObjectNode page2Req = MAPPER.createObjectNode();
        page2Req.put("MaxResults", 2);
        page2Req.put("NextToken", page1Body.get("NextToken").asText());
        Response page2Resp = handler.handle("ListSecrets", page2Req, REGION);
        assertThat(page2Resp.getStatus(), is(200));
        ObjectNode page2Body = (ObjectNode) page2Resp.getEntity();
        assertThat(page2Body.get("SecretList").get(0).get("Name").asText(), is("secret-3"));
        assertThat(page2Body.get("SecretList").get(1).get("Name").asText(), is("secret-4"));
        assertThat(page2Body.has("NextToken"), is(true));

        ObjectNode page3Req = MAPPER.createObjectNode();
        page3Req.put("MaxResults", 2);
        page3Req.put("NextToken", page2Body.get("NextToken").asText());
        Response page3Resp = handler.handle("ListSecrets", page3Req, REGION);
        assertThat(page3Resp.getStatus(), is(200));
        ObjectNode page3Body = (ObjectNode) page3Resp.getEntity();
        assertThat(page3Body.get("SecretList").get(0).get("Name").asText(), is("secret-5"));
        assertThat(page3Body.has("NextToken"), is(false));
    }

    @Test
    void listSecretsNoNextTokenWhenAllResultsFit() {
        ObjectNode req = MAPPER.createObjectNode();
        req.put("Name", "only-secret");
        handler.handle("CreateSecret", req, REGION);

        Response response = handler.handle("ListSecrets", MAPPER.createObjectNode(), REGION);
        assertThat(response.getStatus(), is(200));
        ObjectNode body = (ObjectNode) response.getEntity();
        assertThat(body.has("NextToken"), is(false));
    }

    @Test
    void batchGetSecretValue() {
        ObjectNode createReq1 = MAPPER.createObjectNode();
        createReq1.put("Name", "secret1");
        createReq1.put("SecretString", "value1");
        handler.handle("CreateSecret", createReq1, REGION);

        ObjectNode createReq2 = MAPPER.createObjectNode();
        createReq2.put("Name", "secret2");
        createReq2.put("SecretString", "value2");
        handler.handle("CreateSecret", createReq2, REGION);

        ObjectNode batchReq = MAPPER.createObjectNode();
        batchReq.putArray("SecretIdList").add("secret1").add("secret2");
        Response response = handler.handle("BatchGetSecretValue", batchReq, REGION);

        assertThat(response.getStatus(), is(200));
        ObjectNode body = (ObjectNode) response.getEntity();
        assertThat(body.get("SecretValues").size(), is(2));
        assertThat(body.get("SecretValues").get(0).get("Name").asText(), anyOf(is("secret1"), is("secret2")));
    }

    @Test
    void batchGetSecretValueMissingParameters() {
        ObjectNode batchReq = MAPPER.createObjectNode();
        Response response = handler.handle("BatchGetSecretValue", batchReq, REGION);
        assertThat(response.getStatus(), is(400));
    }
}
