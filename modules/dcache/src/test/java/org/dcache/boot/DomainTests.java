package org.dcache.boot;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThrows;

import java.util.HashMap;
import java.util.Objects;
import java.util.Properties;
import java.util.concurrent.TimeUnit;

import org.apache.curator.framework.CuratorFramework;
import org.apache.curator.test.InstanceSpec;
import org.apache.curator.test.TestingServer;
import org.dcache.util.configuration.ConfigurationProperties;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class DomainTests {

    private static final String DOMAIN_NAME = "domainName";

    // Domain always has a "domain.name" property who's value is the domain's name.
    private static final String PROPERTY_DOMAIN_NAME_KEY = "dcache.domain.name";
    private static final String PROPERTY_DOMAIN_NAME_VALUE = DOMAIN_NAME;

    Domain _domain;
    private ConfigurationProperties _domainProperties;

    private TestingServer zkTestServer;
    private int tlsPort;
    private String curatorKeyStorePath;
    private String curatorTrustStorePath;
    private static final String GLOBAL_PASSWORD = "password";

    @Before
    public void setUp() throws Exception {

        curatorKeyStorePath = Objects.requireNonNull(getClass().getResource("/zookeeper-tls/curator-keystore.p12")).getFile();
        curatorTrustStorePath = Objects.requireNonNull(getClass().getResource("/zookeeper-tls/curator-truststore.p12")).getFile();
        String zkKeyStorePath = Objects.requireNonNull(getClass().getResource("/zookeeper-tls/zookeeper-keystore.p12")).getFile();
        String zkTrustStorePath = Objects.requireNonNull(getClass().getResource("/zookeeper-tls/zookeeper-truststore.p12")).getFile();

        tlsPort = InstanceSpec.getRandomPort();
        HashMap<String, Object> zkProperties = new HashMap<>();
        zkProperties.put("clientPort", "0");
        zkProperties.put("secureClientPort", String.valueOf(tlsPort));
        zkProperties.put("serverCnxnFactory", "org.apache.zookeeper.server.NettyServerCnxnFactory");
        zkProperties.put("ssl.keyStore.location", zkKeyStorePath);
        zkProperties.put("ssl.keyStore.password", "password");
        zkProperties.put("ssl.trustStore.location", zkTrustStorePath);
        zkProperties.put("ssl.trustStore.password", "password");
        zkProperties.put("ssl.clientAuth", "NEED");

        InstanceSpec spec = new InstanceSpec(null, -1, -1,
                -1, true, -1, -1,
                -1, zkProperties);
        zkTestServer = new TestingServer(spec, true);

        _domainProperties = new ConfigurationProperties(new Properties());
        _domainProperties.setProperty("dcache.zookeeper.max-retries", "3");
        _domainProperties.setProperty("dcache.zookeeper.initial-retry-delay", "1");
        _domainProperties.setProperty("dcache.zookeeper.initial-retry-delay.unit", "SECONDS");
        _domainProperties.setProperty("dcache.zookeeper.connection-timeout", "15");
        _domainProperties.setProperty("dcache.zookeeper.connection-timeout.unit", "SECONDS");
        _domainProperties.setProperty("dcache.zookeeper.session-timeout", "60");
        _domainProperties.setProperty("dcache.zookeeper.session-timeout.unit", "SECONDS");
        _domainProperties.setProperty("dcache.zookeeper.connection", "localhost:2181");
        _domainProperties.setProperty("dcache.zookeeper.tls.enabled", "true");

    }

    @Test
    public void testCreateWithNoGlobalProperties() {
        _domain = new Domain(DOMAIN_NAME, _domainProperties);
        assertEquals(DOMAIN_NAME, _domain.getName());
        assertDomainServicesCount(0);
        assertDomainPropertyValue(PROPERTY_DOMAIN_NAME_KEY, PROPERTY_DOMAIN_NAME_VALUE);
    }


    @Test
    public void testCreateWithAGlobalProperty() {
        String globalPropertyKey = "global.property";
        String globalPropertyValue = "global property value";
        ConfigurationProperties globalProperties = new ConfigurationProperties(new Properties());
        globalProperties.setProperty(globalPropertyKey, globalPropertyValue);

        _domain = new Domain(DOMAIN_NAME, globalProperties);

        assertEquals(DOMAIN_NAME, _domain.getName());
        assertDomainServicesCount(0);

        // NB global properties are imported into Properties as "default" values, so
        // are not included in the property count.
        assertDomainPropertyValue(PROPERTY_DOMAIN_NAME_KEY, PROPERTY_DOMAIN_NAME_VALUE);
        assertDomainPropertyValue(globalPropertyKey, globalPropertyValue);
    }

    @Test
    public void testCreateCuratorFrameworkEmptyTLSConfigThrows() {
        _domain = new Domain(DOMAIN_NAME, _domainProperties);
        // key-/truststore paths and passwords are not in properties:
        assertThrows(IllegalStateException.class, () -> _domain.createCuratorFramework());
    }

    @Test
    public void testConnectionEstablished() throws InterruptedException {
        _domainProperties.setProperty("dcache.zookeeper.connection", "localhost:" + tlsPort);
        _domainProperties.setProperty("dcache.zookeeper.tls.keystore.path", curatorKeyStorePath);
        _domainProperties.setProperty("dcache.zookeeper.tls.keystore.password", GLOBAL_PASSWORD);
        _domainProperties.setProperty("dcache.zookeeper.tls.truststore.path", curatorTrustStorePath);
        _domainProperties.setProperty("dcache.zookeeper.tls.truststore.password", GLOBAL_PASSWORD);
        _domain = new Domain(DOMAIN_NAME, _domainProperties);
        CuratorFramework curator = _domain.createCuratorFramework();
        curator.start();
        boolean connected = curator.blockUntilConnected(2, TimeUnit.SECONDS);
        assertTrue(connected);
    }

    /*
     * SUPPORT METHODS
     */
    private void assertDomainServicesCount(int expectedCount) {
        assertEquals(expectedCount, _domain.getServices().size());
    }

    private void assertDomainPropertyValue(String key, String expectedValue) {
        assertEquals(expectedValue, _domain.properties().getValue(key));
    }

    @After
    public void tearDown() throws Exception {
        if (zkTestServer != null) {
            zkTestServer.close();
        }
    }
}
