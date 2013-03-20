package org.evildethow.valves;

import org.apache.catalina.connector.Request;
import org.evildethow.security.util.Inet4AddressUtil;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

public class AccessLogValveTest {

    private static final String ORIGINATING_IP = "58.163.175.187";

    private Request request;
    private AccessLogValve accessLogValve;

    @Before
    public void init() {
        request = new Request() {
            private final Map<String, String> customHeaderMap = new HashMap<String, String>();

            @Override
            public String getRemoteAddr() {
                return ORIGINATING_IP;
            }

            @Override
            public void addHeader(String name, String value) {
                customHeaderMap.put(name, value);
            }

            @Override
            public String getHeader(String name) {
                return customHeaderMap.get(name);
            }
        };
        request.addHeader(Inet4AddressUtil.X_FORWARDED_FOR_HEADER_KEY, ORIGINATING_IP);
        accessLogValve = new AccessLogValve();
    }

    @Test
    public void assertOriginatingIpIsPresentInLog_ForwardedForAddressElement() {
        AccessLogValve.ForwardedForAddressElement addressElement = (AccessLogValve.ForwardedForAddressElement)accessLogValve.createAccessLogElement('f');
        StringBuffer buffer = new StringBuffer();

        addressElement.addElement(buffer, null, request, null, 1L);
        String actualLog = buffer.toString();

        Assert.assertTrue(actualLog.contains(ORIGINATING_IP));
    }
}
