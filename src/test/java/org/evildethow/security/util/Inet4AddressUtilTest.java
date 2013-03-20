package org.evildethow.security.util;

import org.junit.Assert;
import org.apache.catalina.core.DummyRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.*;

/**
 * There are 3 sets of address ranges in IPv4 (lets ignore IPv6 for now) that are reserved for
 * private networks. Normally these are hidden behind NAT gateways and often traffic is forced
 * to either manually or automatically route through a proxy server of some kind.
 *
 * The address ranges are:
 *
 *  10.0.0.0 – 10.255.255.255
 *  172.16.0.0 – 172.31.255.255
 *  192.168.0.0 – 192.168.255.255
 *
 * If you have a client behind one of these networks and it’s not routed through a proxy server
 * then you’ll probably just get the IP address of the NAT gateway which is likely to be the address
 * you want to use. If the request is routed through a proxy server then you may get an X-Forwarded-For
 * that looks something like this:
 *
 *  X-Forwarded-For: 10.208.4.38, 58.163.175.187
 *
 * Where the address you probably want is actually the (proxy) server address on the end rather than
 * the private client address.
 *
 * You may also have a chain of multiple servers, perhaps you have a downstream proxy server going
 * through a larger upstream one before heading out of the network, so you may get something like this:
 *
 *  X-Forwarded-For: 10.208.4.38, 58.163.1.4, 58.163.175.187
 *
 * Or, the downstream proxy server could be within the private network, perhaps a departmental proxy
 * server connecting to a company-wide proxy server and then this may happen:
 *
 *  X-Forwarded-For: 10.208.4.38, 10.10.300.23, 58.163.175.187
 *
 * The rule applied is:
 *
 *  Always use the leftmost non-private address.
 *
 * @see Inet4AddressUtil
 */
@RunWith(Parameterized.class)
public class Inet4AddressUtilTest {

    private static final String ORIGINATING_IP = "58.163.175.187";

    /**
     * X-Forwarded-For IP chains
     */
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_10_0_0_0 = "10.208.4.38, 58.163.175.187";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_10_0_0_0_AND_DOWNSTREAM_PROXY = "10.208.4.38, 58.163.175.187, 58.163.1.4";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_10_0_0_0_AND_PRIVATE_DOWNSTREAM_PROXY = "10.208.4.38, 10.10.300.23, 58.163.175.187";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_172_16_0_0 = "172.16.4.38, 58.163.175.187";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_172_16_0_0_AND_DOWNSTREAM_PROXY = "172.16.4.38, 58.163.175.187, 58.163.1.4";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_172_16_0_0_AND_PRIVATE_DOWNSTREAM_PROXY = "172.16.4.38, 172.16.300.23, 58.163.175.187";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_192_168_0_0 = "192.168.4.38, 58.163.175.187";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_192_168_0_0_AND_DOWNSTREAM_PROXY = "192.168.4.38, 58.163.175.187, 58.163.1.4";
    private static final String X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_192_168_0_0_AND_PRIVATE_DOWNSTREAM_PROXY = "192.168.4.38, 192.168.300.23, 58.163.175.187";
    private static final String X_FORWARDED_FOR_EMPTY = "";

    private static final String LOCALHOST = "127.0.0.1";

    private final String ipChain;
    private DummyRequest request;

    public Inet4AddressUtilTest(String ipChain) {
        this.ipChain = ipChain;
    }

    @Parameterized.Parameters
    public static Collection<String[]> getXForwarderForIpChains() {
        List<String[]> ipChains = new ArrayList<String[]>();

        // Using X-Forwarded-For IP
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_10_0_0_0});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_10_0_0_0_AND_DOWNSTREAM_PROXY});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_10_0_0_0_AND_PRIVATE_DOWNSTREAM_PROXY});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_172_16_0_0});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_172_16_0_0_AND_DOWNSTREAM_PROXY});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_172_16_0_0_AND_PRIVATE_DOWNSTREAM_PROXY});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_192_168_0_0});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_192_168_0_0_AND_DOWNSTREAM_PROXY});
        ipChains.add(new String[] {X_FORWARDED_FOR_BEHIND_PRIVATE_NETWORK_192_168_0_0_AND_PRIVATE_DOWNSTREAM_PROXY});

        // Using originating IP
        ipChains.add(new String[] {X_FORWARDED_FOR_EMPTY});
        ipChains.add(new String[] {ORIGINATING_IP});
        ipChains.add(new String[] {LOCALHOST});

        return ipChains;
    }

    @Before
    public void init() {
        request = new DummyRequest() {
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
        request.addHeader(Inet4AddressUtil.X_FORWARDED_FOR_HEADER_KEY, ipChain);
    }

    @Test
    public void assertUsesLeftmostNonPrivateIpAddress() {
        Assert.assertEquals(ORIGINATING_IP, Inet4AddressUtil.getAddressFromRequest(request));
    }
}
