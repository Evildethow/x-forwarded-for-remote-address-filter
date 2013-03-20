package org.evildethow.security.util;

import javax.servlet.http.HttpServletRequest;
import java.net.Inet4Address;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Don’t assume that the content of the X-Forwarded-For header is either correct or syntactically valid.
 * The header is not hard to spoof and there are only certain situations where you may be able to trust
 * parts of the content of the header.
 *
 * So, my simple advice is not to use this header for anything important. Don’t use it for authentication
 * purposes or anything else that has security implications. It really should only be used for your own
 * information purposes or to provide customised content for the user where it’s OK to be basing that
 * customisation on false information, because this will be a possibility.
 *
 * Now that you've been warned...
 *
 * Adapted from: http://rod.vagg.org/2011/07/handling-x-forwarded-for-in-java-and-tomcat/
 *
 * See:
 *  http://en.wikipedia.org/wiki/X-Forwarded-For
 *  https://addons.mozilla.org/en-US/firefox/addon/x-forwarded-for-spoofer/
 */
public final class Inet4AddressUtil {

    public static final String X_FORWARDED_FOR_HEADER_KEY = "X-Forwarded-For";
    private static final String IP_ADDRESS_REGEX = "([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3})";
    private static final String PRIVATE_IP_ADDRESS_REGEX = "(^127\\.0\\.0\\.1)|(^10\\.)|(^172\\.1[6-9]\\.)|(^172\\.2[0-9]\\.)|(^172\\.3[0-1]\\.)|(^192\\.168\\.)";
    private static Pattern IP_ADDRESS_PATTERN = null;
    private static Pattern PRIVATE_IP_ADDRESS_PATTERN = null;

    private Inet4AddressUtil() {}

    public static String getHostnameFromRequest(HttpServletRequest request) {
        String address = getAddressFromRequest(request);
        try {
            return Inet4Address.getByName(address).getHostName();
        } catch (Exception e) {
            return address;
        }
    }

    public static String getAddressFromRequest(HttpServletRequest request) {
        String forwardedFor = request.getHeader(X_FORWARDED_FOR_HEADER_KEY);
        return (forwardedFor != null && (forwardedFor = findNonPrivateIpAddress(forwardedFor)) != null) ? forwardedFor : request.getRemoteAddr();
    }

    private static String findNonPrivateIpAddress(String s) {
        if (IP_ADDRESS_PATTERN == null) {
            IP_ADDRESS_PATTERN = Pattern.compile(IP_ADDRESS_REGEX);
            PRIVATE_IP_ADDRESS_PATTERN = Pattern.compile(PRIVATE_IP_ADDRESS_REGEX);
        }

        Matcher matcher = IP_ADDRESS_PATTERN.matcher(s);
        while (matcher.find()) {
            if (!PRIVATE_IP_ADDRESS_PATTERN.matcher(matcher.group(0)).find()) {
                return matcher.group(0);
            }
            matcher.region(matcher.end(), s.length());
        }
        return null;
    }
}
