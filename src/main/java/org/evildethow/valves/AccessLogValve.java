package org.evildethow.valves;

import java.util.Date;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.evildethow.security.util.Inet4AddressUtil;

/**
 * You enable request logging in Tomcat by attaching an AccessLogValve to your context or host.
 * It mirrors the custom formatting options that you’ll find in Apache’s CustomLog. So, you can
 * print out a %h for the request hostname but behind a load balancer you’ll just get the name
 * or address of the load balancer that’s forwarding the request. You could also just use
 * %{X-Forwarded-For}i to get access to the raw header value, but this will either just be an IP
 * address or a comma separated string of IP addresses. This may be useful for your purposes but
 * not mine, I want a hostname!
 *
 * Unfortunately, AccessLogValve doesn’t lend itself to easy extension, there are two
 * createAccessLogElement() methods that you’d ideally be able to overwrite in your own subclass
 * and return a new custom AccessLogElement for the character you’ve chosen to represent your log
 * element.
 *
 * The best we can do is overwrite the protected createLogElements and copy the functionality from
 * there and extend with our own. However, in my extension of AccessLogValve I’ve assumed that the
 * Tomcat boys will eventually fix the access modifiers for the createLogElement() methods so I’ve
 * just copied the whole class, named it AccessLogValve_ and changed the modifiers myself.
 * The plan being to remove this in the future and take the _ of the extended class name in my code.
 *
 * Usage:
 *
 * Simply package this JAR, put it in your Tomcat lib directory and make sure you use the right
 * class name when building your AccessLogValve descriptor.
 *
 * For more, see: http://tomcat.apache.org/tomcat-6.0-doc/config/valve.html#Access_Log_Valve
 *
 * Adapted from: http://rod.vagg.org/2011/07/handling-x-forwarded-for-in-java-and-tomcat/
 *
 */
public class AccessLogValve extends org.apache.catalina.valves.AccessLogValve_ {

    protected class ForwardedForAddressElement implements AccessLogElement {
        @Override
        public void addElement(StringBuffer buf, Date date, Request request, Response response, long time) {
            buf.append(Inet4AddressUtil.getAddressFromRequest(request));
        }
    }

    protected class ForwardedForHostElement extends ForwardedForAddressElement {
        @Override
        public void addElement(StringBuffer buf, Date date, Request request, Response response, long time) {
            buf.append(Inet4AddressUtil.getHostnameFromRequest(request));
        }
    }

    protected AccessLogElement createAccessLogElement(char pattern) {
        AccessLogElement accessLogElement = super.createAccessLogElement(pattern);
        if (accessLogElement instanceof StringElement) {
            switch (pattern) {
                case 'f' :
                    return new ForwardedForAddressElement();
                case 'F' :
                    return new ForwardedForHostElement();
            }
        }
        return accessLogElement;
    }
}
