package co.edu.corhuila.dlc.iam.adapter.in.http;

import jakarta.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Resolves the gateway-stamped client address only when the direct peer is trusted. */
@Component
public final class TrustedGatewayClientAddress {
    private final InetAddress gateway;

    public TrustedGatewayClientAddress(
            @Value("${IAM_TRUSTED_GATEWAY_IP:}") String trustedGatewayIp) {
        gateway = trustedGatewayIp == null || trustedGatewayIp.isBlank()
            ? null : literalIp(trustedGatewayIp);
    }

    public InetAddress resolve(HttpServletRequest request) {
        InetAddress peer = literalIp(request.getRemoteAddr());
        if (gateway == null || !gateway.equals(peer)) {
            return peer;
        }
        var headers = request.getHeaders("X-Forwarded-For");
        if (!headers.hasMoreElements()) {
            return peer;
        }
        String forwarded = headers.nextElement();
        if (headers.hasMoreElements()) {
            throw new IllegalArgumentException("Ambiguous forwarded client address");
        }
        // NGINX appends its verified $remote_addr to the right of caller input.
        String last = forwarded.substring(forwarded.lastIndexOf(',') + 1).trim();
        return literalIp(last);
    }

    private static InetAddress literalIp(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Missing client address");
        }
        String ip = value.trim();
        if (ip.indexOf(':') < 0) {
            String[] octets = ip.split("\\.", -1);
            if (octets.length != 4) {
                throw new IllegalArgumentException("Invalid IPv4 address");
            }
            for (String octet : octets) {
                if (octet.isEmpty() || octet.length() > 3 || !octet.matches("[0-9]+")
                    || Integer.parseInt(octet) > 255) {
                    throw new IllegalArgumentException("Invalid IPv4 address");
                }
            }
        } else if (!ip.matches("[0-9a-fA-F:.]+")) {
            throw new IllegalArgumentException("Invalid IPv6 address");
        }
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException invalid) {
            throw new IllegalArgumentException("Invalid client address", invalid);
        }
    }
}
