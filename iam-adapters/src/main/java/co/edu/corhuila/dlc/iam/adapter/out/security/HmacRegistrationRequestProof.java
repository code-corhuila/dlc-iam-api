package co.edu.corhuila.dlc.iam.adapter.out.security;

import co.edu.corhuila.dlc.iam.application.port.out.RegistrationRequestProof;
import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/** Keyed replay proof: request fields, including the password, never persist in cleartext. */
public final class HmacRegistrationRequestProof implements RegistrationRequestProof {
    private final byte[] key;

    public HmacRegistrationRequestProof(byte[] key) {
        if (key == null || key.length < 32) {
            throw new IllegalArgumentException("A 256-bit registration proof key is required");
        }
        this.key = key.clone();
    }

    @Override
    public byte[] prove(String normalizedEmail, String password, String name, String role) {
        if (normalizedEmail == null || password == null || name == null || role == null) {
            throw new IllegalArgumentException("Invalid registration proof input");
        }
        try {
            var bytes = new ByteArrayOutputStream();
            var fields = new DataOutputStream(bytes);
            write(fields, normalizedEmail);
            write(fields, password);
            write(fields, name);
            write(fields, role);
            Mac hmac = Mac.getInstance("HmacSHA256");
            hmac.init(new SecretKeySpec(key, "HmacSHA256"));
            return hmac.doFinal(bytes.toByteArray());
        } catch (GeneralSecurityException | IOException failure) {
            throw new IllegalStateException("Cannot prove registration request", failure);
        }
    }

    private static void write(DataOutputStream out, String value) throws IOException {
        byte[] bytes = value.getBytes(StandardCharsets.UTF_8);
        out.writeInt(bytes.length);
        out.write(bytes);
    }
}
