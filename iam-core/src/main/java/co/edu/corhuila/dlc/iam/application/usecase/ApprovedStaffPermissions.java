package co.edu.corhuila.dlc.iam.application.usecase;

import java.util.List;
import java.util.TreeSet;

/** Current role grants under the approved single-clinic policy. */
public final class ApprovedStaffPermissions {
    private ApprovedStaffPermissions() { }

    public static List<String> forRoles(List<String> roles) {
        if (roles == null || roles.isEmpty()) {
            throw new IllegalArgumentException("Approved staff roles are required");
        }
        var permissions = new TreeSet<String>();
        for (String role : roles) {
            if (role == null) throw new IllegalArgumentException("Invalid staff role");
            switch (role) {
                case "ADMINISTRATOR" -> {
                    permissions.add("clinical:read");
                    permissions.add("patients:read");
                    permissions.add("patients:register");
                    permissions.add("patients:write");
                }
                case "SECRETARY_ASSISTANT" -> {
                    permissions.add("patients:read");
                    permissions.add("patients:register");
                    permissions.add("patients:write");
                }
                case "DENTIST" -> permissions.add("patients:read");
                default -> throw new IllegalArgumentException("Invalid staff role");
            }
        }
        return List.copyOf(permissions);
    }
}
