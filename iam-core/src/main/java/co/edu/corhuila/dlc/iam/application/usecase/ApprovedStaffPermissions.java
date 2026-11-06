package co.edu.corhuila.dlc.iam.application.usecase;

import java.util.List;
import java.util.TreeSet;

/** Current role grants. Individual clinical grants remain unapproved. */
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
                case "ADMINISTRATOR", "SECRETARY_ASSISTANT" -> {
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
