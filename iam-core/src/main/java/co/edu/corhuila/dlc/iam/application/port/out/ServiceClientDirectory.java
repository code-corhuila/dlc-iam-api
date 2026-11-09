package co.edu.corhuila.dlc.iam.application.port.out;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/** ADR-020: provisioned service clients with their hashed secrets and granted audience/scope pairs. */
@FunctionalInterface
public interface ServiceClientDirectory {
    Optional<Client> find(String clientId);

    record Client(String clientId, boolean active, List<String> secretHashes, Set<Grant> grants) {
        public Client {
            secretHashes = List.copyOf(secretHashes);
            grants = Set.copyOf(grants);
        }
    }

    record Grant(String audience, String scope) { }
}
