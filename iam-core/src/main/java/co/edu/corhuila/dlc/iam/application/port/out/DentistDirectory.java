package co.edu.corhuila.dlc.iam.application.port.out;

import java.util.List;
import java.util.UUID;

/** ACTIVE accounts that currently hold DENTIST, projected to id and name (dlc-docs#164). */
public interface DentistDirectory {
    Page list(int page, int limit);

    record Entry(UUID id, String name) { }
    record Page(List<Entry> data, long total) { }
}
