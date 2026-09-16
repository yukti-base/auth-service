package org.yuktisetu.authservice.dto;

import jakarta.validation.constraints.NotNull;

/**
 * Soft delete — the ordinary, reversible delete every role-facing path uses.
 * The account is flagged deleted and hidden from active views, but nothing
 * leaves the database. See {@link HardDeleteRequest} for the IT-Admin-only
 * permanent removal.
 */
public record SoftDeleteRequest(@NotNull Long targetUserId) {
}
