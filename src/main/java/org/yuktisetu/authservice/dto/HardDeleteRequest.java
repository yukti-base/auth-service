package org.yuktisetu.authservice.dto;

import jakarta.validation.constraints.NotNull;

/**
 * Permanent, irreversible removal of the row. IT Admin only, and only for an
 * account that is already soft-deleted and has no connected records left.
 * Everything else in the system soft-deletes — see {@link SoftDeleteRequest}.
 */
public record HardDeleteRequest(@NotNull Long targetUserId) {
}
