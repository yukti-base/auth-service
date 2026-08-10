package org.yuktisetu.authservice.dto;

public record AcceptInviteRequest(String token, String newPassword) {
}
