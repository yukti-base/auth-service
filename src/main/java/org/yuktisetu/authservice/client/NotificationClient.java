package org.yuktisetu.authservice.client;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import org.yuktisetu.messaging.events.NotificationDispatchEvent;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

/**
 * auth-service's door onto notification-service.
 *
 * Deliberately here and not in core. core is on every service's classpath, so a
 * shared client there would hand admin-service a way into notification-service
 * that the fleet's rule says it must not take -- admin-service keeps its own
 * mail on core's EmailService so admins never queue behind a service busy
 * serving students. A per-service client keeps that boundary visible in the
 * dependency graph rather than resting on everyone remembering the rule.
 *
 * Every method here takes a LIST. There is no single-recipient overload on
 * purpose: the way a caller accidentally turns a fifty-person invite into fifty
 * HTTP calls is by being handed a convenient one-person method and putting it
 * in a loop.
 */
@Slf4j
@Component
@ConditionalOnProperty(name = "yuktisetu.notification.client.enabled", havingValue = "true")
public class NotificationClient {

    private final RestClient restClient;
    private final String serviceToken;

    public NotificationClient(@Value("${yuktisetu.notification.base-url}") String baseUrl,
                              @Value("${yuktisetu.notification.service-token}") String serviceToken) {
        this.serviceToken = serviceToken;
        this.restClient = RestClient.builder()
                .baseUrl(baseUrl)
                .requestFactory(clientRequestFactory())
                .build();
    }

    private static org.springframework.http.client.ClientHttpRequestFactory clientRequestFactory() {
        var factory = new org.springframework.http.client.SimpleClientHttpRequestFactory();
        // Short and finite. A notification is never worth holding an invite
        // transaction open on a slow downstream.
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(10));
        return factory;
    }

    /**
     * Sends one dispatch covering every recipient in the list.
     *
     * @param dispatchId stable idempotency key. Generate it ONCE per logical
     *                   dispatch and reuse it across retries -- a fresh uuid per
     *                   attempt defeats the unique constraint and mails everyone
     *                   twice.
     * @return true when notification-service accepted the batch.
     */
    public boolean dispatch(String dispatchId, NotificationDispatchEvent event) {
        try {
            restClient.post()
                    .uri("/dispatch")
                    .header("X-Service-Token", serviceToken)
                    .header("Idempotency-Key", dispatchId)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(event)
                    .retrieve()
                    .toBodilessEntity();

            log.info("Dispatch {} accepted by notification-service: type={} recipients={}",
                    dispatchId, event.notificationType(),
                    event.recipients() == null ? 0 : event.recipients().size());
            return true;

        } catch (Exception e) {
            // Never propagate. A failed notification must not roll back the
            // business action that triggered it -- an invite whose email bounced
            // is a user who still exists and can be re-invited, whereas a
            // rolled-back invite is a user who does not.
            log.error("Dispatch {} rejected by notification-service (type={}, recipients={}): {}",
                    dispatchId, event.notificationType(),
                    event.recipients() == null ? 0 : event.recipients().size(), e.getMessage(), e);
            return false;
        }
    }

    /** Convenience builder for the role-invite dispatch, still list-shaped. */
    public static NotificationDispatchEvent roleInvite(List<NotificationDispatchEvent.Recipient> recipients) {
        return new NotificationDispatchEvent(
                "ROLE_INVITE",
                "INFO",
                "invite-role-email",
                "You're invited to YuktiSetu",
                null,
                Map.of(),
                recipients,
                List.of(),
                Set.of("EMAIL"));
    }

    public static String newDispatchId() {
        return UUID.randomUUID().toString();
    }
}
