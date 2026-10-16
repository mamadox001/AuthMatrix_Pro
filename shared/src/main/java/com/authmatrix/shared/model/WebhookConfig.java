package com.authmatrix.shared.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class WebhookConfig {

    private boolean enabled = false;

    @JsonProperty("webhook_url")
    private String webhookUrl;

    private String platform = "generic"; // "slack", "discord", "generic"

    @JsonProperty("notify_on")
    private String notifyOn = "all"; // "all", "regression_only", "bola_only"

    public WebhookConfig() {}

    public WebhookConfig(boolean enabled, String webhookUrl, String platform, String notifyOn) {
        this.enabled = enabled;
        this.webhookUrl = webhookUrl;
        this.platform = platform != null ? platform : "generic";
        this.notifyOn = notifyOn != null ? notifyOn : "all";
    }

    public boolean isEnabled() { return enabled; }
    public void setEnabled(boolean enabled) { this.enabled = enabled; }

    public String getWebhookUrl() { return webhookUrl; }
    public void setWebhookUrl(String webhookUrl) { this.webhookUrl = webhookUrl; }

    public String getPlatform() { return platform; }
    public void setPlatform(String platform) { this.platform = platform; }

    public String getNotifyOn() { return notifyOn; }
    public void setNotifyOn(String notifyOn) { this.notifyOn = notifyOn; }
}
