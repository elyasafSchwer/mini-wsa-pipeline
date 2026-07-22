package com.es.wsa.storage;

import com.es.wsa.domain.SecurityEvent;
import org.springframework.data.annotation.Id;
import org.springframework.data.elasticsearch.annotations.DateFormat;
import org.springframework.data.elasticsearch.annotations.Document;
import org.springframework.data.elasticsearch.annotations.Field;
import org.springframework.data.elasticsearch.annotations.FieldType;

import java.time.OffsetDateTime;

/**
 * Elasticsearch persistence view of a fully-enriched {@link SecurityEvent}, mapped to the
 * {@code security-events} index.
 *
 * <p>This is deliberately a <em>separate</em> type from the domain {@link SecurityEvent}
 * record. The domain model is an immutable record optimised for the pipeline; the storage
 * model is a mutable POJO because Spring Data Elasticsearch instantiates documents via a
 * no-arg constructor and field access when reading hits back. Keeping the two apart means
 * the index mapping (analysers, field types, formats) can evolve independently of the
 * ingestion contract.
 *
 * <h2>Mapping choices</h2>
 * <ul>
 *   <li><b>Identifiers &amp; enums as {@code Keyword}</b> — exact-match/aggregation fields
 *       ({@code eventId}, {@code policyId}, {@code clientIp}, {@code severity},
 *       {@code action}, {@code attackType}, …) are keywords, not analysed text, so they
 *       aggregate and filter cleanly in Kibana.</li>
 *   <li><b>Free text as {@code Text}</b> — {@code userAgent}, {@code path} and the rule
 *       {@code message} are analysed text for full-text search.</li>
 *   <li><b>Timestamps as {@code Date}</b> — {@code timestamp} and {@code receivedAt} use
 *       {@link DateFormat#date_time} so ISO-8601 offset strings (what
 *       {@link OffsetDateTime} serialises to) are parsed by Elasticsearch seamlessly.</li>
 *   <li><b>Nested objects flattened</b> — the domain {@code Rule} and {@code GeoLocation}
 *       sub-records are flattened into prefixed scalar fields ({@code rule*}, {@code geo*})
 *       to keep the mapping simple and query-friendly.</li>
 * </ul>
 */
@Document(indexName = "security-events")
public class SecurityEventDocument {

    /**
     * Document id. Uses the client-supplied {@code eventId} so re-indexing the same event
     * is idempotent (upsert by id) rather than producing duplicates.
     */
    @Id
    private String eventId;

    @Field(type = FieldType.Date, format = DateFormat.date_time)
    private OffsetDateTime timestamp;

    @Field(type = FieldType.Long)
    private Long configId;

    @Field(type = FieldType.Keyword)
    private String policyId;

    @Field(type = FieldType.Ip)
    private String clientIp;

    @Field(type = FieldType.Keyword)
    private String hostname;

    // Analysed for full-text search (attackers probe many path variants), plus a raw
    // keyword sub-field for exact filtering/aggregation.
    @Field(type = FieldType.Text)
    private String path;

    @Field(type = FieldType.Keyword)
    private String method;

    @Field(type = FieldType.Integer)
    private Integer statusCode;

    @Field(type = FieldType.Text)
    private String userAgent;

    @Field(type = FieldType.Long)
    private Long requestSize;

    @Field(type = FieldType.Long)
    private Long responseSize;

    /** Server-side ingestion timestamp; same ISO-8601 offset format as {@link #timestamp}. */
    @Field(type = FieldType.Date, format = DateFormat.date_time)
    private OffsetDateTime receivedAt;

    // --- Rule (flattened from the domain Rule sub-record) ---

    @Field(type = FieldType.Keyword)
    private String ruleId;

    @Field(type = FieldType.Keyword)
    private String ruleName;

    @Field(type = FieldType.Text)
    private String ruleMessage;

    @Field(type = FieldType.Keyword)
    private String ruleSeverity;

    @Field(type = FieldType.Keyword)
    private String ruleCategory;

    @Field(type = FieldType.Keyword)
    private String ruleAction;

    // --- GeoLocation (flattened from the domain GeoLocation sub-record) ---

    @Field(type = FieldType.Keyword)
    private String geoCountry;

    @Field(type = FieldType.Keyword)
    private String geoCity;

    // --- Enrichment-derived fields ---

    @Field(type = FieldType.Keyword)
    private String attackType;

    @Field(type = FieldType.Integer)
    private Integer threatScore;

    /** No-arg constructor required by Spring Data Elasticsearch for read-back mapping. */
    public SecurityEventDocument() {
    }

    public String getEventId() {
        return eventId;
    }

    public void setEventId(String eventId) {
        this.eventId = eventId;
    }

    public OffsetDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(OffsetDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public Long getConfigId() {
        return configId;
    }

    public void setConfigId(Long configId) {
        this.configId = configId;
    }

    public String getPolicyId() {
        return policyId;
    }

    public void setPolicyId(String policyId) {
        this.policyId = policyId;
    }

    public String getClientIp() {
        return clientIp;
    }

    public void setClientIp(String clientIp) {
        this.clientIp = clientIp;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public String getPath() {
        return path;
    }

    public void setPath(String path) {
        this.path = path;
    }

    public String getMethod() {
        return method;
    }

    public void setMethod(String method) {
        this.method = method;
    }

    public Integer getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(Integer statusCode) {
        this.statusCode = statusCode;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public Long getRequestSize() {
        return requestSize;
    }

    public void setRequestSize(Long requestSize) {
        this.requestSize = requestSize;
    }

    public Long getResponseSize() {
        return responseSize;
    }

    public void setResponseSize(Long responseSize) {
        this.responseSize = responseSize;
    }

    public OffsetDateTime getReceivedAt() {
        return receivedAt;
    }

    public void setReceivedAt(OffsetDateTime receivedAt) {
        this.receivedAt = receivedAt;
    }

    public String getRuleId() {
        return ruleId;
    }

    public void setRuleId(String ruleId) {
        this.ruleId = ruleId;
    }

    public String getRuleName() {
        return ruleName;
    }

    public void setRuleName(String ruleName) {
        this.ruleName = ruleName;
    }

    public String getRuleMessage() {
        return ruleMessage;
    }

    public void setRuleMessage(String ruleMessage) {
        this.ruleMessage = ruleMessage;
    }

    public String getRuleSeverity() {
        return ruleSeverity;
    }

    public void setRuleSeverity(String ruleSeverity) {
        this.ruleSeverity = ruleSeverity;
    }

    public String getRuleCategory() {
        return ruleCategory;
    }

    public void setRuleCategory(String ruleCategory) {
        this.ruleCategory = ruleCategory;
    }

    public String getRuleAction() {
        return ruleAction;
    }

    public void setRuleAction(String ruleAction) {
        this.ruleAction = ruleAction;
    }

    public String getGeoCountry() {
        return geoCountry;
    }

    public void setGeoCountry(String geoCountry) {
        this.geoCountry = geoCountry;
    }

    public String getGeoCity() {
        return geoCity;
    }

    public void setGeoCity(String geoCity) {
        this.geoCity = geoCity;
    }

    public String getAttackType() {
        return attackType;
    }

    public void setAttackType(String attackType) {
        this.attackType = attackType;
    }

    public Integer getThreatScore() {
        return threatScore;
    }

    public void setThreatScore(Integer threatScore) {
        this.threatScore = threatScore;
    }
}
