import org.codehaus.jackson.annotate.JsonProperty;
import org.codehaus.jackson.map.ObjectMapper;

import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

public class CrptApi {

    private static Logger logger = Logger.getLogger(String.valueOf(CrptApi.class));
    private final int requestLimit;
    private final TokenBucket tokenBucket;

    private static final String stringUrl = "https://markirovka.crpt.ru/api/v3/true-api/lk/documents/create";

    public CrptApi(TimeUnit timeUnit, int requestLimit) {
        if (requestLimit >= 0) {
            this.requestLimit = requestLimit;
        } else {
            throw new IllegalArgumentException("Значение должно быть больше 0");
        }
        tokenBucket = new TokenBucket(timeUnit, requestLimit);
    }

    public class TokenBucket {
        private final long capacity;
        private long availableTokens;
        private final long nanosToGenerationToken;
        private long lastRefillNanotime;

        public TokenBucket(TimeUnit timeUnit, long permits) {
            this.nanosToGenerationToken = timeUnit.toNanos(1) / permits;
            this.lastRefillNanotime = System.nanoTime();
            this.capacity = permits;
            this.availableTokens = permits;
        }

        public synchronized boolean tryConsume(int permits) {
            refill();
            if (this.availableTokens < permits) {
                return false;
            } else {
                this.availableTokens -= permits;
                return true;
            }
        }

        private void refill() {
            var now = System.nanoTime();
            var nanosSinceLastRefill = now - lastRefillNanotime;
            if (nanosSinceLastRefill <= nanosToGenerationToken) {
                return;
            }

            var tokensSinceLastRefill = nanosSinceLastRefill / nanosToGenerationToken;
            availableTokens = Math.min(capacity, availableTokens + tokensSinceLastRefill);
            lastRefillNanotime += tokensSinceLastRefill * nanosToGenerationToken;
        }
    }

    public class Product {
        @JsonProperty("product_date")
        private Date productDate;

        @JsonProperty("tnved_code")
        private String tnvedCode;

        @JsonProperty("uit_code")
        private String uitCode;

        @JsonProperty("uitu_code")
        private String uituCode;

        @JsonProperty("certificate_document")
        private CertificateType certificateDocument;

        @JsonProperty("certificate_document_date")
        private Date certificateDocumentDate;

        @JsonProperty("certificate_document_number")
        private String certificateDocumentNumber;

        public Product(Date productDate, String tnvedCode, String uitCode, String uituCode) {
            this.productDate = productDate;
            this.tnvedCode = tnvedCode;
            if (!uitCode.isBlank()) {
                this.uitCode = uitCode;
            } else if (!uituCode.isBlank()) {
                this.uituCode = uituCode;
            } else {
                throw new IllegalArgumentException("Не указаны уникальные идентификаторы");
            }
        }

        public Product(Date productDate, String tnvedCode, String uitCode, String uituCode,
                       CertificateType certificateType, Date certificateDocumentDate, String certificateDocumentNumber) {
            this(productDate, tnvedCode, uitCode, uituCode);
            this.certificateDocument = certificateType;
            this.certificateDocumentDate = certificateDocumentDate;
            this.certificateDocumentNumber = certificateDocumentNumber;
        }

        public void setCertificateDocument(CertificateType certificateType) {
            this.certificateDocument = certificateType;
        }

        public void setCertificateDocumentDate(Date certificateDocumentDate) {
            this.certificateDocumentDate = certificateDocumentDate;
        }

        public void setCertificateDocumentNumber(String certificateDocumentNumber) {
            this.certificateDocumentNumber = certificateDocumentNumber;
        }
    }

    public enum CertificateType {
        CONFORMITY_CERTIFICATE, CONFORMITY_DECLARATION
    }

    public class Document {

        @JsonProperty("description")
        Map<String, String> description = new HashMap<>();

        @JsonProperty("doc_id")
        private UUID id;

        @JsonProperty("doc_status")
        private String status;

        @JsonProperty("doc_type")
        private String docType;

        @JsonProperty("owner_inn")
        private String ownerInn;

        @JsonProperty("participant_inn")
        private String participantInn;

        @JsonProperty("producer_inn")
        private String producerInn;

        @JsonProperty("production_date")
        private Date productionDate;

        @JsonProperty("production_type")
        private String productionType;

        private List<Product> products = new ArrayList<>();

        @JsonProperty("reg_date")
        private Date regDate;

        @JsonProperty("reg_number")
        private String regNumber;

        public Document(String ownerInn, String status, String docType,
                        String participantInn, String producerInn, Date productionDate,
                        String productionType, String regNumber) {
            this.description.put("participant_inn", participantInn);
            this.id = UUID.randomUUID();
            this.status = status;
            this.docType = docType;
            this.ownerInn = ownerInn;
            this.participantInn = participantInn;
            this.producerInn = producerInn;
            this.productionDate = productionDate;
            this.productionType = productionType;
            this.regDate = new Date();
            this.regNumber = regNumber;
        }

        public void addProduct(Product product) {
            products.add(product);
        }
    }

    public void createDocument(Document document, String signature) throws Exception {

        URL url;
        HttpURLConnection connection;

        if (tokenBucket.tryConsume(requestLimit)) {

            try {
                url = new URL(stringUrl);
                connection = (HttpURLConnection) url.openConnection();
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
            connection.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
            connection.setRequestProperty("Accept", "application/json");
            connection.setRequestProperty("Accept-Charset", "utf-8");
            connection.setRequestMethod("POST");
            connection.setDoOutput(true);

            String documentAsString = getObjectAsString(document);
            String documentJson64 = Base64.getEncoder().encodeToString(documentAsString.getBytes());
            String signedDocument = signSHA256RSA(documentAsString, signature);
            Map<String, String> bodyRequest = new HashMap<>();
            bodyRequest.put("document_format", "MANUAL");
            bodyRequest.put("product_document", documentJson64);
            bodyRequest.put("signature", signedDocument);
            bodyRequest.put("type", "SETS_AGGREGATION");
            bodyRequest.put("product_group", "group_of_goods"); // группа товара
            String bodyAsString = getObjectAsString(bodyRequest);

            try (OutputStream os = connection.getOutputStream()) {
                byte[] input = bodyAsString.getBytes(StandardCharsets.UTF_8);
                os.write(input, 0, input.length);
            }

            if (connection.getResponseCode() != 200) {
                logger.warning("Не удалось выполнить ввод оборота");                
            }           
        }      
    }

    private String signSHA256RSA(String input, String signature) throws NoSuchAlgorithmException, InvalidKeySpecException, SignatureException, InvalidKeyException {

        byte[] b1 = Base64.getDecoder().decode(signature);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(b1);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(kf.generatePrivate(spec));
        privateSignature.update(input.getBytes(StandardCharsets.UTF_8));
        byte[] s = privateSignature.sign();
        return Base64.getEncoder().encodeToString(s);
    }

    private String getObjectAsString(Object object) throws IOException {
        return new ObjectMapper().writeValueAsString(object);
    }
}
