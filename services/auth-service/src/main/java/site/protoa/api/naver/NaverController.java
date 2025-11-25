package site.protoa.api.naver;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;
import java.net.URLEncoder;

@RestController
@CrossOrigin(origins = "http://localhost:3000", allowCredentials = "true")
public class NaverController {

    @Value("${naver.client-id}")
    private String naverClientId;

    @Value("${naver.client-secret}")
    private String naverClientSecret;

    @Value("${naver.redirect-uri}")
    private String naverRedirectUri;

    @Value("${security.jwt.secret}")
    private String jwtSecret;

    @Value("${frontend.login-callback-url}")
    private String frontendCallbackUrl;

    private final WebClient webClient = WebClient.create();

    @GetMapping("/oauth2/naver/login")
    public ResponseEntity<?> naverLogin() {
        try {
            String state = java.util.UUID.randomUUID().toString();
            String authorizeUrl = "https://nid.naver.com/oauth2.0/authorize?response_type=code"
                    + "&client_id=" + naverClientId
                    + "&redirect_uri=" + URLEncoder.encode(naverRedirectUri, StandardCharsets.UTF_8)
                    + "&state=" + state;

            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, authorizeUrl)
                    .build();

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "message", "네이버 로그인 URL 생성 중 오류: " + e.getMessage()));
        }
    }

    @GetMapping("/oauth2/naver/callback")
    public ResponseEntity<?> naverCallback(@RequestParam("code") String code,
            @RequestParam("state") String state) {
        try {
            // 1. Access token 요청
            Map<String, String> params = new HashMap<>();
            params.put("grant_type", "authorization_code");
            params.put("client_id", naverClientId);
            params.put("client_secret", naverClientSecret);
            params.put("code", code);
            params.put("state", state);

            String bodyString = params.entrySet().stream()
                    .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                            + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));

            Map<String, Object> tokenResponse = webClient.post()
                    .uri("https://nid.naver.com/oauth2.0/token")
                    .header(HttpHeaders.CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .bodyValue(bodyString)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("success", false, "message", "네이버 토큰 요청 실패"));
            }

            String accessToken = (String) tokenResponse.get("access_token");

            // 2. 유저 정보 조회
            Map<String, Object> userInfo = webClient.get()
                    .uri("https://openapi.naver.com/v1/nid/me")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (userInfo == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("success", false, "message", "네이버 사용자 정보 조회 실패"));
            }

            String naverId = ((Map<String, Object>) userInfo.get("response")).get("id").toString();

            // 3. JWT 발급
            byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
            if (keyBytes.length < 32) {
                byte[] paddedKey = new byte[32];
                System.arraycopy(keyBytes, 0, paddedKey, 0, keyBytes.length);
                keyBytes = paddedKey;
            } else if (keyBytes.length > 32) {
                byte[] trimmedKey = new byte[32];
                System.arraycopy(keyBytes, 0, trimmedKey, 0, 32);
                keyBytes = trimmedKey;
            }
            SecretKey key = Keys.hmacShaKeyFor(keyBytes);

            String jwt = Jwts.builder()
                    .setSubject(naverId)
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 86400000))
                    .signWith(key)
                    .compact();

            String redirectUrl = frontendCallbackUrl + "?token=" + jwt;

            return ResponseEntity.status(HttpStatus.FOUND)
                    .header(HttpHeaders.LOCATION, redirectUrl)
                    .build();

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("success", false, "message", "네이버 로그인 처리 중 오류: " + e.getMessage()));
        }
    }
}
