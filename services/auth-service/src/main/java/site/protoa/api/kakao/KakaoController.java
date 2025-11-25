package site.protoa.api.kakao;

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
public class KakaoController {

    @Value("${kakao.rest-api-key}")
    private String kakaoRestApiKey;

    @Value("${kakao.redirect-uri}")
    private String kakaoRedirectUri;

    @Value("${security.jwt.secret}")
    private String jwtSecret;

    @Value("${frontend.login-callback-url}")
    private String frontendCallbackUrl;

    private final WebClient webClient = WebClient.create();

    @GetMapping("/oauth2/kakao/callback")
    public ResponseEntity<?> kakaoCallback(@RequestParam("code") String code) {
        try {
            // 1. 카카오 토큰 요청
            Map<String, String> formData = new HashMap<>();
            formData.put("grant_type", "authorization_code");
            formData.put("client_id", kakaoRestApiKey);
            formData.put("redirect_uri", kakaoRedirectUri);
            formData.put("code", code);

            String bodyString = formData.entrySet().stream()
                    .map(e -> URLEncoder.encode(e.getKey(), StandardCharsets.UTF_8) + "="
                            + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                    .collect(Collectors.joining("&"));

            Map<String, Object> tokenResponse = webClient.post()
                    .uri("https://kauth.kakao.com/oauth/token")
                    .contentType(org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED)
                    .bodyValue(bodyString)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("success", false, "message", "카카오 토큰 요청 실패"));
            }

            String accessToken = (String) tokenResponse.get("access_token");

            // 2. 유저 정보 조회
            Map<String, Object> userInfo = webClient.get()
                    .uri("https://kapi.kakao.com/v2/user/me")
                    .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();

            if (userInfo == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(Map.of("success", false, "message", "카카오 사용자 정보 조회 실패"));
            }

            String kakaoId = userInfo.get("id").toString();

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
                    .setSubject(kakaoId)
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
                    .body(Map.of("success", false, "message", "카카오 로그인 처리 중 오류: " + e.getMessage()));
        }
    }
}
