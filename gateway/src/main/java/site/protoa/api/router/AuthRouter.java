package site.protoa.api.router;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.ServerResponse;

import javax.crypto.SecretKey;
import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

@Configuration
public class AuthRouter {

    @Value("${kakao.rest-api-key}")
    private String kakaoRestApiKey;

    @Value("${kakao.redirect-uri}")
    private String kakaoRedirectUri;

    @Value("${naver.client-id}")
    private String naverClientId;

    @Value("${naver.redirect-uri}")
    private String naverRedirectUri;

    @Value("${google.client-id}")
    private String googleClientId;

    @Value("${google.redirect-uri}")
    private String googleRedirectUri;

    @Value("${security.jwt.secret}")
    private String jwtSecret;

    @Value("${frontend.login-callback-url}")
    private String frontendCallbackUrl;

    private final WebClient webClient = WebClient.create();
    private static final Logger logger = LoggerFactory.getLogger(AuthRouter.class);
    private static volatile int requestCounter = 0;

    @Bean
    public RouterFunction<ServerResponse> kakaoRoutes() {
        // /kakao/login도 처리 (Next.js에서 호출)
        return route(GET("/kakao/login"), request -> {
            // 요청 카운터 증가 (스레드 안전)
            int currentRequest = ++requestCounter;
            // 간결한 로그 출력
            logger.info("✅ [요청 #{}] 카카오 로그인 요청 성공", currentRequest);

            // 카카오 로그인 페이지로 리다이렉트
            String kakaoAuthUrl = "https://kauth.kakao.com/oauth/authorize"
                    + "?client_id=" + kakaoRestApiKey
                    + "&redirect_uri=" + kakaoRedirectUri
                    + "&response_type=code";
            return ServerResponse.temporaryRedirect(URI.create(kakaoAuthUrl)).build();
        }).andRoute(GET("/oauth2/kakao/login"), request -> {
            // 카카오 로그인 페이지로 리다이렉트
            String kakaoAuthUrl = "https://kauth.kakao.com/oauth/authorize"
                    + "?client_id=" + kakaoRestApiKey
                    + "&redirect_uri=" + kakaoRedirectUri
                    + "&response_type=code";
            return ServerResponse.temporaryRedirect(URI.create(kakaoAuthUrl)).build();
        });
    }

    @Bean
    public RouterFunction<ServerResponse> naverRoutes() {
        return route(GET("/naver/login"), request -> {
            String state = java.util.UUID.randomUUID().toString();
            logger.info("✅ 네이버 로그인 요청, state: {}", state);
            String naverAuthUrl = "https://nid.naver.com/oauth2.0/authorize" + "?client_id=" + naverClientId
                    + "&redirect_uri=" + URLEncoder.encode(naverRedirectUri, StandardCharsets.UTF_8)
                    + "&response_type=code" + "&state=" + state;
            return ServerResponse.temporaryRedirect(URI.create(naverAuthUrl)).build();
        }).andRoute(GET("/oauth2/naver/login"), request -> {
            String state = java.util.UUID.randomUUID().toString();
            String naverAuthUrl = "https://nid.naver.com/oauth2.0/authorize" + "?client_id=" + naverClientId
                    + "&redirect_uri=" + URLEncoder.encode(naverRedirectUri, StandardCharsets.UTF_8)
                    + "&response_type=code" + "&state=" + state;
            return ServerResponse.temporaryRedirect(URI.create(naverAuthUrl)).build();
        });
    }

    @Bean
    public RouterFunction<ServerResponse> googleRoutes() {
        return route(GET("/google/login"), request -> {
            String state = java.util.UUID.randomUUID().toString();
            logger.info("✅ 구글 로그인 요청, state: {}", state);

            String googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth"
                    + "?client_id=" + googleClientId
                    + "&redirect_uri=" + URLEncoder.encode(googleRedirectUri, StandardCharsets.UTF_8)
                    + "&response_type=code"
                    + "&scope=" + URLEncoder.encode("openid email profile", StandardCharsets.UTF_8)
                    + "&state=" + state
                    + "&access_type=offline";

            return ServerResponse.temporaryRedirect(URI.create(googleAuthUrl)).build();
        }).andRoute(GET("/oauth2/google/login"), request -> {
            String state = java.util.UUID.randomUUID().toString();

            String googleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth"
                    + "?client_id=" + googleClientId
                    + "&redirect_uri=" + URLEncoder.encode(googleRedirectUri, StandardCharsets.UTF_8)
                    + "&response_type=code"
                    + "&scope=" + URLEncoder.encode("openid email profile", StandardCharsets.UTF_8)
                    + "&state=" + state
                    + "&access_type=offline";

            return ServerResponse.temporaryRedirect(URI.create(googleAuthUrl)).build();
        });
    }

    // /oauth2/kakao/callback은 application.yaml의 라우팅을 통해 Auth-Service로 전달됨
    // RouterFunction 제거하여 Auth-Service의 KakaoController가 처리하도록 함
    /*
     * }).andRoute(GET("/oauth2/kakao/callback"), request -> {
     * // 카카오에서 받은 code
     * String code = request.queryParam("code").orElse("");
     * if (code.isEmpty()) {
     * return ServerResponse.badRequest().bodyValue("code is missing");
     * }
     * 
     * // 카카오 토큰 요청 (Reactive 스타일 - block() 제거)
     * return webClient.post()
     * .uri(uriBuilder -> uriBuilder
     * .scheme("https")
     * .host("kauth.kakao.com")
     * .path("/oauth/token")
     * .queryParam("grant_type", "authorization_code")
     * .queryParam("client_id", kakaoRestApiKey)
     * .queryParam("redirect_uri", kakaoRedirectUri)
     * .queryParam("code", code)
     * .build())
     * .accept(MediaType.APPLICATION_JSON)
     * .retrieve()
     * .bodyToMono(Map.class)
     * .flatMap(tokenResponse -> {
     * if (tokenResponse == null || !tokenResponse.containsKey("access_token")) {
     * return ServerResponse.status(500)
     * .bodyValue("Failed to get Kakao access token");
     * }
     * 
     * String accessToken = (String) tokenResponse.get("access_token");
     * 
     * // 사용자 정보 조회
     * return webClient.get()
     * .uri("https://kapi.kakao.com/v2/user/me")
     * .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
     * .accept(MediaType.APPLICATION_JSON)
     * .retrieve()
     * .bodyToMono(Map.class)
     * .flatMap(userInfo -> {
     * if (userInfo == null) {
     * return ServerResponse.status(500)
     * .bodyValue("Failed to get user info from Kakao");
     * }
     * 
     * // 카카오 사용자 ID 추출
     * Object idObj = userInfo.get("id");
     * String kakaoId = idObj != null ? idObj.toString() : "unknown";
     * 
     * // JWT 발급 (1일 유효)
     * // SecretKey 생성 (최소 256비트 = 32바이트 필요)
     * byte[] keyBytes = jwtSecret.getBytes(StandardCharsets.UTF_8);
     * // 키가 32바이트보다 작으면 패딩 추가
     * if (keyBytes.length < 32) {
     * byte[] paddedKey = new byte[32];
     * System.arraycopy(keyBytes, 0, paddedKey, 0, keyBytes.length);
     * // 나머지를 0으로 채움
     * keyBytes = paddedKey;
     * } else if (keyBytes.length > 32) {
     * // 32바이트로 자름
     * byte[] trimmedKey = new byte[32];
     * System.arraycopy(keyBytes, 0, trimmedKey, 0, 32);
     * keyBytes = trimmedKey;
     * }
     * SecretKey key = Keys.hmacShaKeyFor(keyBytes);
     * 
     * String jwt = Jwts.builder()
     * .setSubject(kakaoId)
     * .setIssuedAt(new Date())
     * .setExpiration(new Date(System.currentTimeMillis() + 86400000))
     * .signWith(key)
     * .compact();
     * 
     * // Next.js로 리다이렉트
     * String redirectUrl = frontendCallbackUrl + "?token=" + jwt;
     * 
     * // 간결한 로그 출력
     * logger.info("✅ 카카오 로그인 성공! (사용자 ID: {})", kakaoId);
     * 
     * return ServerResponse.temporaryRedirect(URI.create(redirectUrl)).build();
     * });
     * })
     * .onErrorResume(error -> {
     * // 에러 발생 시 에러 메시지 반환
     * return ServerResponse.status(500)
     * .bodyValue("Error during Kakao login: " + error.getMessage());
     * });
     * });
     */
}
