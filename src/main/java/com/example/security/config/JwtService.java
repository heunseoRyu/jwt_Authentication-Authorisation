package com.example.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // jwt에서 얘기하는 모든 username은 해당 유저의 unique 값

    private static final String SECRET_KEY = "9544e16c6f91a8b1debd74340867f0d71bd96566be3f2502930aa3dbd67665ad";

    public String extractUsername(String token) { // extracting userName
        return extractClaim(token, Claims::getSubject);
        /* Claims :: getSubject ???
        "Claims"는 일반적으로 토큰 기반의 인증 시스템에서 사용되는 용어입니다.
        주로 JWT(Json Web Token)에서 많이 쓰이며, 토큰 안에 담겨 있는 정보들을 의미합니다.
        "Claims"에는 사용자의 정보나 토큰의 유효 기간 등이 포함될 수 있습니다.

        getSubject()는 JWT나 다른 토큰에서 "sub"라는 클레임(claim)의 값을 가져오는 메서드입니다.
        "sub" 클레임은 주로 토큰의 소유자나 주체(subject)를 식별하기 위해 사용됩니다.
        이 클레임은 토큰이 나타내는 개체(entity)에 대한 정보를 포함할 수 있습니다.
        주로 사용자 ID나 사용자의 고유 식별자가 "sub" 클레임에 들어갑니다.

        따라서 Claims::getSubject() 메서드를 호출하면
        해당 토큰의 주체(subject)에 대한 정보를 반환할 것입니다.
        이 정보는 해당 토큰이 나타내는 개체(사용자, 서비스 등)를 식별하는 데 사용될 수 있습니다.
        */
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver){ // 즉, Claims로 받고 apply때 T로 반환함.
        final Claims claims = extractAllClaims(token); // extract all the claims
        return claimsResolver.apply(claims); // apply : 신청하다-> Claims형 자료를 T로 바꿔서 반환 // 전달 인자와 반환 값이 모두 존재할 때 값 반환
    }

    // extraClaim없이 token을 생성하고 싶을 시
    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(
            Map<String,Object> extraClaims, // token에 추가적으로 저장하고 싶은 정보 저장가능
            UserDetails userDetails
    ){
        return Jwts.builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername()) // userDetail 옛날에 override해줬음.
                .setIssuedAt(new Date(System.currentTimeMillis())) // 토큰 생성 시간
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) // 토큰 만료 시간 : 24시간 뒤
                .signWith(getSignInKey(), SignatureAlgorithm.HS256) // signature
                .compact(); // compact() : generate and return token
    }

    // 토큰 유효성 검사
    public boolean isTokenValid(String token,UserDetails userDetails){
        final String username = extractUsername(token); // extractusername() : 앞에 정의함.
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token){
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) { // 클레임의 모든 정보 가져오기
        return Jwts.parserBuilder()
                .setSigningKey(getSignInKey()) // 헤더 가져오기
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY); // secret key 디코딩
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
