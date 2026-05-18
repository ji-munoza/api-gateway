package cl.plataforma_gimnasio.api_gateway.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.List;

@Component
public class JwtUtils {

    // 🌟 Usamos una frase directa de más de 32 bytes/caracteres para cumplir con HMAC-SHA256
    private final String SECRET_KEY_PLAIN = "esta-es-una-clave-secreta-ultra-segura-y-larga-para-el-gimnasio-2026";

    private SecretKey getSigningKey() {
        // Genera los bytes exactos basándose en el string de texto plano
        return Keys.hmacShaKeyFor(SECRET_KEY_PLAIN.getBytes(StandardCharsets.UTF_8));
    }

    public Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    @SuppressWarnings("unchecked")
    public List<String> extractRoles(String token) {
        return extractAllClaims(token).get("roles", List.class);
    }

    public boolean validateToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return !claims.getExpiration().before(new Date());
        } catch (Exception e) {
            // Imprime el error real en la consola por si la firma falla por otra razón
            System.out.println("Error al validar token: " + e.getMessage());
            return false;
        }
    }
}