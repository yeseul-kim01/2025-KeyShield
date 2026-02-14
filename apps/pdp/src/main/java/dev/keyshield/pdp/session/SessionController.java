package dev.keyshield.pdp.session;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/session")
public class SessionController {

    @PostMapping("/start")
    public Map<String, String> startSession() {
        String sessionId = UUID.randomUUID().toString();
        return Map.of("sessionId", sessionId);
    }
}
