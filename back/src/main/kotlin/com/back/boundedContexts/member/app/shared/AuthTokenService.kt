package com.back.boundedContexts.member.app.shared

import com.back.boundedContexts.member.domain.shared.Member
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.util.Base64

@Service
class AuthTokenService {
    fun genAccessToken(member: Member): String =
        Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("${member.id}:${member.username}:${member.nickname}".toByteArray(StandardCharsets.UTF_8))
}
