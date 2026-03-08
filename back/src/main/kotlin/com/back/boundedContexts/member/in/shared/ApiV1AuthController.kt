package com.back.boundedContexts.member.`in`.shared

import com.back.boundedContexts.member.app.MemberFacade
import com.back.boundedContexts.member.app.shared.AuthTokenService
import com.back.boundedContexts.member.dto.MemberDto
import com.back.boundedContexts.member.dto.MemberWithUsernameDto
import com.back.global.exception.app.AppException
import com.back.global.rsData.RsData
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.HttpHeaders
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController

@RestController
@RequestMapping("/member/api/v1/auth")
class ApiV1AuthController(
    private val memberFacade: MemberFacade,
    private val authTokenService: AuthTokenService,
) {
    data class MemberLoginRequest(
        @field:NotBlank
        @field:Size(min = 2, max = 30)
        val username: String,
        @field:NotBlank
        @field:Size(min = 2, max = 30)
        val password: String,
    )

    data class MemberLoginResBody(
        val item: MemberDto,
        val apiKey: String,
        val accessToken: String,
    )

    @PostMapping("/login")
    @Transactional(readOnly = true)
    fun login(
        @RequestBody @Valid reqBody: MemberLoginRequest,
        response: HttpServletResponse,
    ): RsData<MemberLoginResBody> {
        val member = memberFacade.findByUsername(reqBody.username)
            ?: throw AppException("401-1", "존재하지 않는 아이디입니다.")

        memberFacade.checkPassword(member, reqBody.password)

        val accessToken = authTokenService.genAccessToken(member)

        response.addCookie(Cookie("apiKey", member.apiKey).apply {
            path = "/"
            isHttpOnly = true
        })
        response.addCookie(Cookie("accessToken", accessToken).apply {
            path = "/"
            isHttpOnly = true
        })

        return RsData(
            "200-1",
            "${member.nickname}님 환영합니다.",
            MemberLoginResBody(
                item = MemberDto(member),
                apiKey = member.apiKey,
                accessToken = accessToken,
            )
        )
    }

    @DeleteMapping("/logout")
    fun logout(
        response: HttpServletResponse,
    ): RsData<Void> {
        response.addCookie(Cookie("apiKey", "").apply {
            path = "/"
            isHttpOnly = true
            maxAge = 0
        })
        response.addCookie(Cookie("accessToken", "").apply {
            path = "/"
            isHttpOnly = true
            maxAge = 0
        })

        return RsData("200-1", "로그아웃 되었습니다.")
    }

    @GetMapping("/me")
    @Transactional(readOnly = true)
    fun me(
        request: HttpServletRequest,
        response: HttpServletResponse,
    ): MemberWithUsernameDto {
        request.cookies
            ?.firstOrNull { it.name == "apiKey" }
            ?.value
            ?.let(memberFacade::findByApiKey)
            ?.let(::MemberWithUsernameDto)
            ?.let { return it }

        val authorization = request.getHeader(HttpHeaders.AUTHORIZATION)
            ?: throw AppException("401-1", "로그인 후 이용해주세요.")

        if (!authorization.startsWith("Bearer ")) {
            throw AppException("401-2", "Authorization 헤더가 Bearer 형식이 아닙니다.")
        }

        val tokens = authorization.removePrefix("Bearer ").trim()
            .split(Regex("\\s+"), limit = 2)

        val apiKey = tokens.firstOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: throw AppException("401-1", "로그인 후 이용해주세요.")

        val member = memberFacade.findByApiKey(apiKey)
            ?: throw AppException("401-1", "로그인 후 이용해주세요.")

        val accessToken = tokens.getOrNull(1)
        val payload = accessToken?.let(authTokenService::payload)

        if (payload == null || payload.id != member.id || payload.username != member.username || payload.name != member.nickname) {
            val newAccessToken = authTokenService.genAccessToken(member)

            response.addCookie(Cookie("accessToken", newAccessToken).apply {
                path = "/"
                isHttpOnly = true
            })
            response.setHeader(HttpHeaders.AUTHORIZATION, newAccessToken)
        }

        return MemberWithUsernameDto(member)
    }
}
