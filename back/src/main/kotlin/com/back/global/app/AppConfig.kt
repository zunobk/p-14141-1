package com.back.global.app

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component

@Component
class AppConfig(
    @Value("\${custom.site.backUrl}")
    siteBackUrl: String,
    @Value("\${custom.systemMemberApiKey}")
    systemMemberApiKey: String,
) {
    init {
        Companion.siteBackUrl = siteBackUrl
        Companion.systemMemberApiKey = systemMemberApiKey
    }

    companion object {
        lateinit var siteBackUrl: String
            private set
        lateinit var systemMemberApiKey: String
            private set
    }
}
