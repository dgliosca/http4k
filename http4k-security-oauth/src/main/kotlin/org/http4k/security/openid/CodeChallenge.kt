package org.http4k.security.openid

import org.http4k.security.AccessTokenFetcher.Companion.Forms.codeVerifier
import java.math.BigInteger
import java.security.SecureRandom
import java.util.*

data class CodeChallenge(val value: String)
data class CodeVerifier(val value: String) {
    companion object {
        val SECURE_CODE_VERIFIER = {
            val codeVerifier = ByteArray(48)
            SecureRandom.getInstance("SHA1PRNG", "SUN").nextBytes(codeVerifier)
            CodeVerifier(Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier))
        }
    }
}
