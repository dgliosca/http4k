package org.http4k.security.openid

import org.http4k.security.openid.CodeChallengeMethod.Plain
import org.http4k.security.openid.CodeChallengeMethod.Sha256
import java.nio.charset.StandardCharsets.UTF_8
import java.security.SecureRandom
import java.util.*
import java.security.MessageDigest

//typealias  CodeChallengeGenerator = (() -> CodeVerifier) -> CodeChallenge

interface PKCECodesGenerator {
    val codeChallengeMethod: CodeChallengeMethod

    fun generateCodeVerifier(): CodeVerifier {
        val codeVerifier = ByteArray(48)
        SecureRandom.getInstance("SHA1PRNG", "SUN").nextBytes(codeVerifier)
        return CodeVerifier(Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifier))
    }

    fun generatePKCECodes(): PKCECodes? {
        val codeVerifier = generateCodeVerifier()
        val codeChallenge = codeChallenge(codeVerifier, codeChallengeMethod)
        return PKCECodes(codeVerifier, codeChallenge)
    }

    fun codeChallenge(codeVerifier: CodeVerifier, codeChallengeMethod: CodeChallengeMethod) =
        when (codeChallengeMethod) {
            Plain -> CodeChallenge(codeVerifier.value)
            Sha256 -> CodeChallenge(
                MessageDigest.getInstance("SHA-256")
                    .digest(codeVerifier.value.toByteArray(UTF_8)).toString()
            )
        }
}

class PKCECodes(val codeVerifier: CodeVerifier, val codeChallenge: CodeChallenge)
class PKCECodeGeneratorDefault(override val codeChallengeMethod: CodeChallengeMethod = Plain) : PKCECodesGenerator
