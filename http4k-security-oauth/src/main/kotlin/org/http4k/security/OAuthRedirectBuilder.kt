package org.http4k.security

import org.http4k.core.Uri
import org.http4k.core.query
import org.http4k.core.queryNotNull
import org.http4k.security.oauth.server.AuthRequest
import org.http4k.security.openid.CodeChallenge
import org.http4k.security.openid.Nonce
import org.http4k.security.openid.RequestJwts

typealias RedirectionUriBuilder = (Uri, AuthRequest, state: State, nonce: Nonce?, codeChallenge: CodeChallenge?) -> Uri

val defaultUriBuilder: RedirectionUriBuilder = { uri: Uri,
                                                 authRequest: AuthRequest,
                                                 state: State,
                                                 nonce: Nonce?,
                                                 codeChallenge: CodeChallenge? ->
    val oauthUri = uri.query("client_id", authRequest.client.value)
        .query("response_type", authRequest.responseType.queryParameterValue)
        .query("scope", authRequest.scopes.joinToString(" "))
        .query("redirect_uri", authRequest.redirectUri.toString())
        .query("state", state.value)
        .queryNotNull("code_challenge", codeChallenge?.value)
        .queryNotNull("nonce", nonce?.value)
        oauthUri
}

fun uriBuilderWithRequestJwt(requestJwts: RequestJwts) =
    { uri: Uri, authRequest: AuthRequest, state: State, nonce: Nonce?, codeChallenge: CodeChallenge? ->
        defaultUriBuilder(uri, authRequest, state, nonce, codeChallenge)
            .query("request", requestJwts.create(authRequest, state, nonce).value)
    }
