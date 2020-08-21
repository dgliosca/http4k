package org.http4k.h4k.example.main.external

import org.http4k.core.HttpHandler
import org.http4k.core.Method.POST
import org.http4k.core.Request
import org.http4k.h4k.example.main.ExternalServiceId

/**
 * Domain client for the 3rd party Doubler service
 */
interface Doubler : (String) -> String {
    companion object {
        val ID = ExternalServiceId("doubler")
    }

    class Http(private val http: HttpHandler) : Reverser {
        override operator fun invoke(input: String) = http(Request(POST, "/").body(input)).bodyString()
    }
}