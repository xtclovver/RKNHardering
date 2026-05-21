package com.notcvnt.rknhardering.customcheck.mapper

import org.json.JSONArray
import org.json.JSONObject

object ResponseMappingParser {

    // JSONPath-lite: supports $.field, $.field.nested, $.array[0].field
    fun extractJsonPath(json: JSONObject, path: String): Any? {
        if (!path.startsWith("$")) return null
        val stripped = path.removePrefix("$").removePrefix(".")
        if (stripped.isEmpty()) return json
        return traversePath(json, tokenizePath(stripped))
    }

    // key=value\n format (cloudflare trace)
    fun extractKeyValue(text: String, key: String): String? {
        for (line in text.lines()) {
            val eq = line.indexOf('=')
            if (eq < 0) continue
            val k = line.substring(0, eq).trim()
            if (k == key) return line.substring(eq + 1).trim()
        }
        return null
    }

    // Returns first capture group of pattern, or null if no match
    fun extractRegex(text: String, pattern: String): String? {
        return try {
            Regex(pattern).find(text)?.groupValues?.getOrNull(1)
        } catch (_: Exception) {
            null
        }
    }

    // Split path like "field.nested[0].sub" into tokens ["field", "nested", "[0]", "sub"]
    private fun tokenizePath(path: String): List<String> {
        val tokens = mutableListOf<String>()
        val current = StringBuilder()
        var i = 0
        while (i < path.length) {
            when {
                path[i] == '.' -> {
                    if (current.isNotEmpty()) { tokens += current.toString(); current.clear() }
                    i++
                }
                path[i] == '[' -> {
                    if (current.isNotEmpty()) { tokens += current.toString(); current.clear() }
                    val end = path.indexOf(']', i)
                    if (end < 0) break
                    tokens += path.substring(i, end + 1)  // "[0]"
                    i = end + 1
                    if (i < path.length && path[i] == '.') i++
                }
                else -> { current.append(path[i]); i++ }
            }
        }
        if (current.isNotEmpty()) tokens += current.toString()
        return tokens
    }

    private fun traversePath(node: Any?, tokens: List<String>): Any? {
        if (tokens.isEmpty()) return node
        val token = tokens[0]
        val rest = tokens.drop(1)

        return when {
            token.startsWith("[") && token.endsWith("]") -> {
                val idx = token.removePrefix("[").removeSuffix("]").toIntOrNull() ?: return null
                when (node) {
                    is JSONArray -> {
                        if (idx < 0 || idx >= node.length()) return null
                        traversePath(node.opt(idx), rest)
                    }
                    else -> null
                }
            }
            node is JSONObject -> {
                if (!node.has(token)) return null
                traversePath(node.opt(token), rest)
            }
            else -> null
        }
    }
}
