package com.notcvnt.rknhardering

import java.io.File
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class NativeHelpDocumentationTest {

    @Test
    fun `every signal has four complete localized articles`() {
        val root = projectRoot()
        headings.forEach { (locale, requiredHeadings) ->
            val ipArticle = File(root, "docs/help/$locale/ip-comparison.md")
            assertTrue("Missing $ipArticle", ipArticle.isFile)
            val ipText = ipArticle.readText()
            requiredHeadings.forEach { heading ->
                assertTrue("$ipArticle lacks $heading", ipText.contains("## $heading"))
            }
            NativeSignalCatalog.entries.forEach { entry ->
                val file = File(root, "docs/help/$locale/native/${entry.slug}.md")
                assertTrue("Missing $file", file.isFile)
                val text = file.readText()
                assertTrue(text.contains("permalink: /help/$locale/native/${entry.slug}/"))
                requiredHeadings.forEach { heading ->
                    assertTrue("$file lacks $heading", text.contains("## $heading"))
                }
            }
        }
    }

    @Test
    fun `help internal links resolve and unsafe installer command is absent`() {
        val helpRoot = File(projectRoot(), "docs/help")
        val files = helpRoot.walkTopDown().filter { it.isFile && it.extension == "md" }.toList()
        files.forEach { file ->
            val text = file.readText()
            assertFalse("Unsafe curl-to-bash example in $file", text.contains("bash <(curl"))
            linkRegex.findAll(text).forEach link@{ match ->
                val target = match.groupValues[1]
                if (target.startsWith("http://") || target.startsWith("https://") || target.startsWith("#")) return@link
                assertTrue("Broken link $target in $file", resolves(requireNotNull(file.parentFile), target))
            }
        }
    }

    private fun resolves(base: File, rawTarget: String): Boolean {
        val clean = rawTarget.substringBefore('#').substringBefore('?')
        val direct = File(base, clean).canonicalFile
        if (direct.isFile) return true
        if (File(direct, "index.md").isFile) return true
        val withoutSlash = direct.path.trimEnd(File.separatorChar)
        return File("$withoutSlash.md").isFile
    }

    private fun projectRoot(): File {
        var current: File? = File(System.getProperty("user.dir") ?: ".").absoluteFile
        while (current != null) {
            if (File(current, "settings.gradle.kts").isFile) return current
            current = current.parentFile
        }
        error("Project root not found")
    }

    companion object {
        private val linkRegex = Regex("\\[[^]]*]\\(([^)]+)\\)")
        private val headings = mapOf(
            "en" to listOf(
                "What is checked and why", "What the result means",
                "Limitations and possible false positives", "Recommendations for this vector",
                "Required permissions and risks", "Evidence level", "Sources and last verification date",
            ),
            "ru" to listOf(
                "Что проверяется и зачем", "Что означает результат",
                "Ограничения и возможные ложные срабатывания", "Рекомендации для этого вектора",
                "Необходимые права и риски", "Уровень доказательности", "Источники и дата последней проверки",
            ),
            "fa" to listOf(
                "چه چیزی و چرا بررسی می‌شود", "نتیجه چه معنایی دارد",
                "محدودیت‌ها و مثبت کاذب احتمالی", "توصیه‌های همین بردار",
                "مجوزهای لازم و خطرها", "سطح شواهد", "منابع و تاریخ آخرین بررسی",
            ),
            "zh-CN" to listOf(
                "检查内容与目的", "结果含义", "限制与可能的误报", "针对该向量的建议",
                "所需权限与风险", "证据等级", "来源与最后核验日期",
            ),
        )
    }
}
