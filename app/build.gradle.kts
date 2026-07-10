plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
}

val nativeNdkVersion = "28.2.13676358"
val nativeCmakeVersion = "3.22.1"
val robolectricSdk33RuntimeDep by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}
val robolectricSdk35RuntimeDep by configurations.creating {
    isCanBeConsumed = false
    isCanBeResolved = true
}
val robolectricRuntimeDepsDir = layout.buildDirectory.dir("robolectric-runtime-deps")
val prepareRobolectricRuntimeDeps by tasks.registering(Copy::class) {
    from(robolectricSdk33RuntimeDep)
    from(robolectricSdk35RuntimeDep)
    into(robolectricRuntimeDepsDir)
}

android {
    namespace = "com.notcvnt.rknhardering"
    ndkVersion = nativeNdkVersion
    compileSdk = 36

    defaultConfig {
        applicationId = "com.notcvnt.rknhardering"
        minSdk = 26
        targetSdk = 36
        versionCode = 21000
        versionName = "2.10.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        androidResources.localeFilters += listOf("en", "ru", "fa", "zh-rCN")

        ndk {
            abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64")
        }

        externalNativeBuild {
            cmake {
                arguments += listOf("-DANDROID_STL=c++_static")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    kotlinOptions {
        jvmTarget = "11"
    }
    buildFeatures {
        buildConfig = true
    }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = nativeCmakeVersion
        }
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
        }
    }
    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }
    testOptions {
        unitTests.isIncludeAndroidResources = true
    }
}

tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    val testHomeDir = layout.buildDirectory.dir("test-home").get().asFile
    val tempDir = layout.buildDirectory.dir("test-tmp").get().asFile

    dependsOn(prepareRobolectricRuntimeDeps)

    doFirst {
        testHomeDir.mkdirs()
        tempDir.mkdirs()
    }

    systemProperty("user.home", testHomeDir.absolutePath)
    systemProperty("java.io.tmpdir", tempDir.absolutePath)
    systemProperty("robolectric.dependency.dir", robolectricRuntimeDepsDir.get().asFile.absolutePath)
    systemProperty("robolectric.offline", "true")
    systemProperty("robolectric.usePreinstrumentedJars", "false")

    // Forward maintainer-only -Dmarketplace.* properties to the test JVM so the
    // MarketplaceSigningTool can pick them up. No effect when unset.
    System.getProperties().forEach { (k, v) ->
        val key = k.toString()
        if (key.startsWith("marketplace.")) systemProperty(key, v.toString())
    }
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.appcompat)
    implementation(libs.material)
    implementation(libs.androidx.activity)
    implementation(libs.androidx.constraintlayout)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.ktx)
    implementation(project(":xray-protos"))
    implementation(libs.grpc.okhttp)
    implementation(libs.okhttp)
    implementation(libs.okhttp.dnsoverhttps)
    testImplementation(libs.junit)
    testImplementation(libs.okhttp.mockwebserver)
    testImplementation(libs.robolectric)
    testImplementation(libs.androidx.test.core)
    robolectricSdk33RuntimeDep("org.robolectric:android-all:13-robolectric-9030017")
    robolectricSdk35RuntimeDep("org.robolectric:android-all:15-robolectric-13954326")
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
}
