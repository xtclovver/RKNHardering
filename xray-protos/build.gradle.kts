plugins {
    `java-library`
    alias(libs.plugins.google.protobuf)
}

java {
    toolchain {
        languageVersion.set(JavaLanguageVersion.of(11))
    }
}

protobuf {
    protoc {
        artifact = "com.google.protobuf:protoc:${libs.versions.protobuf.get()}"
    }
    plugins {
        create("grpc") {
            artifact = "io.grpc:protoc-gen-grpc-java:${libs.versions.grpc.get()}"
        }
    }
    generateProtoTasks {
        all().forEach { task ->
            task.builtins {
                named("java") {
                    option("lite")
                }
            }
            task.plugins {
                maybeCreate("grpc").apply {
                    option("lite")
                }
            }
        }
    }
}

dependencies {
    api(libs.grpc.stub)
    api(libs.grpc.protobuf.lite)
    api(libs.protobuf.javalite)
    compileOnly(libs.javax.annotation.api)
}
