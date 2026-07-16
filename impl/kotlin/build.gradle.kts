// Gradle manifest for the N-PAMP (draft-bubblefish-npamp-01) OPEN reference library, Kotlin/JVM port.
// Makes impl/kotlin a consumable, publishable Maven Central artifact: coordinates
// sh.bubblefish:npamp-kotlin (the `-kotlin` suffix keeps it distinct from the Java port's
// sh.bubblefish:npamp on Maven Central). Dependency-free beyond the Kotlin standard library —
// crypto comes from the JDK (javax.crypto, java.security; Ed25519 via the "EdDSA" provider).
//
// `gradle -p impl/kotlin build` compiles the library and assembles the publishable jar (+ sources +
// javadoc jars via withSourcesJar/withJavadocJar). `gradle -p impl/kotlin publish` deploys it, and is
// credential-gated in .github/workflows/publish.yml (blocked until the operator supplies the Maven
// Central token + signing key). The KAT / conformance tests under src/test/kotlin are main()-driven
// (run per QUICKSTART.md and by impl/_conformance-harness), not a JUnit suite, so the `test` task is
// disabled here — this manifest's job is the publishable library, grading lives in the harness.

plugins {
    kotlin("jvm") version "2.0.20"
    `maven-publish`
    signing
}

group = "sh.bubblefish"
version = "0.1.0"

repositories {
    mavenCentral()
}

kotlin {
    // Verified against OpenJDK 21 (QUICKSTART.md).
    jvmToolchain(21)
}

sourceSets {
    main { kotlin.srcDir("src/main/kotlin") }
    test { kotlin.srcDir("src/test/kotlin") }
}

java {
    withSourcesJar()
    withJavadocJar()
}

// The KATs run via QUICKSTART.md / the cross-language conformance harness, not through Gradle's
// JUnit-based `test` task (they expose main(), not @Test). Disable execution; they still compile.
tasks.named("test") {
    enabled = false
}

publishing {
    publications {
        create<MavenPublication>("maven") {
            from(components["java"])
            artifactId = "npamp-kotlin"
            pom {
                name.set("npamp-kotlin")
                description.set(
                    "Open reference implementation of N-PAMP (draft-bubblefish-npamp-01) wire format — " +
                        "Kotlin/JVM port: frame codec, AES-256-GCM record layer, HKDF-Expand-Label key " +
                        "schedule, and handshake-binding primitives (Standard profile)."
                )
                url.set("https://github.com/bubblefish-tech/npamp_protocol")
                licenses {
                    license {
                        name.set("Apache-2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                organization {
                    name.set("BubbleFish Technologies, Inc.")
                    url.set("https://bubblefish.sh")
                }
                developers {
                    developer {
                        name.set("BubbleFish Technologies, Inc.")
                        organization.set("BubbleFish Technologies, Inc.")
                        organizationUrl.set("https://bubblefish.sh")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/bubblefish-tech/npamp_protocol.git")
                    developerConnection.set("scm:git:git@github.com:bubblefish-tech/npamp_protocol.git")
                    url.set("https://github.com/bubblefish-tech/npamp_protocol")
                }
            }
        }
    }
    repositories {
        maven {
            name = "central"
            // Sonatype Central Portal OSSRH-compatible staging endpoint. Credentials and the target
            // URL are supplied by the operator via ORG_GRADLE_PROJECT_* / env at publish time; absent
            // them, the publish job in publish.yml is skipped (blocked-external).
            url = uri(
                System.getenv("MAVEN_CENTRAL_URL")
                    ?: "https://ossrh-staging-api.central.sonatype.com/service/local/staging/deploy/maven2/"
            )
            credentials {
                username = System.getenv("MAVEN_CENTRAL_USERNAME")
                password = System.getenv("MAVEN_CENTRAL_PASSWORD")
            }
        }
    }
}

signing {
    // In-memory GPG key from CI secrets; only required for the `publish` path (deploy). Ordinary
    // `gradle build` needs no key. isRequired is false when no key is present so local builds work.
    val signingKey = System.getenv("MAVEN_GPG_PRIVATE_KEY")
    val signingPassword = System.getenv("MAVEN_GPG_PASSPHRASE")
    isRequired = signingKey != null
    if (signingKey != null) {
        useInMemoryPgpKeys(signingKey, signingPassword)
        sign(publishing.publications["maven"])
    }
}
