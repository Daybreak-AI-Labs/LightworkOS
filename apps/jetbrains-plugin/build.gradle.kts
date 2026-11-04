plugins {
    kotlin("jvm") version "2.1.20"
    id("org.jetbrains.intellij.platform") version "2.5.0"
}

group = "dev.maverick"
version = "0.1.6"
dependencyLocking { lockAllConfigurations() }

repositories {
    mavenCentral()
    intellijPlatform { defaultRepositories() }
}

dependencies {
    implementation("com.google.code.gson:gson:2.11.0")
    intellijPlatform { intellijIdeaCommunity("2024.3.6") }
}

kotlin { jvmToolchain(21) }
sourceSets.test { kotlin.srcDir("tests") }

intellijPlatform {
    pluginConfiguration {
        name = "Lightwork"
        version = project.version.toString()
        ideaVersion { sinceBuild = "243"; untilBuild = "243.*" }
    }
    buildSearchableOptions = false
}

tasks.register<JavaExec>("loopbackTest") {
    group = "verification"
    description = "Exercise owned SSE connections against a local synthetic HTTP server."
    dependsOn(tasks.testClasses)
    classpath = sourceSets.test.get().runtimeClasspath
    mainClass = "dev.maverick.RunEventStreamTestKt"
    jvmArgs("--add-modules", "jdk.httpserver")
}
tasks.check { dependsOn("loopbackTest") }
tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
