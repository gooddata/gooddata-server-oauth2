/*
 * Copyright 2021 GoodData Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For more details take a look at the 'Building Java & JVM projects' chapter in the Gradle
 * User Manual available at https://docs.gradle.org/6.8.2/userguide/building_java_projects.html
 */

import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import pl.allegro.tech.build.axion.release.domain.TagNameSerializationConfig

plugins {
    val kotlinVersion = "1.4.31"

    kotlin("jvm") version kotlinVersion
    kotlin("plugin.spring") version kotlinVersion

    idea
    `maven-publish`
    `java-library`

    id("com.adarshr.test-logger") version "2.1.1"
    id("io.gitlab.arturbosch.detekt") version "1.14.2"
    id("io.spring.dependency-management") version "1.0.10.RELEASE"
    id("org.datlowe.maven-publish-auth") version "2.0.2"
    id("org.springframework.boot") version "2.4.1"
    id("pl.allegro.tech.build.axion-release") version "1.12.1"
}

scmVersion {
    tag(closureOf<TagNameSerializationConfig> {
        prefix = project.name
    })
}

group = "com.gooddata.oauth2.server"
project.version = scmVersion.version
val rootProjectDir = project(":").projectDir

repositories {
    mavenLocal()
    mavenCentral()
    jcenter()
    maven("https://plugins.gradle.org/m2/")
}

java {
    registerFeature("webfluxSupport") {
        usingSourceSet(sourceSets["main"])
    }
    registerFeature("webmvcSupport") {
        usingSourceSet(sourceSets["main"])
    }
    withJavadocJar()
    withSourcesJar()
}

publishing {
    publications {
        create<MavenPublication>("library") {
            from(components["java"])
        }
    }
    repositories {
        // to be used with `publishLibraryPublicationToGitlabMavenRepository`
        val gitlabMavenUrl: String by project
        gitlabMavenRepository(gitlabMavenUrl)
    }
}

idea {
    module {
        isDownloadJavadoc = true
        isDownloadSources = true
    }
}

detekt {
    toolVersion = "1.14.2"
    input = files(
            "src/main/kotlin",
            "src/test/kotlin"
    )
    config = files("$rootProjectDir/gradle/scripts/detekt-config.yml", "$rootProjectDir/gradle/scripts/detekt-config-strict.yml")
}

/**
 * Avoid having specific dependencies on classpath (all - complete remove, runtime - only binary/runtime)
 */
configurations {
    all {
        exclude(module = "spring-boot-starter-logging")
    }
    runtimeOnly {
        exclude(group = "org.checkerframework")
    }
}

testlogger {
    showFullStackTraces = false
    showCauses = true
    // time of execution more than this threshold = test is considered as slow
    slowThreshold = 2000
    showPassed = true
    showSkipped = true
    showFailed = true
    // set to 'true' to show whole error stream (all ERROR events)
    showStandardStreams = false
    showPassedStandardStreams = false
    showSkippedStandardStreams = false
    showFailedStandardStreams = true
}

tasks {
    bootJar { enabled = false }
    jar { enabled = true }
    withType<Test> {
        useJUnitPlatform()
    }

    withType<KotlinCompile> {
        kotlinOptions {
            freeCompilerArgs = listOf("-Xjsr305=strict", "-Xopt-in=kotlin.RequiresOptIn", "-Xallow-result-return-type")
            jvmTarget = "11"
        }
    }
}

dependencies {
    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:1.14.2")

    "webfluxSupportImplementation"("org.springframework.boot:spring-boot-starter-webflux")
    "webmvcSupportImplementation"("org.springframework.boot:spring-boot-starter-web")
    "webmvcSupportImplementation"("javax.servlet:javax.servlet-api")

    implementation("org.springframework.security:spring-security-oauth2-client")
    implementation("org.springframework.security:spring-security-oauth2-jose")
    implementation("org.springframework.security:spring-security-oauth2-resource-server")
    implementation("org.springframework.security:spring-security-config")
}

/**
 * Registers the HTTP header authenticated GitLab Maven repository for the given [gitlabMavenUrl]
 */
fun RepositoryHandler.gitlabMavenRepository(gitlabMavenUrl: String) {
    maven {
        name = "gitlabMaven"
        url = uri(gitlabMavenUrl)

        credentials(HttpHeaderCredentials::class.java) {
            val jobToken = System.getenv("CI_JOB_TOKEN")
            if (jobToken != null) {
                // GitLab CI
                name = "Job-Token"
                value = jobToken
            } else {
                name = "Private-Token"
                value = System.getenv("GITLAB_TOKEN")
            }
        }

        authentication {
            create<HttpHeaderAuthentication>("header")
        }
    }
}
