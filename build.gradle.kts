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

plugins {
    kotlin("jvm")
    kotlin("plugin.spring") apply false

    idea
    `maven-publish`

    id("com.adarshr.test-logger")
    id("io.gitlab.arturbosch.detekt")
    id("io.spring.dependency-management")
    id("org.datlowe.maven-publish-auth") apply false
    id("org.springframework.boot") apply false
    id("pl.allegro.tech.build.axion-release")
}

scmVersion {
    tag {
        prefix = "${project.name}-"
    }
}

project.version = scmVersion.version
val rootProjectDir = project(":").projectDir

allprojects {
    apply(plugin = "idea")
    apply(plugin = "org.jetbrains.kotlin.jvm")

    group = "com.gooddata.oauth2.server"

    repositories {
        mavenLocal()
        mavenCentral()
        jcenter()
        maven("https://plugins.gradle.org/m2/")
    }

    java.sourceCompatibility = JavaVersion.VERSION_11
}

subprojects {
    apply(plugin = "java-library")
    apply(plugin = "maven-publish")

    apply(plugin = "com.adarshr.test-logger")
    apply(plugin = "io.gitlab.arturbosch.detekt")
    apply(plugin = "io.spring.dependency-management")
    apply(plugin = "org.datlowe.maven-publish-auth")

    project.version = parent?.version ?: error("Subproject has no parent, you are in wrong universe.")

    dependencyManagement {
        imports {
            mavenBom(org.springframework.boot.gradle.plugin.SpringBootPlugin.BOM_COORDINATES)
        }
    }

    dependencies {
        val striktVersion: String by project
        val detektVersion: String by project

        testImplementation(platform("io.strikt:strikt-bom:${striktVersion}"))
        detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:${detektVersion}")
    }

    java {
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
        source = files(
            "src/main/kotlin",
            "src/test/kotlin"
        )
        config = files(
            "$rootProjectDir/gradle/scripts/detekt-config.yml",
            "$rootProjectDir/gradle/scripts/detekt-config-strict.yml"
        )
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
        withType<Test> {
            useJUnitPlatform()
        }

        withType<KotlinCompile> {
            kotlinOptions {
                freeCompilerArgs =
                    listOf("-Xjsr305=strict", "-Xopt-in=kotlin.RequiresOptIn", "-Xallow-result-return-type")
                jvmTarget = "11"
            }
        }
    }
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
