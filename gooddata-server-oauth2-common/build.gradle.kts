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

plugins {
    kotlin("plugin.spring")
    id("org.springframework.boot")
}

tasks {
    bootJar { enabled = false }
    jar { enabled = true }
}

dependencies {
    val jsonUnitVersion: String by project
    val tinkVersion: String by project
    val kotlinCoroutinesVersion: String by project
    val mockkVersion: String by project
    val kotlinLoggingVersion: String by project
    val wiremockVersion: String by project

    api("com.fasterxml.jackson.core:jackson-databind")
    api("io.netty:netty-codec-http")
    api("org.springframework:spring-web")
    api("org.springframework.boot:spring-boot")
    api("org.springframework.security:spring-security-oauth2-client:5.6.2")
    api("org.springframework.security:spring-security-oauth2-resource-server:5.6.2")

    implementation("com.google.crypto.tink:tink:${tinkVersion}")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${kotlinCoroutinesVersion}")
    implementation("io.github.microutils:kotlin-logging:${kotlinLoggingVersion}")
    implementation("org.springframework.security:spring-security-oauth2-jose:5.7.3")
    implementation("com.github.ben-manes.caffeine:caffeine:3.1.1")

    testImplementation("io.strikt:strikt-core")
    testImplementation("net.javacrumbs.json-unit:json-unit:${jsonUnitVersion}")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("io.mockk:mockk:${mockkVersion}")
    testImplementation("com.github.tomakehurst:wiremock:${wiremockVersion}")
}
