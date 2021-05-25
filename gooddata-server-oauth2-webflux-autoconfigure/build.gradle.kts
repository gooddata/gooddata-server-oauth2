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
    val detektFormattingVersion: String by project
    val jsonUnitVersion: String by project
    val kotlinCoroutinesVersion: String by project
    val kotlinLoggingVersion: String by project
    val mockkVersion: String by project
    val springMockkVersion: String by project
    val tinkVersion: String by project

    api(project(":gooddata-server-oauth2-common"))

    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:${detektFormattingVersion}")

    api("org.jetbrains.kotlinx:kotlinx-coroutines-reactor:${kotlinCoroutinesVersion}")
    api("org.springframework.boot:spring-boot-starter-webflux")

    implementation("io.github.microutils:kotlin-logging:${kotlinLoggingVersion}")
    implementation("io.projectreactor.kotlin:reactor-kotlin-extensions")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${kotlinCoroutinesVersion}")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-slf4j:${kotlinCoroutinesVersion}")
    implementation("org.springframework.security:spring-security-oauth2-jose")
    implementation("org.springframework.security:spring-security-config")

    testImplementation("com.ninja-squad:springmockk:${springMockkVersion}")
    testImplementation("io.mockk:mockk:${mockkVersion}")
    testImplementation("io.strikt:strikt-core")
    testImplementation("net.javacrumbs.json-unit:json-unit:${jsonUnitVersion}")
    testImplementation("org.junit.jupiter:junit-jupiter")
    testImplementation("org.springframework.boot:spring-boot-starter-test") {
        exclude(group="org.mockito", module="mockito-core")
        exclude(group="org.skyscreamer", module="jsonassert")
    }
    testImplementation("com.google.crypto.tink:tink:${tinkVersion}")
}
