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
 * The settings file is used to specify which projects to include in your build.
 *
 * Detailed information about configuring a multi-project build in Gradle can be found
 * in the user manual at https://docs.gradle.org/6.8.2/userguide/multi_project_builds.html
 */

rootProject.name = "gooddata-server-oauth2"

pluginManagement {
    plugins {
        val kotlinVersion: String by settings
        val detektVersion: String by settings
        val springBootVersion: String by settings

        kotlin("jvm") version kotlinVersion
        kotlin("plugin.spring") version kotlinVersion

        id("com.adarshr.test-logger") version "3.2.0"
        id("io.gitlab.arturbosch.detekt") version detektVersion
        id("io.spring.dependency-management") version "1.0.11.RELEASE"
        id("org.datlowe.maven-publish-auth") version "2.0.2"
        id("org.springframework.boot") version springBootVersion
        id("pl.allegro.tech.build.axion-release") version "1.13.14"
    }
}

include("gooddata-server-oauth2-common")
include("gooddata-server-oauth2-autoconfigure")
include("gooddata-server-oauth2-starter")
