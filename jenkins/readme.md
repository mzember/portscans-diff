# LFRIS Security Jenkins

## Purpose

* To maintain jenkins vms where we run our tests

## Overview

### Before you run or test

* Add gradle-ext.properties
* Update gradle-ext.properties with "jenkinsUsername=\<your username\>" and "jenkinsPassword=\<your password\>"

### Run

* ../gradlew updateJenkinsItems"lfris-security"