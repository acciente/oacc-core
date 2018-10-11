OACC Java Application Security Framework
========================================

## What is OACC?

OACC - pronounced _[oak]_ - is a fully featured API to both **enforce** and **manage** your application's authentication and authorization needs.

In a nutshell, OACC provides _permission-based_ authorization services and allows your application to enforce security by answering the question:

    Is entity 'A' allowed to perform action 'p' on entity 'B'?

## Features

- **Fully implemented API**  
All the functionality to manage your application's security model, out of the box.

- **Single access-control paradigm**  
Always operate at the resource level. Manage permissions exclusively between resources.

- **Flexible security model**  
Secure any operation between your domain objects and the actors on them.

- **Permission delegation**  
Authorize subjects to delegate their permissions to others with _GRANT OPTIONS_.

- **Identity delegation**  
Authorize an authenticated subject to securely "impersonate" another subject.

- **Efficient query methods**  
Find resources by permission with efficient symmetric query methods.

Learn more about all of OACC's authorization and authentication features on the [Features page](http://oaccframework.org/oacc-features.html) of the project website.

## License

OACC is open source software released under the commercial friendly [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Supported Environments

OACC persists all security relationships in database tables and currently supports the following databases:

- IBM DB2 10.5
- Microsoft SQL Server 12.0 (2014)
- Oracle 11g R2
- PostgreSQL 9.3
- HSQLDB 2.3
- MySQL 5.6 / MariaDB 10.0
- SQLite 3.8

OACC is compatible with Java&#8482; SE 7 (Java&#8482; version 1.7.0), or higher.

## Get Started

The easiest way to include the latest OACC release into your project is to declare the following Maven coordinates as a dependency in your POM file:

```xml
<dependency>
    <groupId>com.acciente.oacc</groupId>
    <artifactId>acciente-oacc</artifactId>
    <version>2.0.0</version>
</dependency>
```

To _install, configure and initialize_ the **OACC database**, please refer to the [Get Started Tutorial](http://oaccframework.org/getting-started-tutorial.html) on the project website.

The [_SecureTodo_ sample application](http://oaccframework.org/secure-todo-example.html) illustrates how to integrate OACC into a Java application and how to address several real-world authorization scenarios. The writeup is also available in the [Github repository](https://github.com/acciente/oacc-example-securetodo) that contains the full source code.

## Documentation

You can find more information about OACC, including the latest Javadocs, releases, and tutorials on the project website:
[oaccframework.org](http://oaccframework.org).

## About Acciente

[Acciente, LLC](http://www.acciente.com) is a software company located in Scottsdale, Arizona specializing in systems architecture and software design for medium to large scale software projects.
