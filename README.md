REACC Framework
===============

## Overview
REACC is a Java Application Security Framework. REACC is acronym for Resource ACCess Control. REACC provides a high-performance access control API that provides _permission based_ authorization services for Java application objects.
It has support for hierarchical domains, super users, permission inheritance and impersonation.

In a nutshell, REACC allows your application to enforce security by answering the question:

    Is entity 'A' allowed to perform action 'p' on entity 'B'?

## Design Goals
The key design goals of REACC are to:

- **simplify** the maintenance of complex, real world security topologies

- **fine grained access control** 
	+ example: grant _John_ permissions _READ_, _WRITE_ on _SalesSummary-2014.xls_

- **coarse grained access control**
	+ example: grant _John_ permission _READ_ on _Class:DOCUMENT_ in _Domain:NY Office_

- **logical security domains** for use in multi-tenant application architectures
	+ example: _Domain:NY Office_


## Supported Environments
REACC persists all security relationships in database tables and currently supports the following databases:

- IBM DB2 10.5
- Microsoft SQL Server 12.0 (2014)
- Oracle 11g R2
- PostgreSQL 9.3

REACC is compatible with Java&#8482; SE 7 (Java&#8482; version 1.7.0), or higher.

## License
REACC is open source software released under the commercial friendly [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).

## Documentation
You can find more information about REACC, including the latest Javadocs, releases, and tutorials on the project website:
[resourcesecurityframework.org](http://resourcesecurityframework.org).

## About Acciente
[Acciente, LLC](http://www.acciente.com) is a software company located in Scottsdale, Arizona specializing in systems architecture and software design for medium to large scale software projects.
You can learn more about [Acciente](http://www.acciente.com) on our [about us](http://www.acciente.com/index.php?cid=about) page.
