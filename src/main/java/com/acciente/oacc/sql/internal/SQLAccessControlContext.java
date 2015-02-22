/*
 * Copyright 2009-2015, Acciente LLC
 *
 * Acciente LLC licenses this file to you under the
 * Apache License, Version 2.0 (the "License"); you
 * may not use this file except in compliance with the
 * License. You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in
 * writing, software distributed under the License is
 * distributed on an "AS IS" BASIS, WITHOUT WARRANTIES
 * OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing
 * permissions and limitations under the License.
 */
package com.acciente.oacc.sql.internal;

import com.acciente.oacc.AccessControlContext;
import com.acciente.oacc.AuthenticationProvider;
import com.acciente.oacc.Credentials;
import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainCreatePermissions;
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.DomainPermissions;
import com.acciente.oacc.NotAuthenticatedException;
import com.acciente.oacc.NotAuthorizedException;
import com.acciente.oacc.OaccException;
import com.acciente.oacc.Resource;
import com.acciente.oacc.ResourceClassInfo;
import com.acciente.oacc.ResourceCreatePermission;
import com.acciente.oacc.ResourceCreatePermissions;
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.Resources;
import com.acciente.oacc.sql.SQLDialect;
import com.acciente.oacc.sql.internal.persister.DomainPersister;
import com.acciente.oacc.sql.internal.persister.GrantDomainCreatePermissionPostCreateSysPersister;
import com.acciente.oacc.sql.internal.persister.GrantDomainCreatePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.GrantDomainPermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.GrantGlobalResourcePermissionPersister;
import com.acciente.oacc.sql.internal.persister.GrantGlobalResourcePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.GrantResourceCreatePermissionPostCreatePersister;
import com.acciente.oacc.sql.internal.persister.GrantResourceCreatePermissionPostCreateSysPersister;
import com.acciente.oacc.sql.internal.persister.GrantResourceCreatePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.GrantResourcePermissionPersister;
import com.acciente.oacc.sql.internal.persister.GrantResourcePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.ResourceClassPermissionPersister;
import com.acciente.oacc.sql.internal.persister.ResourceClassPersister;
import com.acciente.oacc.sql.internal.persister.ResourcePersister;
import com.acciente.oacc.sql.internal.persister.SQLConnection;
import com.acciente.oacc.sql.internal.persister.SQLStrings;
import com.acciente.oacc.sql.internal.persister.id.DomainId;
import com.acciente.oacc.sql.internal.persister.id.Id;
import com.acciente.oacc.sql.internal.persister.id.ResourceClassId;
import com.acciente.oacc.sql.internal.persister.id.ResourceId;
import com.acciente.oacc.sql.internal.persister.id.ResourcePermissionId;

import javax.sql.DataSource;
import java.io.Serializable;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@SuppressWarnings({"UnusedAssignment", "ThrowFromFinallyBlock"})
public class SQLAccessControlContext implements AccessControlContext, Serializable {
   // services
   private DataSource dataSource;
   private Connection connection;

   // state
   private AuthenticationProvider authenticationProvider;
   private boolean                hasDefaultAuthenticationProvider;

   // The resource that authenticated in this session with a call to one of the authenticate() methods
   private Resource authenticatedResource;
   private String   authenticatedResourceDomainName;

   // The resource as which the session's credentials are checked. This would be the same as the resource
   // that initially authenticated - UNLESS a another resource is being IMPERSONATED
   private Resource sessionResource;
   private String   sessionResourceDomainName;

   // resource ID constants
   private static final int SYSTEM_RESOURCE_ID = 0;

   // domain permissions constants
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN
         = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, false);
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN_GRANT
         = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);
   private static final DomainPermission DomainPermission_SUPER_USER
         = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, false);
   private static final DomainPermission DomainPermission_SUPER_USER_GRANT
         = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);

   // resource permissions constants
   private static final ResourcePermission ResourcePermission_INHERIT
         = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, false);
   private static final ResourcePermission ResourcePermission_INHERIT_GRANT
         = ResourcePermissions.getInstance(ResourcePermissions.INHERIT, true);
   private static final ResourcePermission ResourcePermission_IMPERSONATE
         = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, false);
   private static final ResourcePermission ResourcePermission_IMPERSONATE_GRANT
         = ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true);
   private static final ResourcePermission ResourcePermission_RESET_CREDENTIALS
         = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, false);
   private static final ResourcePermission ResourcePermission_RESET_CREDENTIALS_GRANT
         = ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true);

   // persisters
   private final ResourceClassPersister                              resourceClassPersister;
   private final ResourceClassPermissionPersister                    resourceClassPermissionPersister;
   private final DomainPersister                                     domainPersister;
   private final GrantDomainCreatePermissionSysPersister             grantDomainCreatePermissionSysPersister;
   private final GrantDomainCreatePermissionPostCreateSysPersister   grantDomainCreatePermissionPostCreateSysPersister;
   private final GrantDomainPermissionSysPersister                   grantDomainPermissionSysPersister;
   private final ResourcePersister                                   resourcePersister;
   private final GrantResourceCreatePermissionSysPersister           grantResourceCreatePermissionSysPersister;
   private final GrantResourceCreatePermissionPostCreateSysPersister grantResourceCreatePermissionPostCreateSysPersister;
   private final GrantResourceCreatePermissionPostCreatePersister    grantResourceCreatePermissionPostCreatePersister;
   private final GrantResourcePermissionSysPersister                 grantResourcePermissionSysPersister;
   private final GrantGlobalResourcePermissionSysPersister           grantGlobalResourcePermissionSysPersister;
   private final GrantResourcePermissionPersister                    grantResourcePermissionPersister;
   private final GrantGlobalResourcePermissionPersister              grantGlobalResourcePermissionPersister;

   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLDialect sqlDialect) {
      return new SQLAccessControlContext(connection, schemaName, sqlDialect);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLDialect sqlDialect) {
      return new SQLAccessControlContext(dataSource, schemaName, sqlDialect);
   }

   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLDialect sqlDialect,
                                                              AuthenticationProvider authenticationProvider) {
      return new SQLAccessControlContext(connection, schemaName, sqlDialect, authenticationProvider);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLDialect sqlDialect,
                                                              AuthenticationProvider authenticationProvider) {
      return new SQLAccessControlContext(dataSource, schemaName, sqlDialect, authenticationProvider);
   }

   public static void preSerialize(AccessControlContext accessControlContext) {
      if (accessControlContext instanceof SQLAccessControlContext) {
         SQLAccessControlContext sqlAccessControlContext = (SQLAccessControlContext) accessControlContext;
         sqlAccessControlContext.__preSerialize();
      }
   }

   public static void postDeserialize(AccessControlContext accessControlContext, Connection connection) {
      if (accessControlContext instanceof SQLAccessControlContext) {
         SQLAccessControlContext sqlAccessControlContext = (SQLAccessControlContext) accessControlContext;
         sqlAccessControlContext.__postDeserialize(connection);
      }
   }

   public static void postDeserialize(AccessControlContext accessControlContext, DataSource dataSource) {
      if (accessControlContext instanceof SQLAccessControlContext) {
         SQLAccessControlContext sqlAccessControlContext = (SQLAccessControlContext) accessControlContext;
         sqlAccessControlContext.__postDeserialize(dataSource);
      }
   }

   private SQLAccessControlContext(Connection connection,
                                   String schemaName,
                                   SQLDialect sqlDialect) {
      this(schemaName, sqlDialect);
      this.connection = connection;
      // use the built-in authentication provider when no custom implementation is provided
      this.authenticationProvider
            = new SQLPasswordAuthenticationProvider(connection, schemaName, sqlDialect);
      this.hasDefaultAuthenticationProvider = true;
   }

   private SQLAccessControlContext(Connection connection,
                                   String schemaName,
                                   SQLDialect sqlDialect,
                                   AuthenticationProvider authenticationProvider) {
      this(schemaName, sqlDialect);
      this.connection = connection;
      this.authenticationProvider = authenticationProvider;
      this.hasDefaultAuthenticationProvider = false;
   }

   private SQLAccessControlContext(DataSource dataSource,
                                   String schemaName,
                                   SQLDialect sqlDialect) {
      this(schemaName, sqlDialect);
      this.dataSource = dataSource;
      // use the built-in authentication provider when no custom implementation is provided
      this.authenticationProvider
            = new SQLPasswordAuthenticationProvider(dataSource, schemaName, sqlDialect);
      this.hasDefaultAuthenticationProvider = true;
   }

   private SQLAccessControlContext(DataSource dataSource,
                                   String schemaName,
                                   SQLDialect sqlDialect,
                                   AuthenticationProvider authenticationProvider) {
      this(schemaName, sqlDialect);
      this.dataSource = dataSource;
      this.authenticationProvider = authenticationProvider;
      this.hasDefaultAuthenticationProvider = false;
   }

   private SQLAccessControlContext(String schemaName,
                                   SQLDialect sqlDialect) {
      // generate all the SQLs the persisters need based on the database dialect
      SQLStrings sqlStrings = SQLStrings.getSQLStrings(schemaName, sqlDialect);

      // setup persisters
      resourceClassPersister
            = new ResourceClassPersister(sqlStrings);
      resourceClassPermissionPersister
            = new ResourceClassPermissionPersister(sqlStrings);
      grantDomainCreatePermissionSysPersister
            = new GrantDomainCreatePermissionSysPersister(sqlStrings);
      grantDomainCreatePermissionPostCreateSysPersister
            = new GrantDomainCreatePermissionPostCreateSysPersister(sqlStrings);
      grantDomainPermissionSysPersister
            = new GrantDomainPermissionSysPersister(sqlStrings);
      domainPersister
            = new DomainPersister(sqlStrings);
      resourcePersister
            = new ResourcePersister(sqlStrings);
      grantResourceCreatePermissionSysPersister
            = new GrantResourceCreatePermissionSysPersister(sqlStrings);
      grantResourceCreatePermissionPostCreateSysPersister
            = new GrantResourceCreatePermissionPostCreateSysPersister(sqlStrings);
      grantResourceCreatePermissionPostCreatePersister
            = new GrantResourceCreatePermissionPostCreatePersister(sqlStrings);
      grantResourcePermissionSysPersister
            = new GrantResourcePermissionSysPersister(sqlStrings);
      grantGlobalResourcePermissionSysPersister
            = new GrantGlobalResourcePermissionSysPersister(sqlStrings);
      grantResourcePermissionPersister
            = new GrantResourcePermissionPersister(sqlStrings);
      grantGlobalResourcePermissionPersister
            = new GrantGlobalResourcePermissionPersister(sqlStrings);
   }

   private void __preSerialize() {
      this.dataSource = null;
      this.connection = null;
      if (hasDefaultAuthenticationProvider) {
         ((SQLPasswordAuthenticationProvider) authenticationProvider).preSerialize();
      }
   }

   private void __postDeserialize(DataSource dataSource) {
      this.dataSource = dataSource;
      this.connection = null;
      if (hasDefaultAuthenticationProvider) {
         ((SQLPasswordAuthenticationProvider) authenticationProvider).postDeserialize(dataSource);
      }
   }

   private void __postDeserialize(Connection connection) {
      this.dataSource = null;
      this.connection = connection;
      if (hasDefaultAuthenticationProvider) {
         ((SQLPasswordAuthenticationProvider) authenticationProvider).postDeserialize(connection);
      }
   }

   @Override
   public void authenticate(Resource resource, Credentials credentials) {
      __assertResourceSpecified(resource);
      __assertCredentialsSpecified(credentials);

      __authenticate(resource, credentials);
   }

   @Override
   public void authenticate(Resource resource) {
      __assertResourceSpecified(resource);

      __authenticate(resource, null);
   }

   private void __authenticate(Resource resource, Credentials credentials) {
      // before delegating to the authentication provider we do some basic validation
      SQLConnection connection = null;

      final String resourceDomainForResource;
      try {
         connection = __getConnection();

         final ResourceClassInternalInfo resourceClassInternalInfo
               = resourceClassPersister.getResourceClassInfoByResourceId(connection, resource);

         // complain if the resource is not marked as supporting authentication
         if (!resourceClassInternalInfo.isAuthenticatable()) {
            throw new IllegalArgumentException("Resource " + resource
                                                     + " is not of an authenticatable resource class: "
                                                     + resourceClassInternalInfo.getResourceClassName());
         }
         resourceDomainForResource = domainPersister.getResourceDomainNameByResourceId(connection, resource);
      }
      finally {
         __closeConnection(connection);
      }

      // now we delegate to the authentication provider
      if (credentials != null) {
         authenticationProvider.authenticate(resource, credentials);
      }
      else {
         authenticationProvider.authenticate(resource);
      }

      authenticatedResource = resource;
      authenticatedResourceDomainName = resourceDomainForResource;

      sessionResource = authenticatedResource;
      sessionResourceDomainName = authenticatedResourceDomainName;
   }

   @Override
   public void unauthenticate() {
      sessionResource = authenticatedResource = null;
      sessionResourceDomainName = authenticatedResourceDomainName = null;
   }

   @Override
   public void impersonate(Resource resource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(resource);

      try {
         connection = __getConnection();

         __assertImpersonatePermission(connection, resource);

         // switch the session credentials to the new resource
         sessionResource = resource;
         sessionResourceDomainName = domainPersister.getResourceDomainNameByResourceId(connection, resource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __assertImpersonatePermission(SQLConnection connection, Resource resource) {
      // this call will throw an exception if the resource is not found
      resourcePersister.verifyResourceExists(connection, resource);

      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfoByResourceId(connection, resource);

      // complain if the resource is not of an authenticatable resource-class
      if (!resourceClassInternalInfo.isAuthenticatable()) {
         throw new IllegalArgumentException("Resource " + resource
                                                  + " is not of an authenticatable resource class: "
                                                  + resourceClassInternalInfo.getResourceClassName());
      }

      boolean impersonatePermissionOK = false;

      // first check direct permissions
      final Set<ResourcePermission>
            resourcePermissions = __getEffectiveResourcePermissions(connection, authenticatedResource, resource);

      if (resourcePermissions.contains(ResourcePermission_IMPERSONATE)
            || resourcePermissions.contains(ResourcePermission_IMPERSONATE_GRANT)) {
         impersonatePermissionOK = true;
      }

      if (!impersonatePermissionOK) {
         // next check global direct permissions
         final String
               domainName = domainPersister.getResourceDomainNameByResourceId(connection, resource);
         final Set<ResourcePermission>
               globalResourcePermissions = __getEffectiveGlobalResourcePermissions(connection,
                                                                                   authenticatedResource,
                                                                                   resourceClassInternalInfo.getResourceClassName(),
                                                                                   domainName);

         if (globalResourcePermissions.contains(ResourcePermission_IMPERSONATE)
               || globalResourcePermissions.contains(ResourcePermission_IMPERSONATE_GRANT)) {
            impersonatePermissionOK = true;
         }
      }

      if (!impersonatePermissionOK) {
         // finally check for super user permissions
         if (__isSuperUserOfResource(connection, authenticatedResource, resource)) {
            impersonatePermissionOK = true;
         }
      }

      if (!impersonatePermissionOK) {
         throw new NotAuthorizedException(authenticatedResource, "impersonate", resource);
      }
   }

   @Override
   public void unimpersonate() {
      sessionResource = authenticatedResource;
      sessionResourceDomainName = authenticatedResourceDomainName;
   }

   @Override
   public void setCredentials(Resource resource, Credentials newCredentials) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(resource);

      if (!authenticatedResource.equals(sessionResource)) {
         throw new IllegalStateException("Calling setCredentials while impersonating another resource is not valid");
      }

      __assertCredentialsSpecified(newCredentials);

      final ResourceClassInternalInfo resourceClassInfo;
      final String domainName;
      try {
         connection = __getConnection();

         resourceClassInfo = resourceClassPersister.getResourceClassInfoByResourceId(connection, resource);

         if (!resourceClassInfo.isAuthenticatable()) {
            throw new IllegalArgumentException("Calling setCredentials for an unauthenticatable resource is not valid");
         }

         domainName = domainPersister.getResourceDomainNameByResourceId(connection, resource);

         // skip permission checks if the authenticated resource is trying to set its own credentials
         if (!authenticatedResource.equals(resource)) {
            __assertResetCredentialsResourcePermission(connection,
                                                       resource,
                                                       resourceClassInfo.getResourceClassName(),
                                                       domainName);
         }
      }
      finally {
         __closeConnection(connection);
      }

      authenticationProvider.validateCredentials(resourceClassInfo.getResourceClassName(),
                                                 domainName,
                                                 newCredentials);

      authenticationProvider.setCredentials(resource, newCredentials);
   }

   private void __assertResetCredentialsResourcePermission(SQLConnection connection,
                                                           Resource resource,
                                                           String resourceClassName,
                                                           String domainName) {
      // first check direct permissions
      boolean hasResetCredentialsPermission = false;

      final Set<ResourcePermission>
            resourcePermissions = __getEffectiveResourcePermissions(connection, authenticatedResource, resource);

      if (resourcePermissions.contains(ResourcePermission_RESET_CREDENTIALS)
            || resourcePermissions.contains(ResourcePermission_RESET_CREDENTIALS_GRANT)) {
         hasResetCredentialsPermission = true;
      }

      if (!hasResetCredentialsPermission) {
         // next check global direct permissions
         final Set<ResourcePermission>
               globalResourcePermissions = __getEffectiveGlobalResourcePermissions(connection,
                                                                                   authenticatedResource,
                                                                                   resourceClassName,
                                                                                   domainName);

         if (globalResourcePermissions.contains(ResourcePermission_RESET_CREDENTIALS)
               || globalResourcePermissions.contains(ResourcePermission_RESET_CREDENTIALS_GRANT)) {
            hasResetCredentialsPermission = true;
         }
      }

      if (!hasResetCredentialsPermission) {
         // finally check for super user permissions
         if (__isSuperUserOfResource(connection, authenticatedResource, resource)) {
            hasResetCredentialsPermission = true;
         }
      }

      if (!hasResetCredentialsPermission) {
         throw new NotAuthorizedException(authenticatedResource, "reset credentials", resource);
      }
   }

   @Override
   public void createResourceClass(String resourceClassName,
                                   boolean authenticatable,
                                   boolean unauthenticatedCreateAllowed) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertAuthenticatedAsSystemResource();  // check if the auth resource is permitted to create resource classes
      __assertResourceClassNameValid(resourceClassName);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();

         // check if this resource class already exists
         if (resourceClassPersister.getResourceClassId(connection, resourceClassName) != null) {
            throw new IllegalArgumentException("Duplicate resource class: " + resourceClassName);
         }

         resourceClassPersister.addResourceClass(connection, resourceClassName, authenticatable, unauthenticatedCreateAllowed);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void createResourcePermission(String resourceClassName, String permissionName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertAuthenticatedAsSystemResource();  // check if the auth resource is permitted to create resource classes
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionNameValid(permissionName);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();
         permissionName = permissionName.trim();

         // first verify that resource class is defined
         Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

         if (resourceClassId == null) {
            throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
         }

         // check if the permission name is already defined!
         Id<ResourcePermissionId> permissionId
               = resourceClassPermissionPersister.getResourceClassPermissionId(connection, resourceClassId, permissionName);

         if (permissionId != null) {
            throw new IllegalArgumentException("Duplicate permission: " + permissionName + " for resource class: " + resourceClassName);
         }

         resourceClassPermissionPersister.addResourceClassPermission(connection, resourceClassId, permissionName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void createDomain(String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         domainName = domainName.trim();

         __createDomain(connection, domainName, null);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void createDomain(String domainName,
                            String parentDomainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertDomainSpecified(domainName);
      __assertParentDomainSpecified(parentDomainName);

      try {
         connection = __getConnection();

         domainName = domainName.trim();
         parentDomainName = parentDomainName.trim();

         __createDomain(connection, domainName, parentDomainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __createDomain(SQLConnection connection,
                               String domainName,
                               String parentDomainName) {
      // we need to check if the currently authenticated resource is allowed to create domains
      final Set<DomainCreatePermission> domainCreatePermissions
            = grantDomainCreatePermissionSysPersister.getDomainCreateSysPermissionsIncludeInherited(connection,
                                                                                                    sessionResource);

      // if there is at least one permission, then it implies that this resource is allowed to create domains
      if (domainCreatePermissions.isEmpty()) {
         throw new NotAuthorizedException(sessionResource, "create domain");
      }

      // determine the post create permissions on the new domain
      final Set<DomainPermission> newDomainPermissions
            = __getPostCreateDomainPermissions(grantDomainCreatePermissionPostCreateSysPersister
                                                     .getDomainCreatePostCreateSysPermissionsIncludeInherited(connection,
                                                                                                              sessionResource));
      // check to ensure that the requested domain name does not already exist
      if (domainPersister.getResourceDomainId(connection, domainName) != null) {
         throw new IllegalArgumentException("Duplicate domain: " + domainName);
      }

      if (parentDomainName == null) {
         // create the new root domain
         domainPersister.addResourceDomain(connection, domainName);
      }
      else {
         // check to ensure that the parent domain name exists
         Id<DomainId> parentDomainId = domainPersister.getResourceDomainId(connection, parentDomainName);

         if (parentDomainId == null) {
            throw new IllegalArgumentException("Parent domain: " + parentDomainName + " not found!");
         }

         // we need to check if the currently authenticated resource is allowed to create child domains in the parent
         Set<DomainPermission> parentDomainPermissions;

         parentDomainPermissions = __getEffectiveDomainPermissions(connection, sessionResource, parentDomainName);

         if (!parentDomainPermissions.contains(DomainPermission_CREATE_CHILD_DOMAIN)
               && !parentDomainPermissions.contains(DomainPermission_CREATE_CHILD_DOMAIN_GRANT)
               && !parentDomainPermissions.contains(DomainPermission_SUPER_USER)
               && !parentDomainPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {
            throw new NotAuthorizedException(sessionResource, "create child domain in domain: " + parentDomainName);
         }

         // create the new child domain
         domainPersister.addResourceDomain(connection, domainName, parentDomainId);
      }

      if (newDomainPermissions.size() > 0) {
         // grant the currently authenticated resource the privileges to the new domain
         __setDirectDomainPermissions(connection,
                                      sessionResource,
                                      domainName,
                                      newDomainPermissions,
                                      true);
      }
   }

   @Override
   public Resource createResource(String resourceClassName) {
      SQLConnection connection = null;

      __assertAuthenticated();

      try {
         connection = __getConnection();

         return __createResource(connection, resourceClassName, sessionResourceDomainName, null);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Resource createResource(String resourceClassName, String domainName) {
      SQLConnection connection = null;

      try {
         connection = __getConnection();

         return __createResource(connection, resourceClassName, domainName, null);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Resource createResource(String resourceClassName, Credentials credentials) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertCredentialsSpecified(credentials);

      try {
         connection = __getConnection();

         return __createResource(connection, resourceClassName, sessionResourceDomainName, credentials);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Resource createResource(String resourceClassName,
                                  String domainName,
                                  Credentials credentials) {
      SQLConnection connection = null;

      __assertCredentialsSpecified(credentials);

      try {
         connection = __getConnection();

         return __createResource(connection, resourceClassName, domainName, credentials);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Resource __createResource(SQLConnection connection,
                                     String resourceClassName,
                                     String domainName,
                                     Credentials credentials) {
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);

      // validate the resource class
      resourceClassName = resourceClassName.trim();
      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);

      // check if the resource class is valid
      if (resourceClassInternalInfo == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      if (!resourceClassInternalInfo.isUnauthenticatedCreateAllowed()) {
         __assertAuthenticated();
      }

      if (resourceClassInternalInfo.isAuthenticatable()) {
         // if this resource class is authenticatable, then validate the credentials
         authenticationProvider.validateCredentials(resourceClassName, domainName, credentials);
      }
      else {
         // if this resource class is NOT authenticatable, then specifying credentials is invalid
         __assertCredentialsNotSpecified(credentials);
      }

      // validate the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // we first check the create permissions
      final Set<ResourcePermission> newResourcePermissions;

      // the only way we can have come here with _sessionResource == null is
      // when non-authenticated create is allowed for this resource class
      if (sessionResource == null) {
         // if this session is unauthenticated then give the new resource all available
         // permissions to itself
         newResourcePermissions = new HashSet<>();

         for (String permissionName : resourceClassPermissionPersister.getPermissionNames(connection, resourceClassName)) {
            newResourcePermissions.add(ResourcePermissions.getInstance(permissionName, true));
         }

         if (resourceClassInternalInfo.isAuthenticatable()) {
            newResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));
            newResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
         }
      }
      else {
         final Set<ResourceCreatePermission> resourceCreatePermissions;
         boolean createPermissionOK = false;

         resourceCreatePermissions = __getEffectiveResourceCreatePermissions(connection,
                                                                             sessionResource,
                                                                             resourceClassName,
                                                                             domainName);
         newResourcePermissions = __getPostCreateResourcePermissions(resourceCreatePermissions);

         if (resourceCreatePermissions.size() > 0) {
            createPermissionOK = true;
         }

         // if that did not work, next we check the session resource has super user permissions
         // to the domain of the new resource
         if (!createPermissionOK) {
            createPermissionOK = __isSuperUserOfDomain(connection, sessionResource, domainName);
         }

         if (!createPermissionOK) {
            throw new NotAuthorizedException(sessionResource, "create resource of resource class " + resourceClassName);
         }
      }

      // generate a resource id for the new resource
      final Id<ResourceId> newResourceId = resourcePersister.getNextResourceId(connection);

      if (newResourceId == null) {
         throw new IllegalStateException("Error generating new resource ID");
      }

      // create the new resource
      resourcePersister.createResource(connection,
                                       newResourceId,
                                       Id.<ResourceClassId>from(resourceClassInternalInfo.getResourceClassId()),
                                       domainId);

      // set permissions on the new resource, if applicable
      final Resource newResource = Resources.getInstance(newResourceId.getValue());

      if (newResourcePermissions != null && newResourcePermissions.size() > 0) {
         if (sessionResource != null) {
            __setDirectResourcePermissions(connection,
                                           sessionResource,
                                           newResource,
                                           newResourcePermissions,
                                           sessionResource,
                                           true);
         }
         else {
            // if this session is unauthenticated the permissions are granted to the newly created resource
            __setDirectResourcePermissions(connection,
                                           newResource,
                                           newResource,
                                           newResourcePermissions,
                                           newResource,
                                           true);
         }
      }

      if (credentials != null) {
         authenticationProvider.setCredentials(newResource, credentials);
      }

      return newResource;
   }

   @Override
   public void setDomainPermissions(Resource accessorResource,
                                    String domainName,
                                    Set<DomainPermission> permissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(permissions);

      try {
         connection = __getConnection();

         __setDirectDomainPermissions(connection, accessorResource, domainName, permissions, false);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __setDirectDomainPermissions(SQLConnection connection,
                                             Resource accessorResource,
                                             String domainName,
                                             Set<DomainPermission> requestedDomainPermissions,
                                             boolean newDomainMode) {
      // determine the domain ID of the domain, for use in the grant below
      Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // validate requested set is not null; empty set is valid and would remove any direct domain permissions
      if (requestedDomainPermissions == null) {
         throw new IllegalArgumentException("Set of requested domain permissions may not be null");
      }

      if (!newDomainMode) {
         resourcePersister.verifyResourceExists(connection, accessorResource);

         // check if the grantor (=session resource) has permissions to grant the requested permissions
         final Set<DomainPermission>
               grantorPermissions
               = __getEffectiveDomainPermissions(connection,
                                                 sessionResource,
                                                 domainName);

         // check if the grantor (=session resource) has super user permissions to the target domain
         if (!grantorPermissions.contains(DomainPermission_SUPER_USER)
               && !grantorPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {

            final Set<DomainPermission>
                  directAccessorPermissions
                  = __getDirectDomainPermissions(connection, accessorResource, domainId);

            final Set<DomainPermission>
                  requestedAddPermissions
                  = __subtract(requestedDomainPermissions, directAccessorPermissions);

            if (!requestedAddPermissions.isEmpty()) {
               final Set<DomainPermission> unauthorizedAddPermissions;
               unauthorizedAddPermissions
                     = __subtractDomainPermissionsIfGrantableFrom(requestedAddPermissions, grantorPermissions);

               if (unauthorizedAddPermissions.size() > 0) {
                  throw new NotAuthorizedException(sessionResource,
                                                   "add the following domain permission(s): " + unauthorizedAddPermissions);
               }
            }

            final Set<DomainPermission>
                  requestedRemovePermissions
                  = __subtract(directAccessorPermissions, requestedDomainPermissions);

            if (!requestedRemovePermissions.isEmpty()) {
               final Set<DomainPermission> unauthorizedRemovePermissions;
               unauthorizedRemovePermissions
                     = __subtractDomainPermissionsIfGrantableFrom(requestedRemovePermissions, grantorPermissions);

               if (unauthorizedRemovePermissions.size() > 0) {
                  throw new NotAuthorizedException(sessionResource,
                                                   "remove the following domain permission(s): " + unauthorizedRemovePermissions);
               }
            }
         }

         // revoke any existing permissions that accessor to has to this domain directly
         grantDomainPermissionSysPersister.removeDomainSysPermissions(connection, accessorResource, domainId);
      }

      // add the new permissions
      grantDomainPermissionSysPersister.addDomainSysPermissions(connection,
                                                                accessorResource,
                                                                sessionResource,
                                                                domainId,
                                                                requestedDomainPermissions);
   }

   private Set<DomainPermission> __getDirectDomainPermissions(SQLConnection connection,
                                                              Resource accessorResource,
                                                              Id<DomainId> domainId) {
      // only system permissions are possible on a domain
      return grantDomainPermissionSysPersister.getDomainSysPermissions(connection, accessorResource, domainId);
   }

   private Set<DomainPermission> __subtractDomainPermissionsIfGrantableFrom(Set<DomainPermission> candidatePermissionSet,
                                                                            Set<DomainPermission> grantorPermissionSet) {
      Set<DomainPermission> differenceSet = new HashSet<>(candidatePermissionSet);

      for (DomainPermission candidatePermission : candidatePermissionSet) {
         for (DomainPermission grantorPermission : grantorPermissionSet) {
            if (candidatePermission.isGrantableFrom(grantorPermission)) {
               differenceSet.remove(candidatePermission);
               break;
            }
         }
      }

      return differenceSet;
   }

   @Override
   public Set<DomainPermission> getDomainPermissions(Resource accessorResource,
                                                     String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();

         Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

         if (domainId == null) {
            throw new IllegalArgumentException("Could not find domain: " + domainName);
         }

         return __getDirectDomainPermissions(connection, accessorResource, domainId);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Map<String, Set<DomainPermission>> getDomainPermissionsMap(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __collapseDomainPermissions(grantDomainPermissionSysPersister.getDomainSysPermissions(connection,
                                                                                                      accessorResource));
      }
      finally {
         __closeConnection(connection);
      }

   }

   @Override
   public Set<DomainPermission> getEffectiveDomainPermissions(Resource accessorResource,
                                                              String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();

         return __getEffectiveDomainPermissions(connection, accessorResource, domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<DomainPermission> __getEffectiveDomainPermissions(SQLConnection connection,
                                                                 Resource accessorResource,
                                                                 String domainName) {
      Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // only system permissions are possible on a domain
      return __collapseDomainPermissions(grantDomainPermissionSysPersister
                                               .getDomainSysPermissionsIncludeInherited(connection,
                                                                                        accessorResource,
                                                                                        domainId));
   }

   private Set<DomainPermission> __collapseDomainPermissions(Set<DomainPermission> domainPermissions) {
      final Set<DomainPermission> collapsedPermissions = new HashSet<>(domainPermissions);

      for (DomainPermission permission : domainPermissions) {
         for (DomainPermission grantEquivalentPermission : domainPermissions) {
            if (permission.isGrantableFrom(grantEquivalentPermission) && !permission.equals(grantEquivalentPermission)) {
               collapsedPermissions.remove(permission);
               break;
            }
         }
      }

      return collapsedPermissions;
   }

   @Override
   public Map<String, Set<DomainPermission>> getEffectiveDomainPermissionsMap(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __collapseDomainPermissions(grantDomainPermissionSysPersister
                                                  .getDomainSysPermissionsIncludeInherited(connection, accessorResource));
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Map<String, Set<DomainPermission>> __collapseDomainPermissions(Map<String, Set<DomainPermission>> domainPermissionsMap) {
      Map<String, Set<DomainPermission>> collapsedDomainPermissionsMap = new HashMap<>(domainPermissionsMap.size());

      for (String domainName : domainPermissionsMap.keySet()) {
         collapsedDomainPermissionsMap.put(domainName, __collapseDomainPermissions(domainPermissionsMap.get(domainName)));
      }

      return collapsedDomainPermissionsMap;
   }

   @Override
   public void setDomainCreatePermissions(Resource accessorResource,
                                          Set<DomainCreatePermission> domainCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionsSpecified(domainCreatePermissions);

      try {
         connection = __getConnection();

         __setDirectDomainCreatePermissions(connection, accessorResource, domainCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __setDirectDomainCreatePermissions(SQLConnection connection,
                                                   Resource accessorResource,
                                                   Set<DomainCreatePermission> requestedDomainCreatePermissions) {
      __assertSetContainsDomainCreateSystemPermission(requestedDomainCreatePermissions);

      resourcePersister.verifyResourceExists(connection, accessorResource);

      // check if grantor (=session resource) is authorized to add/remove requested permissions
      final Set<DomainCreatePermission>
            grantorPermissions
            = __getEffectiveDomainCreatePermissions(connection, sessionResource);

      final Set<DomainCreatePermission>
            directAccessorPermissions
            = __getDirectDomainCreatePermissions(connection, accessorResource);

      final Set<DomainCreatePermission>
            requestedAddPermissions
            = __subtract(requestedDomainCreatePermissions, directAccessorPermissions);

      if (!requestedAddPermissions.isEmpty()) {
         final Set<DomainCreatePermission>
               unauthorizedAddPermissions
               = __subtractDomainCreatePermissionsIfGrantableFrom(requestedAddPermissions, grantorPermissions);

         if (unauthorizedAddPermissions.size() > 0) {
            throw new NotAuthorizedException(accessorResource,
                                             "add the following domain create permission(s): " + unauthorizedAddPermissions);
         }
      }

      final Set<DomainCreatePermission>
            requestedRemovePermissions
            = __subtract(directAccessorPermissions, requestedDomainCreatePermissions);

      if (!requestedRemovePermissions.isEmpty()) {
         final Set<DomainCreatePermission>
               unauthorizedRemovePermissions
               = __subtractDomainCreatePermissionsIfGrantableFrom(requestedRemovePermissions, grantorPermissions);

         if (unauthorizedRemovePermissions.size() > 0) {
            throw new NotAuthorizedException(accessorResource,
                                             "remove the following domain create permission(s): " + unauthorizedRemovePermissions);
         }
      }

      // NOTE: our current data model only support system permissions for domains

      // revoke any existing domain system permission (*CREATE) this accessor has to this domain
      grantDomainCreatePermissionSysPersister.removeDomainCreateSysPermissions(connection, accessorResource);
      // revoke any existing domain post create system permissions this accessor has to this domain
      grantDomainCreatePermissionPostCreateSysPersister.removeDomainCreatePostCreateSysPermissions(connection,
                                                                                                   accessorResource);

      // add the domain system permissions (*CREATE)
      grantDomainCreatePermissionSysPersister.addDomainCreateSysPermissions(connection,
                                                                            accessorResource,
                                                                            sessionResource,
                                                                            requestedDomainCreatePermissions);
      // add the domain post create system permissions
      grantDomainCreatePermissionPostCreateSysPersister
            .addDomainCreatePostCreateSysPermissions(connection,
                                                     accessorResource,
                                                     sessionResource,
                                                     requestedDomainCreatePermissions);
   }

   private void __assertSetContainsDomainCreateSystemPermission(Set<DomainCreatePermission> domainCreatePermissions) {
      if (!domainCreatePermissions.isEmpty()) {
         boolean createSysPermissionFound = false;
         for (final DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
            if (domainCreatePermission.isSystemPermission()
                  && DomainCreatePermissions.CREATE.equals(domainCreatePermission.getPermissionName())) {
               createSysPermissionFound = true;
               break;
            }
         }
         // if at least one permission is specified, then there must be a *CREATE permission in the set
         if (!createSysPermissionFound) {
            throw new IllegalArgumentException("Domain create permission *CREATE must be specified");
         }
      }
   }

   private Set<DomainCreatePermission> __getDirectDomainCreatePermissions(SQLConnection connection,
                                                                          Resource accessorResource) {
      final Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions
            .addAll(grantDomainCreatePermissionSysPersister.getDomainCreateSysPermissions(connection,
                                                                                          accessorResource));
      domainCreatePermissions
            .addAll(grantDomainCreatePermissionPostCreateSysPersister.getDomainCreatePostCreateSysPermissions(
                  connection,
                  accessorResource));
      return domainCreatePermissions;
   }

   private Set<DomainCreatePermission> __subtractDomainCreatePermissionsIfGrantableFrom(Set<DomainCreatePermission> candidatePermissionSet,
                                                                                        Set<DomainCreatePermission> grantorPermissionSet) {
      Set<DomainCreatePermission> differenceSet = new HashSet<>(candidatePermissionSet);

      for (DomainCreatePermission candidatePermission : candidatePermissionSet) {
         for (DomainCreatePermission grantorPermission : grantorPermissionSet) {
            if (candidatePermission.isGrantableFrom(grantorPermission)) {
               differenceSet.remove(candidatePermission);
               break;
            }
         }
      }

      return differenceSet;
   }

   @Override
   public Set<DomainCreatePermission> getDomainCreatePermissions(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __getDirectDomainCreatePermissions(connection, accessorResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<DomainCreatePermission> getEffectiveDomainCreatePermissions(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __getEffectiveDomainCreatePermissions(connection, accessorResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<DomainCreatePermission> __getEffectiveDomainCreatePermissions(SQLConnection connection,
                                                                             Resource accessorResource) {
      final Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions
            .addAll(grantDomainCreatePermissionSysPersister.getDomainCreateSysPermissionsIncludeInherited(connection,
                                                                                                          accessorResource));
      domainCreatePermissions
            .addAll(grantDomainCreatePermissionPostCreateSysPersister
                          .getDomainCreatePostCreateSysPermissionsIncludeInherited(connection,
                                                                                   accessorResource));
      return __collapseDomainCreatePermissions(domainCreatePermissions);
   }

   private Set<DomainCreatePermission> __collapseDomainCreatePermissions(Set<DomainCreatePermission> domainCreatePermissions) {
      final Set<DomainCreatePermission> collapsedPermissions = new HashSet<>(domainCreatePermissions);

      for (DomainCreatePermission permission : domainCreatePermissions) {
         for (DomainCreatePermission grantEquivalentPermission : domainCreatePermissions) {
            if (permission.isGrantableFrom(grantEquivalentPermission) && !permission.equals(grantEquivalentPermission)) {
               collapsedPermissions.remove(permission);
               break;
            }
         }
      }

      return collapsedPermissions;
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions,
                                            String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionsSpecified(resourceCreatePermissions);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();

         __setDirectResourceCreatePermissions(connection,
                                              accessorResource,
                                              resourceClassName,
                                              resourceCreatePermissions,
                                              domainName
         );
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionsSpecified(resourceCreatePermissions);

      try {
         connection = __getConnection();

         __setDirectResourceCreatePermissions(connection,
                                              accessorResource,
                                              resourceClassName,
                                              resourceCreatePermissions,
                                              sessionResourceDomainName
         );
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __setDirectResourceCreatePermissions(SQLConnection connection,
                                                     Resource accessorResource,
                                                     String resourceClassName,
                                                     Set<ResourceCreatePermission> requestedResourceCreatePermissions,
                                                     String domainName) {
      resourcePersister.verifyResourceExists(connection, accessorResource);

      // verify that resource class is defined and get its metadata
      final ResourceClassInternalInfo resourceClassInfo
            = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);

      if (resourceClassInfo == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      final Id<ResourceClassId> resourceClassId = Id.from(resourceClassInfo.getResourceClassId());

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // ensure that the *CREATE system permissions was specified
      __assertSetContainsResourceCreateSystemPermission(requestedResourceCreatePermissions);

      // ensure that the post create permissions are all in the correct resource class
      __assertUniquePostCreatePermissionsNamesForResourceClass(connection, requestedResourceCreatePermissions, resourceClassInfo);

      // check if the grantor (=session resource) is authorized to grant the requested permissions
      if (!__isSuperUserOfDomain(connection, sessionResource, domainName)) {
         final Set<ResourceCreatePermission>
               grantorPermissions
               = __getEffectiveResourceCreatePermissions(connection,
                                                         sessionResource,
                                                         resourceClassName,
                                                         domainName);

         final Set<ResourceCreatePermission>
               directAccessorPermissions
               = __getDirectResourceCreatePermissions(connection,
                                                      accessorResource,
                                                      resourceClassId,
                                                      domainId);

         final Set<ResourceCreatePermission>
               requestedAddPermissions
               = __subtract(requestedResourceCreatePermissions, directAccessorPermissions);

         if (!requestedAddPermissions.isEmpty()) {
            final Set<ResourceCreatePermission>
                  unauthorizedAddPermissions
                  = __subtractResourceCreatePermissionsIfGrantableFrom(requestedAddPermissions, grantorPermissions);

            if (unauthorizedAddPermissions.size() > 0) {
               throw new NotAuthorizedException(accessorResource,
                                                "add the following permission(s): " + unauthorizedAddPermissions);
            }
         }

         final Set<ResourceCreatePermission>
               requestedRemovePermissions
               = __subtract(directAccessorPermissions, requestedResourceCreatePermissions);

         if (!requestedRemovePermissions.isEmpty()) {
            final Set<ResourceCreatePermission>
                  unauthorizedRemovePermissions
                  = __subtractResourceCreatePermissionsIfGrantableFrom(requestedRemovePermissions, grantorPermissions);

            if (unauthorizedRemovePermissions.size() > 0) {
               throw new NotAuthorizedException(accessorResource,
                                                "remove the following permission(s): " + unauthorizedRemovePermissions);
            }
         }
      }

      // revoke any existing *CREATE system permissions this accessor has to this resource class
      grantResourceCreatePermissionSysPersister.removeResourceCreateSysPermissions(connection,
                                                                                   accessorResource,
                                                                                   resourceClassId,
                                                                                   domainId);


      // revoke any existing post create system permissions this accessor has to this resource class
      grantResourceCreatePermissionPostCreateSysPersister.removeResourceCreatePostCreateSysPermissions(connection,
                                                                                                       accessorResource,
                                                                                                       resourceClassId,
                                                                                                       domainId);

      // revoke any existing post create non-system permissions this accessor has to this resource class
      grantResourceCreatePermissionPostCreatePersister.removeResourceCreatePostCreatePermissions(connection,
                                                                                                 accessorResource,
                                                                                                 resourceClassId,
                                                                                                 domainId);

      // grant the *CREATE system permissions
      grantResourceCreatePermissionSysPersister.addResourceCreateSysPermissions(connection,
                                                                                accessorResource,
                                                                                resourceClassId,
                                                                                domainId,
                                                                                requestedResourceCreatePermissions,
                                                                                sessionResource);

      // grant the post create system permissions
      grantResourceCreatePermissionPostCreateSysPersister.addResourceCreatePostCreateSysPermissions(connection,
                                                                                                    accessorResource,
                                                                                                    resourceClassId,
                                                                                                    domainId,
                                                                                                    requestedResourceCreatePermissions,
                                                                                                    sessionResource);

      // grant the post create non-system permissions
      grantResourceCreatePermissionPostCreatePersister.addResourceCreatePostCreatePermissions(connection,
                                                                                              accessorResource,
                                                                                              resourceClassId,
                                                                                              domainId,
                                                                                              requestedResourceCreatePermissions,
                                                                                              sessionResource);
   }

   private void __assertSetContainsResourceCreateSystemPermission(Set<ResourceCreatePermission> resourceCreatePermissions) {
      if (!resourceCreatePermissions.isEmpty()) {
         boolean createSysPermissionFound = false;
         for (final ResourceCreatePermission resourceCreatePermission : resourceCreatePermissions) {
            if (resourceCreatePermission.isSystemPermission()
                  && ResourceCreatePermissions.CREATE.equals(resourceCreatePermission.getPermissionName())) {
               createSysPermissionFound = true;
               break;
            }
         }
         // if at least one permission is specified, then there must be a *CREATE permission in the set
         if (!createSysPermissionFound) {
            throw new IllegalArgumentException("Permission: *CREATE must be specified");
         }
      }
   }

   private void __assertUniquePostCreatePermissionsNamesForResourceClass(SQLConnection connection,
                                                                         Set<ResourceCreatePermission> resourceCreatePermissions,
                                                                         ResourceClassInternalInfo resourceClassInternalInfo) {
      final List<String> validPermissionNames
            = resourceClassPermissionPersister.getPermissionNames(connection, resourceClassInternalInfo.getResourceClassName());
      final Set<String> uniquePermissionNames = new HashSet<>(resourceCreatePermissions.size());

      for (final ResourceCreatePermission resourceCreatePermission : resourceCreatePermissions) {
         if (resourceCreatePermission.isSystemPermission()
               && ResourceCreatePermissions.CREATE.equals(resourceCreatePermission.getPermissionName())) {
            continue;
         }

         final ResourcePermission postCreateResourcePermission = resourceCreatePermission.getPostCreateResourcePermission();

         if (postCreateResourcePermission.isSystemPermission()) {
            // we allow impersonate and reset_credentials system permissions only for authenticatable resource classes
            if (!resourceClassInternalInfo.isAuthenticatable()
                  && (ResourcePermissions.IMPERSONATE.equals(postCreateResourcePermission.getPermissionName())
                  || ResourcePermissions.RESET_CREDENTIALS.equals(postCreateResourcePermission.getPermissionName()))) {
               throw new IllegalArgumentException("Permission: " + postCreateResourcePermission
                                                      + ", not valid for unauthenticatable resource");
            }
         }
         else {
            // every non-system permission must be defined for the resource class specified
            if (!validPermissionNames.contains(postCreateResourcePermission.getPermissionName())) {
               throw new IllegalArgumentException("Permission: " + postCreateResourcePermission.getPermissionName()
                                                      + " does not exist for the specified resource class: "
                                                      + resourceClassInternalInfo.getResourceClassName());
            }
         }
         if (uniquePermissionNames.contains(postCreateResourcePermission.getPermissionName())) {
            throw new IllegalArgumentException("Duplicate permission: " + postCreateResourcePermission.getPermissionName()
                                                   + " that only differs in 'withGrant' option");
         }
         else {
            uniquePermissionNames.add(postCreateResourcePermission.getPermissionName());
         }
      }
   }

   private Set<ResourceCreatePermission> __subtractResourceCreatePermissionsIfGrantableFrom(Set<ResourceCreatePermission> candidatePermissionSet,
                                                                                            Set<ResourceCreatePermission> grantorPermissionSet) {
      Set<ResourceCreatePermission> differenceSet = new HashSet<>(candidatePermissionSet);

      for (ResourceCreatePermission candidatePermission : candidatePermissionSet) {
         for (ResourceCreatePermission grantorPermission : grantorPermissionSet) {
            if (candidatePermission.isGrantableFrom(grantorPermission)) {
               differenceSet.remove(candidatePermission);
               break;
            }
         }
      }

      return differenceSet;
   }

   private <T> Set<T> __subtract(Set<T> minuendSet, Set<T> subtrahendSet) {
      Set<T> differenceSet = new HashSet<>(minuendSet);

      differenceSet.removeAll(subtrahendSet);

      return differenceSet;
   }

   private Set<ResourceCreatePermission> __getDirectResourceCreatePermissions(SQLConnection connection,
                                                                              Resource accessorResource,
                                                                              Id<ResourceClassId> resourceClassId,
                                                                              Id<DomainId> domainId) {
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();

      // first get the *CREATE system permission the accessor has directly to the specified resource class
      resourceCreatePermissions
            .addAll(grantResourceCreatePermissionSysPersister.getResourceCreateSysPermissions(connection,
                                                                                              accessorResource,
                                                                                              resourceClassId,
                                                                                              domainId));

      // next get the post create system permissions the accessor has directly to the specified resource class
      resourceCreatePermissions
            .addAll(grantResourceCreatePermissionPostCreateSysPersister.getResourceCreatePostCreateSysPermissions(
                  connection,
                  accessorResource,
                  resourceClassId,
                  domainId));

      // next get the post create non-system permissions the accessor has directly to the specified resource class
      resourceCreatePermissions
            .addAll(grantResourceCreatePermissionPostCreatePersister.getResourceCreatePostCreatePermissions(
                  connection,
                  accessorResource,
                  resourceClassId,
                  domainId));

      return resourceCreatePermissions;
   }

   @Override
   public Set<ResourceCreatePermission> getResourceCreatePermissions(Resource accessorResource,
                                                                     String resourceClassName,
                                                                     String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __getDirectResourceCreatePermissions(connection,
                                                     accessorResource,
                                                     resourceClassName,
                                                     domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<ResourceCreatePermission> __getDirectResourceCreatePermissions(SQLConnection connection,
                                                                              Resource accessorResource,
                                                                              String resourceClassName,
                                                                              String domainName) {
      // verify that resource class is defined
      Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      return __getDirectResourceCreatePermissions(connection,
                                                  accessorResource,
                                                  resourceClassId,
                                                  domainId);
   }

   @Override
   public Set<ResourceCreatePermission> getResourceCreatePermissions(Resource accessorResource,
                                                                     String resourceClassName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         return __getDirectResourceCreatePermissions(connection,
                                                     accessorResource,
                                                     resourceClassName,
                                                     sessionResourceDomainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreatePermissionsMap(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __getDirectResourceCreatePermissionsMap(connection, accessorResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Map<String, Map<String, Set<ResourceCreatePermission>>> __getDirectResourceCreatePermissionsMap(SQLConnection connection,
                                                                                                           Resource accessorResource) {
      // collect all the create permissions that the accessor has
      Map<String, Map<String, Set<ResourceCreatePermission>>> allResourceCreatePermissionsMap = new HashMap<>();

      // read the *CREATE system permissions and add to allResourceCreatePermissionsMap
      allResourceCreatePermissionsMap
            .putAll(grantResourceCreatePermissionSysPersister.getResourceCreateSysPermissions(connection, accessorResource));

      // read the post create system permissions and add to allResourceCreatePermissionsMap
      __mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(
            grantResourceCreatePermissionPostCreateSysPersister
                  .getResourceCreatePostCreateSysPermissions(connection, accessorResource),
            allResourceCreatePermissionsMap);

      // read the post create non-system permissions and add to allResourceCreatePermissionsMap
      __mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(
            grantResourceCreatePermissionPostCreatePersister
                  .getResourceCreatePostCreatePermissions(connection, accessorResource),
            allResourceCreatePermissionsMap);

      return __collapseResourceCreatePermissions(allResourceCreatePermissionsMap);
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName,
                                                                              String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __getEffectiveResourceCreatePermissions(connection,
                                                        accessorResource,
                                                        resourceClassName,
                                                        domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         return __getEffectiveResourceCreatePermissions(connection,
                                                        accessorResource,
                                                        resourceClassName,
                                                        sessionResourceDomainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<ResourceCreatePermission> __getEffectiveResourceCreatePermissions(SQLConnection connection,
                                                                                 Resource accessorResource,
                                                                                 String resourceClassName,
                                                                                 String domainName) {
      // verify that resource class is defined
      Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // collect the create permissions that this resource has to this resource class
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();

      // first read the *CREATE system permission the accessor has to the specified resource class
      resourceCreatePermissions.addAll(
            grantResourceCreatePermissionSysPersister.getResourceCreateSysPermissionsIncludeInherited(connection,
                                                                                                      accessorResource,
                                                                                                      resourceClassId,
                                                                                                      domainId));

      // next read the post create system permissions the accessor has to the specified resource class
      resourceCreatePermissions
            .addAll(grantResourceCreatePermissionPostCreateSysPersister
                          .getResourceCreatePostCreateSysPermissionsIncludeInherited(connection,
                                                                                     accessorResource,
                                                                                     resourceClassId,
                                                                                     domainId));

      // next read the post create non-system permissions the accessor has to the specified resource class
      resourceCreatePermissions
            .addAll(grantResourceCreatePermissionPostCreatePersister
                          .getResourceCreatePostCreatePermissionsIncludeInherited(connection,
                                                                                  accessorResource,
                                                                                  resourceClassId,
                                                                                  domainId));
      return __collapseResourceCreatePermissions(resourceCreatePermissions);
   }

   private Set<ResourceCreatePermission> __collapseResourceCreatePermissions(Set<ResourceCreatePermission> resourceCreatePermissions) {
      final Set<ResourceCreatePermission> collapsedPermissions = new HashSet<>(resourceCreatePermissions);

      for (ResourceCreatePermission permission : resourceCreatePermissions) {
         for (ResourceCreatePermission grantEquivalentPermission : resourceCreatePermissions) {
            if (permission.isGrantableFrom(grantEquivalentPermission) && !permission.equals(grantEquivalentPermission)) {
               collapsedPermissions.remove(permission);
               break;
            }
         }
      }

      return collapsedPermissions;
   }

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getEffectiveResourceCreatePermissionsMap(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __getEffectiveResourceCreatePermissionsMap(connection,
                                                           accessorResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Map<String, Map<String, Set<ResourceCreatePermission>>> __getEffectiveResourceCreatePermissionsMap(
         SQLConnection connection,
         Resource accessorResource) {
      // collect all the create permissions that the accessor has
      Map<String, Map<String, Set<ResourceCreatePermission>>> allResourceCreatePermissionsMap = new HashMap<>();

      // read the *CREATE system permissions and add to allResourceCreatePermissionsMap
      allResourceCreatePermissionsMap
            .putAll(grantResourceCreatePermissionSysPersister
                          .getResourceCreateSysPermissionsIncludeInherited(connection, accessorResource));

      // read the post create system permissions and add to allResourceCreatePermissionsMap
      __mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(
            grantResourceCreatePermissionPostCreateSysPersister
                  .getResourceCreatePostCreateSysPermissionsIncludeInherited(connection, accessorResource),
            allResourceCreatePermissionsMap);

      // read the post create non-system permissions and add to allResourceCreatePermissionsMap
      __mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(
            grantResourceCreatePermissionPostCreatePersister
                  .getResourceCreatePostCreatePermissionsIncludeInherited(connection, accessorResource),
            allResourceCreatePermissionsMap);

      return __collapseResourceCreatePermissions(allResourceCreatePermissionsMap);
   }

   private void __mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(Map<String, Map<String, Set<ResourceCreatePermission>>> sourceCreatePermissionsMap,
                                                                                Map<String, Map<String, Set<ResourceCreatePermission>>> targetCreatePermissionsMap) {
      for (String domainName : sourceCreatePermissionsMap.keySet()) {
         Map<String, Set<ResourceCreatePermission>> targetCreatePermsForDomainMap;
         // does the target map have domain?
         if ((targetCreatePermsForDomainMap = targetCreatePermissionsMap.get(domainName)) == null) {
            // no, add the domain
            targetCreatePermissionsMap.put(domainName, targetCreatePermsForDomainMap = new HashMap<>());
         }
         for (String resourceClassName : sourceCreatePermissionsMap.get(domainName).keySet()) {
            Set<ResourceCreatePermission> targetCreatePermsForClassSet;
            // does the target map have the resource class?
            if ((targetCreatePermsForClassSet = targetCreatePermsForDomainMap.get(resourceClassName)) == null) {
               // no, add the resource class
               targetCreatePermsForDomainMap.put(resourceClassName,
                                                 targetCreatePermsForClassSet = new HashSet<>());
            }
            // get the source permissions for the domain + resource class
            final Set<ResourceCreatePermission> sourceCreatePermsForClassSet
                  = sourceCreatePermissionsMap.get(domainName).get(resourceClassName);
            // add the source permissions above to the target for the respective domain + resource class
            targetCreatePermsForClassSet.addAll(sourceCreatePermsForClassSet);
         }
      }
   }

   private Map<String, Map<String, Set<ResourceCreatePermission>>> __collapseResourceCreatePermissions(Map<String, Map<String, Set<ResourceCreatePermission>>> resourceCreatePermissionsMap) {
      for (String domainName : resourceCreatePermissionsMap.keySet()) {
         final Map<String, Set<ResourceCreatePermission>> createPermissionsByDomainMap
               = resourceCreatePermissionsMap.get(domainName);

         for (String resourceClassName : createPermissionsByDomainMap.keySet()) {
            final Set<ResourceCreatePermission> createPermissionsByResourceClassMap
                  = createPermissionsByDomainMap.get(resourceClassName);
            createPermissionsByDomainMap.put(resourceClassName,
                                             __collapseResourceCreatePermissions(createPermissionsByResourceClassMap));
         }
      }

      return resourceCreatePermissionsMap;
   }

   @Override
   public void setResourcePermissions(Resource accessorResource,
                                      Resource accessedResource,
                                      Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionsSpecified(resourcePermissions);

      try {
         connection = __getConnection();

         __setDirectResourcePermissions(connection,
                                        accessorResource,
                                        accessedResource,
                                        resourcePermissions,
                                        sessionResource,
                                        false);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __setDirectResourcePermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               Resource accessedResource,
                                               Set<ResourcePermission> requestedResourcePermissions,
                                               Resource grantorResource,
                                               boolean newResourceMode) {
      final ResourceClassInternalInfo accessedResourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfoByResourceId(connection, accessedResource);

      // next ensure that the requested permissions are all in the correct resource class
      __assertUniqueResourcePermissionsNamesForResourceClass(connection,
                                                             requestedResourcePermissions,
                                                             accessedResourceClassInternalInfo);

      // if this method is being called to set the post create permissions on a newly created resource
      // we do not perform the security checks below, since it would be incorrect
      if (!newResourceMode) {
         resourcePersister.verifyResourceExists(connection, accessorResource);

         if (!__isSuperUserOfResource(connection, grantorResource, accessedResource)) {
            // next check if the grantor (i.e. session resource) has permissions to grant the requested permissions
            final Set<ResourcePermission>
                  grantorResourcePermissions
                  = __getEffectiveResourcePermissions(connection,
                                                      grantorResource,
                                                      accessedResource);

            final Set<ResourcePermission>
                  directAccessorResourcePermissions
                  = __getDirectResourcePermissions(connection,
                                                   accessorResource,
                                                   accessedResource);

            final Set<ResourcePermission>
                  requestedAddPermissions
                  = __subtract(requestedResourcePermissions, directAccessorResourcePermissions);

            if (requestedAddPermissions.size() > 0) {
               final Set<ResourcePermission>
                     unauthorizedAddPermissions
                     = __subtractResourcePermissionsIfGrantableFrom(requestedAddPermissions, grantorResourcePermissions);

               if (unauthorizedAddPermissions.size() > 0) {
                  throw new NotAuthorizedException(accessorResource,
                                                   "add the following permission(s): " + unauthorizedAddPermissions);
               }
            }

            final Set<ResourcePermission>
                  requestedRemovePermissions
                  = __subtract(directAccessorResourcePermissions, requestedResourcePermissions);

            if (requestedRemovePermissions.size() > 0) {
               final Set<ResourcePermission>
                     unauthorizedRemovePermissions
                     = __subtractResourcePermissionsIfGrantableFrom(requestedRemovePermissions, grantorResourcePermissions);

               if (unauthorizedRemovePermissions.size() > 0) {
                  throw new NotAuthorizedException(accessorResource,
                                                   "remove the following permission(s): " + unauthorizedRemovePermissions);
               }
            }
         }

         // if inherit permissions are about to be granted, first check for cycles
         if (requestedResourcePermissions.contains(ResourcePermission_INHERIT)
               || requestedResourcePermissions.contains(ResourcePermission_INHERIT_GRANT)) {
            Set<ResourcePermission> reversePathResourcePermissions = __getEffectiveResourcePermissions(connection,
                                                                                                       accessedResource,
                                                                                                       accessorResource);

            if (reversePathResourcePermissions.contains(ResourcePermission_INHERIT)
                  || reversePathResourcePermissions.contains(ResourcePermission_INHERIT_GRANT)) {
               throw new OaccException("Granting the requested permission(s): "
                                                      + requestedResourcePermissions
                                                      + " will cause a cycle between: "
                                                      + accessorResource
                                                      + " and: "
                                                      + accessedResource);
            }
         }

         // revoke any existing direct system permissions between the accessor and the accessed resource
         grantResourcePermissionSysPersister.removeResourceSysPermissions(connection,
                                                                          accessorResource,
                                                                          accessedResource);

         // revoke any existing direct non-system permissions between the accessor and the accessed resource
         grantResourcePermissionPersister.removeResourcePermissions(connection, accessorResource, accessedResource);
      }

      // add the new direct system permissions
      grantResourcePermissionSysPersister.addResourceSysPermissions(connection,
                                                                    accessorResource,
                                                                    accessedResource,
                                                                    Id.<ResourceClassId>from(
                                                                          accessedResourceClassInternalInfo.getResourceClassId()),
                                                                    requestedResourcePermissions,
                                                                    grantorResource);

      // add the new direct non-system permissions
      grantResourcePermissionPersister.addResourcePermissions(connection,
                                                              accessorResource,
                                                              accessedResource,
                                                              Id.<ResourceClassId>from(accessedResourceClassInternalInfo.getResourceClassId()),
                                                              requestedResourcePermissions,
                                                              grantorResource);
   }

   private void __assertUniqueResourcePermissionsNamesForResourceClass(SQLConnection connection,
                                                                       Set<ResourcePermission> resourcePermissions,
                                                                       ResourceClassInternalInfo resourceClassInternalInfo) {
      final List<String> validPermissionNames
            = resourceClassPermissionPersister.getPermissionNames(connection, resourceClassInternalInfo.getResourceClassName());
      final Set<String> uniquePermissionNames = new HashSet<>(resourcePermissions.size());

      for (final ResourcePermission resourcePermission : resourcePermissions) {
         if (resourcePermission.isSystemPermission()) {
            // we allow impersonate and reset_credentials system permissions only for authenticatable resource classes
            if (!resourceClassInternalInfo.isAuthenticatable()
                  && (ResourcePermissions.IMPERSONATE.equals(resourcePermission.getPermissionName())
                  || ResourcePermissions.RESET_CREDENTIALS.equals(resourcePermission.getPermissionName()))) {
               throw new IllegalArgumentException("Permission: " + resourcePermission
                                                      + ", not valid for unauthenticatable resource");
            }
         }
         else {
            // every non-system permission must be defined for the resource class specified
            if (!validPermissionNames.contains(resourcePermission.getPermissionName())) {
               throw new IllegalArgumentException("Permission: " + resourcePermission.getPermissionName()
                                                      + " does not exist for the specified resource class: "
                                                      + resourceClassInternalInfo.getResourceClassName());
            }
         }
         if (uniquePermissionNames.contains(resourcePermission.getPermissionName())) {
            throw new IllegalArgumentException("Duplicate permission: " + resourcePermission.getPermissionName()
                                                   + " that only differs in 'withGrant' option");
         }
         else {
            uniquePermissionNames.add(resourcePermission.getPermissionName());
         }
      }
   }

   private Set<ResourcePermission> __subtractResourcePermissionsIfGrantableFrom(Set<ResourcePermission> candidatePermissionSet,
                                                                                Set<ResourcePermission> grantorPermissionSet) {
      Set<ResourcePermission> differenceSet = new HashSet<>(candidatePermissionSet);

      for (ResourcePermission candidatePermission : candidatePermissionSet) {
         for (ResourcePermission grantorPermission : grantorPermissionSet) {
            if (candidatePermission.isGrantableFrom(grantorPermission)) {
               differenceSet.remove(candidatePermission);
               break;
            }
         }
      }

      return differenceSet;
   }

   @Override
   public Set<ResourcePermission> getResourcePermissions(Resource accessorResource,
                                                         Resource accessedResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);

      try {
         connection = __getConnection();

         return __getDirectResourcePermissions(connection, accessorResource, accessedResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<ResourcePermission> __getDirectResourcePermissions(SQLConnection connection,
                                                                  Resource accessorResource,
                                                                  Resource accessedResource) {
      Set<ResourcePermission> resourcePermissions = new HashSet<>();

      // collect the system permissions that the accessor resource has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionSysPersister.getResourceSysPermissions(connection,
                                                                                               accessorResource,
                                                                                               accessedResource));

      // collect the non-system permissions that the accessor has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionPersister.getResourcePermissions(connection,
                                                                                         accessorResource,
                                                                                         accessedResource));

      return resourcePermissions;
   }

   @Override
   public Set<ResourcePermission> getEffectiveResourcePermissions(Resource accessorResource, Resource accessedResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);

      try {
         connection = __getConnection();

         return __getEffectiveResourcePermissions(connection, accessorResource, accessedResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<ResourcePermission> __getEffectiveResourcePermissions(SQLConnection connection,
                                                                     Resource accessorResource,
                                                                     Resource accessedResource) {
      Set<ResourcePermission> resourcePermissions = new HashSet<>();

      // collect the system permissions that the accessor resource has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionSysPersister
                                       .getResourceSysPermissionsIncludeInherited(connection,
                                                                                  accessorResource,
                                                                                  accessedResource));

      // collect the non-system permissions that the accessor has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionPersister.getResourcePermissionsIncludeInherited(connection,
                                                                                                         accessorResource,
                                                                                                         accessedResource));

      final Id<DomainId> accessedDomainId = resourcePersister.getDomainIdByResource(connection, accessedResource);
      final Id<ResourceClassId> accessedResourceClassId
            = Id.from(resourceClassPersister
                            .getResourceClassInfoByResourceId(connection, accessedResource)
                            .getResourceClassId());

      // collect the global system permissions that the accessor has to the accessed resource's domain
      resourcePermissions
            .addAll(grantGlobalResourcePermissionSysPersister.getGlobalSysPermissionsIncludeInherited(connection,
                                                                                                      accessorResource,
                                                                                                      accessedResourceClassId,
                                                                                                      accessedDomainId));

      // first collect the global non-system permissions that the accessor this resource has to the accessed resource's domain
      resourcePermissions
            .addAll(grantGlobalResourcePermissionPersister.getGlobalResourcePermissionsIncludeInherited(connection,
                                                                                                        accessorResource,
                                                                                                        accessedResourceClassId,
                                                                                                        accessedDomainId));
      return __collapseResourcePermissions(resourcePermissions);
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions,
                                            String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __setDirectGlobalPermissions(connection,
                                      accessorResource,
                                      resourceClassName,
                                      resourcePermissions,
                                      domainName
         );
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionsSpecified(resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         __setDirectGlobalPermissions(connection,
                                      accessorResource,
                                      resourceClassName,
                                      resourcePermissions,
                                      sessionResourceDomainName
         );
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __setDirectGlobalPermissions(SQLConnection connection,
                                             Resource accessorResource,
                                             String resourceClassName,
                                             Set<ResourcePermission> requestedResourcePermissions,
                                             String domainName) {
      resourcePersister.verifyResourceExists(connection, accessorResource);

      // verify that resource class is defined
      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      final ResourceClassInternalInfo resourceClassInternalInfo = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // next ensure that the requested permissions are all in the correct resource class
      __assertUniqueGlobalResourcePermissionNamesForResourceClass(connection, requestedResourcePermissions, resourceClassInternalInfo);

      if (!__isSuperUserOfDomain(connection, sessionResource, domainName)) {
         // check if the grantor (=session resource) is authorized to grant the requested permissions
         final Set<ResourcePermission>
               grantorPermissions
               = __getEffectiveGlobalResourcePermissions(connection,
                                                         sessionResource,
                                                         resourceClassName,
                                                         domainName);
         final Set<ResourcePermission>
               directAccessorPermissions
               = __getDirectGlobalResourcePermissions(connection,
                                                      accessorResource,
                                                      resourceClassId,
                                                      domainId);

         final Set<ResourcePermission>
               requestedAddPermissions
               = __subtract(requestedResourcePermissions, directAccessorPermissions);

         if (!requestedAddPermissions.isEmpty()) {
            final Set<ResourcePermission>
                  unauthorizedAddPermissions
                  = __subtractResourcePermissionsIfGrantableFrom(requestedAddPermissions, grantorPermissions);

            if (unauthorizedAddPermissions.size() > 0) {
               throw new NotAuthorizedException(accessorResource,
                                                "add the following global permission(s): " + unauthorizedAddPermissions);
            }
         }

         final Set<ResourcePermission>
               requestedRemovePermissions
               = __subtract(directAccessorPermissions, requestedResourcePermissions);

         if (!requestedRemovePermissions.isEmpty()) {
            final Set<ResourcePermission>
                  unauthorizedRemovePermissions
                  = __subtractResourcePermissionsIfGrantableFrom(requestedRemovePermissions, grantorPermissions);

            if (unauthorizedRemovePermissions.size() > 0) {
               throw new NotAuthorizedException(accessorResource,
                                                "remove the following global permission(s): " + unauthorizedRemovePermissions);
            }
         }
      }

      // revoke any existing system permissions this accessor has to this domain + resource class
      grantGlobalResourcePermissionSysPersister.removeGlobalSysPermissions(connection,
                                                                           accessorResource,
                                                                           resourceClassId,
                                                                           domainId);

      // revoke any existing non-system permissions that this grantor gave this accessor to this domain to the resource class
      grantGlobalResourcePermissionPersister.removeGlobalResourcePermissions(connection,
                                                                             accessorResource,
                                                                             resourceClassId,
                                                                             domainId);

      // add the new system permissions
      grantGlobalResourcePermissionSysPersister.addGlobalSysPermissions(connection,
                                                                        accessorResource,
                                                                        resourceClassId,
                                                                        domainId,
                                                                        requestedResourcePermissions,
                                                                        sessionResource);

      // add the new non-system permissions
      grantGlobalResourcePermissionPersister.addGlobalResourcePermissions(connection,
                                                                          accessorResource,
                                                                          resourceClassId,
                                                                          domainId,
                                                                          requestedResourcePermissions,
                                                                          sessionResource);
   }

   private Set<ResourcePermission> __getDirectGlobalResourcePermissions(SQLConnection connection,
                                                                        Resource accessorResource,
                                                                        Id<ResourceClassId> resourceClassId,
                                                                        Id<DomainId> domainId) {
      Set<ResourcePermission> resourcePermissions = new HashSet<>();

      // collect the global system permissions that the accessor resource has to the accessed resource class & domain directly
      resourcePermissions.addAll(grantGlobalResourcePermissionSysPersister.getGlobalSysPermissions(connection,
                                                                                                   accessorResource,
                                                                                                   resourceClassId,
                                                                                                   domainId));

      // collect the global non-system permissions that the accessor has to the accessed resource class & domain directly
      resourcePermissions.addAll(grantGlobalResourcePermissionPersister.getGlobalResourcePermissions(connection,
                                                                                                     accessorResource,
                                                                                                     resourceClassId,
                                                                                                     domainId));

      return resourcePermissions;
   }

   private void __assertUniqueGlobalResourcePermissionNamesForResourceClass(SQLConnection connection,
                                                                            Set<ResourcePermission> requestedResourcePermissions,
                                                                            ResourceClassInternalInfo resourceClassInternalInfo) {
      final List<String> validPermissionNames
            = resourceClassPermissionPersister.getPermissionNames(connection, resourceClassInternalInfo.getResourceClassName());
      final HashSet<String> uniquePermissionNames = new HashSet<>(requestedResourcePermissions.size());

      for (final ResourcePermission resourcePermission : requestedResourcePermissions) {
         // we prohibit granting the system INHERIT permission, since cycle checking may be prohibitively compute intensive
         if (resourcePermission.isSystemPermission()) {
            if (ResourcePermission_INHERIT.equals(resourcePermission)) {
               throw new IllegalArgumentException("Permission: " + resourcePermission + ", not valid in this context");
            }
            if (!resourceClassInternalInfo.isAuthenticatable()
                  && (ResourcePermissions.IMPERSONATE.equals(resourcePermission.getPermissionName())
                  || ResourcePermissions.RESET_CREDENTIALS.equals(resourcePermission.getPermissionName()))) {
               throw new IllegalArgumentException("Permission: " + resourcePermission + ", not valid for unauthenticatable resource");
            }
         }
         else {
            // every non-system permission must be defined for the resource class specified
            if (!validPermissionNames.contains(resourcePermission.getPermissionName())) {
               throw new IllegalArgumentException("Permission: " + resourcePermission.getPermissionName()
                                                + " does not exist for the specified resource class: "
                                                + resourceClassInternalInfo.getResourceClassName());
            }
         }
         if (uniquePermissionNames.contains(resourcePermission.getPermissionName())) {
            throw new IllegalArgumentException("Duplicate permission: "
                                             + resourcePermission.getPermissionName() + " that only differs in 'withGrant' option");
         }
         else {
            uniquePermissionNames.add(resourcePermission.getPermissionName());
         }
      }
   }

   @Override
   public Set<ResourcePermission> getGlobalResourcePermissions(Resource accessorResource,
                                                               String resourceClassName,
                                                               String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __getDirectGlobalResourcePermissions(connection,
                                                     accessorResource,
                                                     resourceClassName,
                                                     domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<ResourcePermission> __getDirectGlobalResourcePermissions(SQLConnection connection,
                                                                        Resource accessorResource,
                                                                        String resourceClassName,
                                                                        String domainName) {
      // verify that resource class is defined
      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      return __getDirectGlobalResourcePermissions(connection,
                                                  accessorResource,
                                                  resourceClassId,
                                                  domainId);
   }

   @Override
   public Set<ResourcePermission> getGlobalResourcePermissions(Resource accessorResource,
                                                               String resourceClassName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         return __getDirectGlobalResourcePermissions(connection,
                                                     accessorResource,
                                                     resourceClassName,
                                                     sessionResourceDomainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName,
                                                                        String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __getEffectiveGlobalResourcePermissions(connection,
                                                        accessorResource,
                                                        resourceClassName,
                                                        domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         return __getEffectiveGlobalResourcePermissions(connection,
                                                        accessorResource,
                                                        resourceClassName,
                                                        sessionResourceDomainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<ResourcePermission> __getEffectiveGlobalResourcePermissions(SQLConnection connection,
                                                                           Resource accessorResource,
                                                                           String resourceClassName,
                                                                           String domainName) {
      // verify that resource class is defined
      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      Set<ResourcePermission> resourcePermissions = new HashSet<>();

      // first collect the system permissions that the accessor has to the accessed resource
      resourcePermissions.addAll(grantGlobalResourcePermissionSysPersister
                                       .getGlobalSysPermissionsIncludeInherited(connection,
                                                                                accessorResource,
                                                                                resourceClassId,
                                                                                domainId));

      // first collect the non-system permissions that the accessor this resource has to the accessor resource
      resourcePermissions.addAll(grantGlobalResourcePermissionPersister
                                       .getGlobalResourcePermissionsIncludeInherited(connection,
                                                                                     accessorResource,
                                                                                     resourceClassId,
                                                                                     domainId));
      return __collapseResourcePermissions(resourcePermissions);
   }

   private Set<ResourcePermission> __collapseResourcePermissions(Set<ResourcePermission> resourcePermissions) {
      final Set<ResourcePermission> collapsedPermissions = new HashSet<>(resourcePermissions);

      for (ResourcePermission permission : resourcePermissions) {
         for (ResourcePermission grantEquivalentPermission : resourcePermissions) {
            if (permission.isGrantableFrom(grantEquivalentPermission) && !permission.equals(grantEquivalentPermission)) {
               collapsedPermissions.remove(permission);
               break;
            }
         }
      }

      return collapsedPermissions;
   }

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getGlobalResourcePermissionsMap(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __getDirectGlobalResourcePermissionsMap(connection, accessorResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Map<String, Map<String, Set<ResourcePermission>>> __getDirectGlobalResourcePermissionsMap(SQLConnection connection,
                                                                                                     Resource accessorResource) {
      final Map<String, Map<String, Set<ResourcePermission>>> globalALLPermissionsMap = new HashMap<>();

      // collect the system permissions that the accessor has and add it into the globalALLPermissionsMap
      globalALLPermissionsMap
            .putAll(grantGlobalResourcePermissionSysPersister.getGlobalSysPermissions(connection, accessorResource));

      // next collect the non-system permissions that the accessor has and add it into the globalALLPermissionsMap
      __mergeSourcePermissionsMapIntoTargetPermissionsMap(grantGlobalResourcePermissionPersister
                                                                .getGlobalResourcePermissions(connection, accessorResource),
                                                          globalALLPermissionsMap);

      return __collapseResourcePermissions(globalALLPermissionsMap);
   }

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getEffectiveGlobalResourcePermissionsMap(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         return __getEffectiveGlobalResourcePermissionsMap(connection, accessorResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Map<String, Map<String, Set<ResourcePermission>>> __getEffectiveGlobalResourcePermissionsMap(SQLConnection connection,
                                                                                                        Resource accessorResource) {
      final Map<String, Map<String, Set<ResourcePermission>>> globalALLPermissionsMap = new HashMap<>();

      // collect the system permissions that the accessor has and add it into the globalALLPermissionsMap
      globalALLPermissionsMap
            .putAll(grantGlobalResourcePermissionSysPersister
                          .getGlobalSysPermissionsIncludeInherited(connection, accessorResource));

      // next collect the non-system permissions that the accessor has and add it into the globalALLPermissionsMap
      __mergeSourcePermissionsMapIntoTargetPermissionsMap(
            grantGlobalResourcePermissionPersister.getGlobalResourcePermissionsIncludeInherited(connection,
                                                                                                accessorResource),
            globalALLPermissionsMap);

      return __collapseResourcePermissions(globalALLPermissionsMap);
   }

   private void __mergeSourcePermissionsMapIntoTargetPermissionsMap(Map<String, Map<String, Set<ResourcePermission>>> sourcePermissionsMap,
                                                                    Map<String, Map<String, Set<ResourcePermission>>> targetPermissionsMap) {
      for (String domainName : sourcePermissionsMap.keySet()) {
         Map<String, Set<ResourcePermission>> targetPermsForDomainMap;
         // does the target map have domain?
         if ((targetPermsForDomainMap = targetPermissionsMap.get(domainName)) == null) {
            // no, add the domain
            targetPermissionsMap.put(domainName, targetPermsForDomainMap = new HashMap<>());
         }
         for (String resourceClassName : sourcePermissionsMap.get(domainName).keySet()) {
            Set<ResourcePermission> targetPermsForClassSet;
            // does the target map have the resource class?
            if ((targetPermsForClassSet = targetPermsForDomainMap.get(resourceClassName)) == null) {
               // no, add the resource class
               targetPermsForDomainMap.put(resourceClassName,
                                           targetPermsForClassSet = new HashSet<>());
            }
            // get the source permissions for the domain + resource class
            final Set<ResourcePermission> sourcePermissionsForClassSet
                  = sourcePermissionsMap.get(domainName).get(resourceClassName);
            // add the source permissions above to the target for the respective domain + resource class
            targetPermsForClassSet.addAll(sourcePermissionsForClassSet);
         }
      }
   }

   private Map<String, Map<String, Set<ResourcePermission>>> __collapseResourcePermissions(Map<String, Map<String, Set<ResourcePermission>>> resourcePermissionsMap) {
      for (String domainName : resourcePermissionsMap.keySet()) {
         final Map<String, Set<ResourcePermission>> createPermissionsByDomainMap = resourcePermissionsMap.get(domainName);

         for (String resourceClassName : createPermissionsByDomainMap.keySet()) {
            final Set<ResourcePermission> createPermissionsByResourceClassMap
                  = createPermissionsByDomainMap.get(resourceClassName);
            createPermissionsByDomainMap.put(resourceClassName,
                                             __collapseResourcePermissions(createPermissionsByResourceClassMap));
         }
      }

      return resourcePermissionsMap;
   }

   @Override
   public String getDomainNameByResource(Resource resource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(resource);

      try {
         connection = __getConnection();

         return domainPersister.getResourceDomainNameByResourceId(connection, resource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<String> getDomainDescendants(String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         domainName = domainName.trim();

         return domainPersister.getResourceDomainNameDescendants(connection, domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public ResourceClassInfo getResourceClassInfo(String resourceClassName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceClassSpecified(resourceClassName);

      try {
         connection = __getConnection();

         final ResourceClassInternalInfo resourceClassInternalInfo
               = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);

         if (resourceClassInternalInfo == null) {
            throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
         }

         return new ResourceClassInfo(resourceClassInternalInfo.getResourceClassName(),
                                      resourceClassInternalInfo.isAuthenticatable(),
                                      resourceClassInternalInfo.isUnauthenticatedCreateAllowed());
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public ResourceClassInfo getResourceClassInfoByResource(Resource resource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(resource);

      try {
         connection = __getConnection();

         final ResourceClassInternalInfo resourceClassInternalInfo
               = resourceClassPersister.getResourceClassInfoByResourceId(connection, resource);
         return new ResourceClassInfo(resourceClassInternalInfo.getResourceClassName(),
                                      resourceClassInternalInfo.isAuthenticatable(),
                                      resourceClassInternalInfo.isUnauthenticatedCreateAllowed());
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Resource getAuthenticatedResource() {
      __assertAuthenticated();

      return authenticatedResource;
   }

   @Override
   public Resource getSessionResource() {
      __assertAuthenticated();

      return sessionResource;
   }

   @Override
   public void assertPostCreateDomainPermission(Resource accessorResource,
                                                DomainPermission domainPermission) {

      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionSpecified(domainPermission);

      try {
         connection = __getConnection();
         __assertPostCreateDomainPermission(connection,
                                            accessorResource,
                                            domainPermission);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __assertPostCreateDomainPermission(SQLConnection connection,
                                                   Resource accessorResource,
                                                   DomainPermission requestedDomainPermission) {
      boolean createSysPermissionFound = false;
      final Set<DomainCreatePermission> effectiveDomainCreatePermissions
            = __getEffectiveDomainCreatePermissions(connection, accessorResource);

      for (DomainCreatePermission domainCreatePermission : effectiveDomainCreatePermissions) {
         if (domainCreatePermission.isSystemPermission()
               && DomainCreatePermissions.CREATE.equals(domainCreatePermission.getPermissionName())) {
            createSysPermissionFound = true;
            break;
         }
      }

      if (createSysPermissionFound) {
         // check if the requested permission is permissible from the set of effective post-create permissions
         final Set<DomainPermission> postCreateDomainPermissions
               = __getPostCreateDomainPermissions(effectiveDomainCreatePermissions);

         if (__isPermissible(requestedDomainPermission, postCreateDomainPermissions)) {
            return;
         }

         if (postCreateDomainPermissions.contains(DomainPermission_SUPER_USER)
               || postCreateDomainPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {
            return;
         }
      }

      // if none of the above then complain...
      if (createSysPermissionFound) {
         throw new NotAuthorizedException(accessorResource,
                                          "receive " + String.valueOf(requestedDomainPermission)
                                                + " permission after creating a domain");
      }
      else {
         throw new NotAuthorizedException(accessorResource, "create any domains");
      }
   }

   private boolean __isPermissible(DomainPermission queriedDomainPermission,
                                   Set<DomainPermission> domainPermissions) {
      for (DomainPermission domainPermission : domainPermissions) {
         if (queriedDomainPermission.equals(domainPermission)
               || queriedDomainPermission.isGrantableFrom(domainPermission)) {
            return true;
         }
      }
      return false;
   }

   @Override
   public void assertDomainPermission(Resource accessorResource,
                                      DomainPermission domainPermission,
                                      String domainName) {

      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionSpecified(domainPermission);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();

         if (!__hasPermission(connection, accessorResource, domainPermission, domainName)) {
            throw new NotAuthorizedException(accessorResource, domainPermission, domainName);
         }
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasPermission(SQLConnection connection,
                                   Resource accessorResource,
                                   DomainPermission requestedDomainPermission,
                                   String domainName) {
      // first check for effective permissions
      if (__isPermissible(requestedDomainPermission,
                          __getEffectiveDomainPermissions(connection, accessorResource, domainName))) {
         return true;
      }

      // next check super-user permissions to the domain of the accessed resource
      if (__isSuperUserOfDomain(connection, accessorResource, domainName)) {
         return true;
      }

      return false;
   }

   @Override
   public void assertPostCreateResourcePermission(Resource accessorResource,
                                                  String resourceClassName,
                                                  ResourcePermission requestedResourcePermission) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(requestedResourcePermission);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         __assertPostCreateResourcePermission(connection,
                                              accessorResource,
                                              resourceClassName,
                                              requestedResourcePermission,
                                              sessionResourceDomainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void assertPostCreateResourcePermission(Resource accessorResource,
                                                  String resourceClassName,
                                                  ResourcePermission resourcePermission,
                                                  String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __assertPostCreateResourcePermission(connection,
                                              accessorResource,
                                              resourceClassName,
                                              resourcePermission,
                                              domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __assertPostCreateResourcePermission(SQLConnection connection,
                                                     Resource accessorResource,
                                                     String resourceClassName,
                                                     ResourcePermission requestedResourcePermission,
                                                     String domainName) {
      __assertPermissionValid(connection, resourceClassName, requestedResourcePermission);

      boolean createSysPermissionFound = false;
      final Set<ResourceCreatePermission> effectiveResourceCreatePermissions
            = __getEffectiveResourceCreatePermissions(connection,
                                                      accessorResource,
                                                      resourceClassName,
                                                      domainName);

      for (ResourceCreatePermission resourceCreatePermission : effectiveResourceCreatePermissions) {
         if (resourceCreatePermission.isSystemPermission()
               && ResourceCreatePermissions.CREATE.equals(resourceCreatePermission.getPermissionName())) {
            createSysPermissionFound = true;
            break;
         }
      }

      if (createSysPermissionFound) {
         // check if the requested permission is permissible from the set of effective post-create permissions
         final Set<ResourcePermission> postCreateResourcePermissions
               = __getPostCreateResourcePermissions(effectiveResourceCreatePermissions);

         if (__isPermissible(requestedResourcePermission, postCreateResourcePermissions)) {
            return;
         }

         // check if the requested permission is permissible from the set of effective global permissions
         final Set<ResourcePermission> globalResourcePermissions
               = __getEffectiveGlobalResourcePermissions(connection,
                                                         accessorResource,
                                                         resourceClassName,
                                                         domainName);

         if (__isPermissible(requestedResourcePermission, globalResourcePermissions)) {
            return;
         }
      }

      if (__isSuperUserOfDomain(connection, accessorResource, domainName)) {
         return;
      }

      // if none of the above then complain...
      if (createSysPermissionFound) {
         throw new NotAuthorizedException(accessorResource,
                                          "receive " + String.valueOf(requestedResourcePermission)
                                                + " permission after creating a " + resourceClassName
                                                + " resource in domain " + domainName);
      }
      else {
         throw new NotAuthorizedException(accessorResource,
                                          "create any " + resourceClassName + " resources in domain " + domainName);
      }
   }

   private boolean __isPermissible(ResourcePermission queriedResourcePermission,
                                   Set<ResourcePermission> resourcePermissions) {
      for (ResourcePermission resourcePermission : resourcePermissions) {
         if (queriedResourcePermission.equals(resourcePermission)
               || queriedResourcePermission.isGrantableFrom(resourcePermission)) {
            return true;
         }
      }
      return false;
   }

   @Override
   public void assertGlobalResourcePermission(Resource accessorResource,
                                              String resourceClassName, 
                                              ResourcePermission requestedResourcePermission) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(requestedResourcePermission);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         __assertGlobalResourcePermission(connection,
                                          accessorResource,
                                          resourceClassName,
                                          requestedResourcePermission,
                                          sessionResourceDomainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void assertGlobalResourcePermission(Resource accessorResource,
                                              String resourceClassName,
                                              ResourcePermission requestedResourcePermission,
                                              String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(requestedResourcePermission);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __assertGlobalResourcePermission(connection,
                                          accessorResource,
                                          resourceClassName,
                                          requestedResourcePermission,
                                          domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __assertGlobalResourcePermission(SQLConnection connection,
                                                 Resource accessorResource,
                                                 String resourceClassName,
                                                 ResourcePermission requestedResourcePermission,
                                                 String domainName) {
      __assertPermissionValid(connection, resourceClassName, requestedResourcePermission);

      final Set<ResourcePermission>
            globalResourcePermissions = __getEffectiveGlobalResourcePermissions(connection,
                                                                                accessorResource,
                                                                                resourceClassName,
                                                                                domainName);

      if (__isPermissible(requestedResourcePermission, globalResourcePermissions)) {
         return;
      }

      if (__isSuperUserOfDomain(connection, accessorResource, domainName)) {
         return;
      }

      // if none of the above then complain...
      throw new NotAuthorizedException(accessorResource, requestedResourcePermission, resourceClassName, domainName);
   }

   @Override
   public void assertResourcePermission(Resource accessorResource,
                                        Resource accessedResource,
                                        ResourcePermission requestedResourcePermission) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionSpecified(requestedResourcePermission);

      try {
         connection = __getConnection();

         resourcePersister.verifyResourceExists(connection, accessorResource);

         final ResourceClassInternalInfo resourceClassInternalInfo
               = resourceClassPersister.getResourceClassInfoByResourceId(connection, accessedResource);
         __assertPermissionValid(connection, resourceClassInternalInfo.getResourceClassName(), requestedResourcePermission);

         if (!__hasPermission(connection, accessorResource, accessedResource, requestedResourcePermission)) {
            throw new NotAuthorizedException(accessorResource, requestedResourcePermission, accessedResource);
         }
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasPermission(SQLConnection connection,
                                   Resource accessorResource,
                                   Resource accessedResource,
                                   ResourcePermission requestedResourcePermission) {
      // first check for effective permissions
      if (__isPermissible(requestedResourcePermission,
                          __getEffectiveResourcePermissions(connection, accessorResource, accessedResource))) {
         return true;
      }

      // next check super-user permissions to the domain of the accessed resource
      final String domainName
            = domainPersister.getResourceDomainNameByResourceId(connection, accessedResource);

      if (__isSuperUserOfDomain(connection, accessorResource, domainName)) {
         return true;
      }

      return false;
   }

   private boolean __hasAnyPermissions(SQLConnection connection,
                                       Resource accessorResource,
                                       Resource accessedResource,
                                       Set<ResourcePermission> requestedResourcePermissions) {
      // first check for effective permissions
      final Set<ResourcePermission> effectiveResourcePermissions
            = __getEffectiveResourcePermissions(connection, accessorResource, accessedResource);

      for (ResourcePermission requestedResourcePermission : requestedResourcePermissions) {
         if (__isPermissible(requestedResourcePermission, effectiveResourcePermissions)) {
            return true;
         }
      }

      // next check for super-user permissions to the domain of the accessed resource
      final String domainName
            = domainPersister.getResourceDomainNameByResourceId(connection, accessedResource);

      if (__isSuperUserOfDomain(connection, accessorResource, domainName)) {
         return true;
      }

      return false;
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(String resourceClassName,
                                                         ResourcePermission resourcePermission) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();

         return __getResourcesByPermission(connection, sessionResource, resourceClassName, resourcePermission);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();

         Set<ResourcePermission> anyRequiredResourcePermissions = new HashSet<>(3);
         anyRequiredResourcePermissions.add(ResourcePermission_IMPERSONATE);
         anyRequiredResourcePermissions.add(ResourcePermission_INHERIT);
         anyRequiredResourcePermissions.add(ResourcePermission_RESET_CREDENTIALS);

         if ( sessionResource.equals(accessorResource)
               || __hasAnyPermissions(connection,
                                      sessionResource,
                                      accessorResource,
                                      anyRequiredResourcePermissions)) {
            return __getResourcesByPermission(connection, accessorResource, resourceClassName, resourcePermission);
         }
         else {
            throw new NotAuthorizedException(sessionResource, "retrieve resources by permission for", accessorResource);
         }
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<Resource> __getResourcesByPermission(SQLConnection connection,
                                                    Resource accessorResource,
                                                    String resourceClassName,
                                                    ResourcePermission resourcePermission) {
      // first verify that resource class is defined
      Id<ResourceClassId> resourceClassId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      Set<Resource> resources = new HashSet<>();

      if (resourcePermission.isSystemPermission()) {
         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionSysPersister.getResourcesByResourceSysPermission(connection,
                                                                                                  accessorResource,
                                                                                                  resourceClassId,
                                                                                                  resourcePermission));

         // get the list of objects of the specified type that the session has access to via global permissions
         resources.addAll(grantGlobalResourcePermissionSysPersister.getResourcesByGlobalSysPermission(connection,
                                                                                                      accessorResource,
                                                                                                      resourceClassId,
                                                                                                      resourcePermission));
      }
      else {
         // check if the non-system permission name is valid
         permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection, resourceClassId, resourcePermission.getPermissionName());

         if (permissionId == null) {
            throw new IllegalArgumentException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }

         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionPersister.getResourcesByResourcePermission(connection,
                                                                                            accessorResource,
                                                                                            resourceClassId,
                                                                                            resourcePermission,
                                                                                            permissionId));

         // get the list of objects of the specified type that the session has access to via global permissions
         resources.addAll(grantGlobalResourcePermissionPersister
                                .getResourcesByGlobalResourcePermission(connection,
                                                                        accessorResource,
                                                                        resourceClassId,
                                                                        resourcePermission,
                                                                        permissionId));
      }

      // finally get the list of objects of the specified type that the session has access to via super user permissions
      resources.addAll(grantDomainPermissionSysPersister.getResourcesByDomainSuperUserPermission(connection,
                                                                                                 accessorResource,
                                                                                                 resourceClassId));
      return resources;
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(String resourceClassName,
                                                         ResourcePermission resourcePermission,
                                                         String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();

         return __getResourcesByPermission(connection,
                                           sessionResource,
                                           resourceClassName,
                                           resourcePermission,
                                           domainName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission,
                                                         String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();
         Set<ResourcePermission> anyRequiredResourcePermissions = new HashSet<>(3);
         anyRequiredResourcePermissions.add(ResourcePermission_IMPERSONATE);
         anyRequiredResourcePermissions.add(ResourcePermission_INHERIT);
         anyRequiredResourcePermissions.add(ResourcePermission_RESET_CREDENTIALS);

         if ( sessionResource.equals(accessorResource)
               || __hasAnyPermissions(connection,
                                      sessionResource,
                                      accessorResource,
                                      anyRequiredResourcePermissions)) {
            return __getResourcesByPermission(connection,
                                              accessorResource,
                                              resourceClassName,
                                              resourcePermission,
                                              domainName
            );
         }
         else {
            throw new NotAuthorizedException(sessionResource, "retrieve resources by permission for", accessorResource);
         }
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<Resource> __getResourcesByPermission(SQLConnection connection,
                                                    Resource accessorResource,
                                                    String resourceClassName,
                                                    ResourcePermission resourcePermission,
                                                    String domainName) {
      // first verify that resource class and domain is defined
      Id<ResourceClassId> resourceClassId;
      Id<DomainId> domainId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }


      Set<Resource> resources = new HashSet<>();

      if (resourcePermission.isSystemPermission()) {
         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionSysPersister.getResourcesByResourceSysPermission(connection,
                                                                                                  accessorResource,
                                                                                                  resourceClassId,
                                                                                                  domainId,
                                                                                                  resourcePermission));

         // get the list of objects of the specified type that the session has access to via global permissions
         resources.addAll(grantGlobalResourcePermissionSysPersister.getResourcesByGlobalSysPermission(connection,
                                                                                                      accessorResource,
                                                                                                      resourceClassId,
                                                                                                      domainId,
                                                                                                      resourcePermission));
      }
      else {
         // check if the non-system permission name is valid
         permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection,
                                                                                      resourceClassId,
                                                                                      resourcePermission.getPermissionName());

         if (permissionId == null) {
            throw new IllegalArgumentException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }

         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionPersister.getResourcesByResourcePermission(connection,
                                                                                            accessorResource,
                                                                                            resourceClassId,
                                                                                            domainId,
                                                                                            resourcePermission,
                                                                                            permissionId));

         // get the list of objects of the specified type that the session has access to via global permissions
         resources.addAll(grantGlobalResourcePermissionPersister
                                .getResourcesByGlobalResourcePermission(connection,
                                                                        accessorResource,
                                                                        resourceClassId,
                                                                        domainId,
                                                                        resourcePermission,
                                                                        permissionId));
      }

      // finally get the list of objects of the specified type that the session has access to via super user permissions
      resources.addAll(grantDomainPermissionSysPersister.getResourcesByDomainSuperUserPermission(connection,
                                                                                                 accessorResource,
                                                                                                 resourceClassId,
                                                                                                 domainId));
      return resources;
   }

   @Override
   public Set<Resource> getAccessorResourcesByResourcePermission(Resource accessedResource,
                                                                 String resourceClassName,
                                                                 ResourcePermission resourcePermission) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessedResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         return __getAccessorResourcesByResourcePermission(connection, accessedResource, resourceClassName, resourcePermission);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<Resource> __getAccessorResourcesByResourcePermission(SQLConnection connection,
                                                                    Resource accessedResource,
                                                                    String resourceClassName,
                                                                    ResourcePermission resourcePermission) {
      // first verify that resource class is defined
      Id<ResourceClassId> resourceClassId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      Set<Resource> resources = new HashSet<>();

      if (resourcePermission.isSystemPermission()) {
         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionSysPersister.getAccessorResourcesByResourceSysPermission(connection,
                                                                                                          accessedResource,
                                                                                                          resourceClassId,
                                                                                                          resourcePermission));
      }
      else {
         // check if the non-system permission name is valid
         permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection, resourceClassId, resourcePermission.getPermissionName());

         if (permissionId == null) {
            throw new IllegalArgumentException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }

         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionPersister.getAccessorResourcesByResourcePermission(connection,
                                                                                                    accessedResource,
                                                                                                    resourceClassId,
                                                                                                    resourcePermission,
                                                                                                    permissionId));
      }

      return resources;
   }

   @Override
   public List<String> getResourceClassNames() {
      SQLConnection connection = null;

      __assertAuthenticated();

      try {
         connection = __getConnection();

         return resourceClassPersister.getResourceClassNames(connection);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public List<String> getResourcePermissionNames(String resourceClassName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceClassSpecified(resourceClassName);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();

         return resourceClassPermissionPersister.getPermissionNames(connection, resourceClassName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   // private shared helper methods

   private boolean __isSuperUserOfResource(SQLConnection connection,
                                           Resource accessorResource,
                                           Resource accessedResource) {
      return __isSuperUserOfDomain(connection,
                                   accessorResource,
                                   domainPersister.getResourceDomainNameByResourceId(connection, accessedResource));
   }


   private boolean __isSuperUserOfDomain(SQLConnection connection,
                                         Resource accessorResource,
                                         String queriedDomain) {
      Set<DomainPermission> domainPermissions = __getEffectiveDomainPermissions(connection, accessorResource, queriedDomain);

      return domainPermissions.contains(DomainPermission_SUPER_USER)
            || domainPermissions.contains(DomainPermission_SUPER_USER_GRANT);
   }

   private Set<DomainPermission> __getPostCreateDomainPermissions(Set<DomainCreatePermission> domainCreatePermissions) {
      Set<DomainPermission> domainPermissions = new HashSet<>();

      for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
         if (!domainCreatePermission.isSystemPermission()) {
            domainPermissions.add(domainCreatePermission.getPostCreateDomainPermission());
         }
      }
      return domainPermissions;
   }

   private Set<ResourcePermission> __getPostCreateResourcePermissions(Set<ResourceCreatePermission> resourceCreatePermissions) {
      Set<ResourcePermission> resourcePermissions = new HashSet<>();

      for (ResourceCreatePermission resourceCreatePermission : resourceCreatePermissions) {
         if (!resourceCreatePermission.isSystemPermission()) {
            resourcePermissions.add(resourceCreatePermission.getPostCreateResourcePermission());
         }
      }
      return resourcePermissions;
   }

   // helper methods

   private void __assertResourceSpecified(Resource resource) {
      if (resource == null) {
         throw new NullPointerException("Resource required, none specified");
      }
   }

   private void __assertCredentialsSpecified(Credentials credentials) {
      if (credentials == null) {
         throw new NullPointerException("Credentials required, none specified");
      }
   }

   private void __assertCredentialsNotSpecified(Credentials credentials) {
      if (credentials != null) {
         throw new IllegalArgumentException("Credentials not supported, but specified for unauthenticatable resource class");
      }
   }

   private void __assertDomainSpecified(String domainName) {
      if (domainName == null) {
         throw new NullPointerException("Domain required, none specified");
      }
      else if (domainName.trim().isEmpty()) {
         throw new IllegalArgumentException("Domain required, none specified");
      }
   }

   private void __assertParentDomainSpecified(String domainName) {
      if (domainName == null) {
         throw new NullPointerException("Parent domain required, none specified");
      }
      else if (domainName.trim().isEmpty()) {
         throw new IllegalArgumentException("Parent domain required, none specified");
      }
   }

   private void __assertAuthenticatedAsSystemResource() {
      if (sessionResource == null || sessionResource.getId() != SYSTEM_RESOURCE_ID) {
         throw new NotAuthorizedException(sessionResource, "perform operation reserved for the system resource");
      }
   }

   private void __assertAuthenticated() {
      if (sessionResource == null) {
         throw new NotAuthenticatedException("Session not authenticated");
      }
   }

   private void __assertResourceClassSpecified(String resourceClassName) {
      if (resourceClassName == null) {
         throw new NullPointerException("Resource class required, none specified");
      }
      else if (resourceClassName.trim().isEmpty()) {
         throw new IllegalArgumentException("Resource class required, none specified");
      }
   }

   private void __assertPermissionSpecified(ResourcePermission resourcePermission) {
      if (resourcePermission == null) {
         throw new NullPointerException("Resource permission required, none specified");
      }
   }

   private void __assertPermissionSpecified(DomainPermission domainPermission) {
      if (domainPermission == null) {
         throw new NullPointerException("Domain permission required, none specified");
      }
   }

   private void __assertPermissionsSpecified(Set permissionSet) {
      if (permissionSet == null) {
         throw new NullPointerException("Set of permissions required, none specified");
      }

      if (permissionSet.contains(null)) {
         throw new NullPointerException("Set of permissions contains null element");
      }
   }

   private void __assertPermissionNameValid(String permissionName) {
      if (permissionName == null) {
         throw new NullPointerException("Permission name may not be null");
      }
      else if (permissionName.trim().isEmpty()) {
         throw new IllegalArgumentException("Permission name may not be blank");
      }

      if (permissionName.trim().startsWith("*")) {
         throw new IllegalArgumentException("Permission name may not start with asterisk '*'");
      }
   }

   private void __assertResourceClassNameValid(String resourceClassName) {
      if (resourceClassName == null) {
         throw new NullPointerException("Resource class name may not be null");
      }
      else if (resourceClassName.trim().isEmpty()) {
         throw new IllegalArgumentException("Resource class name may not be blank");
      }
   }

   private void __assertPermissionValid(SQLConnection connection,
                                        String resourceClassName,
                                        ResourcePermission resourcePermission) {
      if (!resourcePermission.isSystemPermission()) {
         final List<String> permissionNames
               = resourceClassPermissionPersister.getPermissionNames(connection, resourceClassName);
         if (!permissionNames.contains(resourcePermission.getPermissionName())) {
            throw new IllegalArgumentException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }
      }
   }

   // private connection management helper methods

   private SQLConnection __getConnection() {
      if (dataSource != null) {
         try {
            return new SQLConnection(dataSource.getConnection());
         }
         catch (SQLException e) {
            throw new RuntimeException(e);
         }
      }
      else if (connection != null) {
         return new SQLConnection(connection);
      }
      else {
         throw new IllegalStateException("Not initialized! No data source or connection, perhaps missing call to postDeserialize()?");
      }
   }

   private void __closeConnection(SQLConnection connection) {
      // only close the connection if we got it from a pool, otherwise just leave the connection open
      if (dataSource != null) {
         if (connection != null) {
            try {
               connection.close();
            }
            catch (SQLException e) {
               throw new RuntimeException(e);
            }
         }
      }
   }
}