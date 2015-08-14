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
import com.acciente.oacc.sql.SQLType;
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
import com.acciente.oacc.sql.internal.persister.NonRecursiveDomainPersister;
import com.acciente.oacc.sql.internal.persister.NonRecursiveGrantDomainCreatePermissionPostCreateSysPersister;
import com.acciente.oacc.sql.internal.persister.NonRecursiveGrantDomainCreatePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.NonRecursiveGrantDomainPermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.NonRecursiveGrantResourceCreatePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.NonRecursiveGrantResourcePermissionPersister;
import com.acciente.oacc.sql.internal.persister.NonRecursiveResourcePersister;
import com.acciente.oacc.sql.internal.persister.RecursiveDomainPersister;
import com.acciente.oacc.sql.internal.persister.RecursiveGrantDomainCreatePermissionPostCreateSysPersister;
import com.acciente.oacc.sql.internal.persister.RecursiveGrantDomainCreatePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.RecursiveGrantDomainPermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.RecursiveGrantResourceCreatePermissionSysPersister;
import com.acciente.oacc.sql.internal.persister.RecursiveGrantResourcePermissionPersister;
import com.acciente.oacc.sql.internal.persister.RecursiveResourcePersister;
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
import java.util.Arrays;
import java.util.Collections;
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
   private static final DomainPermission DomainPermission_DELETE
         = DomainPermissions.getInstance(DomainPermissions.DELETE, false);
   private static final DomainPermission DomainPermission_DELETE_GRANT
         = DomainPermissions.getInstance(DomainPermissions.DELETE, true);
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
   private static final ResourcePermission ResourcePermission_DELETE
         = ResourcePermissions.getInstance(ResourcePermissions.DELETE, false);
   private static final ResourcePermission ResourcePermission_DELETE_GRANT
         = ResourcePermissions.getInstance(ResourcePermissions.DELETE, true);
   private static final ResourcePermission ResourcePermission_QUERY
         = ResourcePermissions.getInstance(ResourcePermissions.QUERY, false);
   private static final ResourcePermission ResourcePermission_QUERY_GRANT
         = ResourcePermissions.getInstance(ResourcePermissions.QUERY, true);

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
                                                              SQLType sqlType) {
      return new SQLAccessControlContext(connection, schemaName, sqlType);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLType sqlType) {
      return new SQLAccessControlContext(dataSource, schemaName, sqlType);
   }

   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLType sqlType,
                                                              AuthenticationProvider authenticationProvider) {
      return new SQLAccessControlContext(connection, schemaName, sqlType, authenticationProvider);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLType sqlType,
                                                              AuthenticationProvider authenticationProvider) {
      return new SQLAccessControlContext(dataSource, schemaName, sqlType, authenticationProvider);
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
                                   SQLType sqlType) {
      this(schemaName, sqlType);
      this.connection = connection;
      // use the built-in authentication provider when no custom implementation is provided
      this.authenticationProvider
            = new SQLPasswordAuthenticationProvider(connection, schemaName, sqlType.getSqlDialect());
      this.hasDefaultAuthenticationProvider = true;
   }

   private SQLAccessControlContext(Connection connection,
                                   String schemaName,
                                   SQLType sqlType,
                                   AuthenticationProvider authenticationProvider) {
      this(schemaName, sqlType);
      this.connection = connection;
      this.authenticationProvider = authenticationProvider;
      this.hasDefaultAuthenticationProvider = false;
   }

   private SQLAccessControlContext(DataSource dataSource,
                                   String schemaName,
                                   SQLType sqlType) {
      this(schemaName, sqlType);
      this.dataSource = dataSource;
      // use the built-in authentication provider when no custom implementation is provided
      this.authenticationProvider
            = new SQLPasswordAuthenticationProvider(dataSource, schemaName, sqlType.getSqlDialect());
      this.hasDefaultAuthenticationProvider = true;
   }

   private SQLAccessControlContext(DataSource dataSource,
                                   String schemaName,
                                   SQLType sqlType,
                                   AuthenticationProvider authenticationProvider) {
      this(schemaName, sqlType);
      this.dataSource = dataSource;
      this.authenticationProvider = authenticationProvider;
      this.hasDefaultAuthenticationProvider = false;
   }

   private SQLAccessControlContext(String schemaName,
                                   SQLType sqlType) {
      // generate all the SQLs the persisters need based on the database dialect
      SQLStrings sqlStrings = SQLStrings.getSQLStrings(schemaName, sqlType.getSqlDialect());

      // setup persisters
      resourceClassPersister
            = new ResourceClassPersister(sqlStrings);
      resourceClassPermissionPersister
            = new ResourceClassPermissionPersister(sqlStrings);

      if (sqlType.isRecursionCompatible()) {
         grantDomainCreatePermissionSysPersister
               = new RecursiveGrantDomainCreatePermissionSysPersister(sqlStrings);
         grantDomainCreatePermissionPostCreateSysPersister
               = new RecursiveGrantDomainCreatePermissionPostCreateSysPersister(sqlStrings);
         grantDomainPermissionSysPersister
               = new RecursiveGrantDomainPermissionSysPersister(sqlStrings);
         domainPersister
               = new RecursiveDomainPersister(sqlStrings);
         resourcePersister
               = new RecursiveResourcePersister(sqlStrings);
         grantResourceCreatePermissionSysPersister
               = new RecursiveGrantResourceCreatePermissionSysPersister(sqlStrings);
         grantResourceCreatePermissionPostCreateSysPersister
               = new GrantResourceCreatePermissionPostCreateSysPersister(sqlStrings);
         grantResourceCreatePermissionPostCreatePersister
               = new GrantResourceCreatePermissionPostCreatePersister(sqlStrings);
         grantResourcePermissionSysPersister
               = new GrantResourcePermissionSysPersister(sqlStrings);
         grantGlobalResourcePermissionSysPersister
               = new GrantGlobalResourcePermissionSysPersister(sqlStrings);
         grantResourcePermissionPersister
               = new RecursiveGrantResourcePermissionPersister(sqlStrings);
         grantGlobalResourcePermissionPersister
               = new GrantGlobalResourcePermissionPersister(sqlStrings);
      }
      else {
         grantDomainCreatePermissionSysPersister
               = new NonRecursiveGrantDomainCreatePermissionSysPersister(sqlStrings);
         grantDomainCreatePermissionPostCreateSysPersister
               = new NonRecursiveGrantDomainCreatePermissionPostCreateSysPersister(sqlStrings);
         grantDomainPermissionSysPersister
               = new NonRecursiveGrantDomainPermissionSysPersister(sqlStrings);
         domainPersister
               = new NonRecursiveDomainPersister(sqlStrings);
         resourcePersister
               = new NonRecursiveResourcePersister(sqlStrings);
         grantResourceCreatePermissionSysPersister
               = new NonRecursiveGrantResourceCreatePermissionSysPersister(sqlStrings);
         grantResourceCreatePermissionPostCreateSysPersister
               = new GrantResourceCreatePermissionPostCreateSysPersister(sqlStrings);
         grantResourceCreatePermissionPostCreatePersister
               = new GrantResourceCreatePermissionPostCreatePersister(sqlStrings);
         grantResourcePermissionSysPersister
               = new GrantResourcePermissionSysPersister(sqlStrings);
         grantGlobalResourcePermissionSysPersister
               = new GrantGlobalResourcePermissionSysPersister(sqlStrings);
         grantResourcePermissionPersister
               = new NonRecursiveGrantResourcePermissionPersister(sqlStrings);
         grantGlobalResourcePermissionPersister
               = new GrantGlobalResourcePermissionPersister(sqlStrings);
      }
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
      __assertResourceExists(connection, resource);

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
         throw NotAuthorizedException.newInstanceForActionOnResource(authenticatedResource, "impersonate", resource);
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
         throw NotAuthorizedException.newInstanceForActionOnResource(authenticatedResource,
                                                                     "reset credentials",
                                                                     resource);
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

         resourceClassPersister.addResourceClass(connection,
                                                 resourceClassName,
                                                 authenticatable,
                                                 unauthenticatedCreateAllowed);
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
         throw NotAuthorizedException.newInstanceForAction(sessionResource, "create domain");
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
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "create child domain in domain: " + parentDomainName);
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
   public boolean deleteDomain(String domainName) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertDomainSpecified(domainName);

      try {
         connection = __getConnection();

         return __deleteDomain(connection, domainName);
      }
      finally {
         __closeConnection(connection);
      }

   }

   private boolean __deleteDomain(SQLConnection connection, String domainName) {
      // short-circuit out of this call if the specified resource does not exist
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);
      if (domainId == null) {
         return false;
      }

      // check for authorization (using internal has-permission method is ok because querying for session resource)
      if (!__hasDomainPermissions(connection,
                                  sessionResource,
                                  domainName,
                                  Collections.singleton(DomainPermission_DELETE))) {
         throw NotAuthorizedException.newInstanceForDomainPermissions(sessionResource,
                                                                      domainName,
                                                                      DomainPermission_DELETE);
      }

      // check if the domain is empty (=domain must not contain any resources, and none in any descendant domains)
      if (!resourcePersister.isDomainEmpty(connection, domainId)) {
         throw new IllegalArgumentException("Deleting a domain ("
                                                  + domainName
                                                  + ") that contains resources directly or in a descendant domain is invalid");
      }

      // remove any permissions the obsolete resource has as an accessor resource
      grantDomainPermissionSysPersister.removeAllDomainSysPermissions(connection, domainId);
      grantResourceCreatePermissionPostCreatePersister.removeAllResourceCreatePostCreatePermissions(connection, domainId);
      grantResourceCreatePermissionPostCreateSysPersister.removeAllResourceCreatePostCreateSysPermissions(connection, domainId);
      grantResourceCreatePermissionSysPersister.removeAllResourceCreateSysPermissions(connection, domainId);
      grantGlobalResourcePermissionPersister.removeAllGlobalResourcePermissions(connection, domainId);
      grantGlobalResourcePermissionSysPersister.removeAllGlobalSysPermissions(connection, domainId);

      // remove the domain
      domainPersister.deleteDomain(connection, domainId);

      return true;
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
      final ResourceClassInternalInfo resourceClassInternalInfo = __getResourceClassInternalInfo(connection,
                                                                                                 resourceClassName);

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

         newResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.DELETE, true));
         newResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.QUERY, true));

         if (resourceClassInternalInfo.isAuthenticatable()) {
            newResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.RESET_CREDENTIALS, true));
            newResourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE, true));
         }
      }
      else {
         final Set<ResourceCreatePermission> resourceCreatePermissions;
         boolean createPermissionOK = false;

         resourceCreatePermissions = __getEffectiveResourceCreatePermissionsIgnoringSuperUserPrivileges(connection,
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
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "create resource of resource class " + resourceClassName);
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
   public boolean deleteResource(Resource obsoleteResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(obsoleteResource);

      try {
         connection = __getConnection();

         return __deleteResource(connection, obsoleteResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __deleteResource(SQLConnection connection,
                                    Resource obsoleteResource) {
      // short-circuit out of this call if the specified resource does not exist
      try {
         resourcePersister.verifyResourceExists(connection, obsoleteResource);
      }
      catch (IllegalArgumentException e) {
         if (e.getMessage().toLowerCase().contains("not found")) {
            return false;
         }
         throw e;
      }

      // check for authorization
      if (!__isSuperUserOfResource(connection, sessionResource, obsoleteResource)) {
         final Set<ResourcePermission> sessionResourcePermissions
               = __getEffectiveResourcePermissionsIgnoringSuperUserPrivileges(connection,
                                                                              sessionResource,
                                                                              obsoleteResource);

         if (!sessionResourcePermissions.contains(ResourcePermission_DELETE) &&
               !sessionResourcePermissions.contains(ResourcePermission_DELETE_GRANT)) {
            throw NotAuthorizedException.newInstanceForActionOnResource(sessionResource, "delete", obsoleteResource);
         }
      }

      // remove the resource's credentials, if necessary
      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfoByResourceId(connection, obsoleteResource);

      if (resourceClassInternalInfo.isAuthenticatable()) {
         authenticationProvider.deleteCredentials(obsoleteResource);
      }

      // remove any permissions the obsolete resource has as an accessor resource
      grantDomainCreatePermissionPostCreateSysPersister.removeDomainCreatePostCreateSysPermissions(connection, obsoleteResource);
      grantDomainCreatePermissionSysPersister.removeDomainCreateSysPermissions(connection, obsoleteResource);
      grantDomainPermissionSysPersister.removeAllDomainSysPermissions(connection, obsoleteResource);
      grantResourceCreatePermissionPostCreatePersister.removeAllResourceCreatePostCreatePermissions(connection, obsoleteResource);
      grantResourceCreatePermissionPostCreateSysPersister.removeAllResourceCreatePostCreateSysPermissions(connection, obsoleteResource);
      grantResourceCreatePermissionSysPersister.removeAllResourceCreateSysPermissions(connection, obsoleteResource);
      grantGlobalResourcePermissionPersister.removeAllGlobalResourcePermissions(connection, obsoleteResource);
      grantGlobalResourcePermissionSysPersister.removeAllGlobalSysPermissions(connection, obsoleteResource);

      // remove any permissions the obsolete resource has as an accessor resource OR as an accessed resource
      grantResourcePermissionPersister.removeAllResourcePermissionsAsAccessorOrAccessed(connection, obsoleteResource);
      grantResourcePermissionSysPersister.removeAllResourceSysPermissionsAsAccessorOrAccessed(connection, obsoleteResource);

      // remove the resource
      resourcePersister.deleteResource(connection, obsoleteResource);

      // handle special case where deleted resource is the session or authenticated resource
      if (authenticatedResource.equals(obsoleteResource)) {
         unauthenticate();
      }
      else if (sessionResource.equals(obsoleteResource)) {
         unimpersonate();
      }

      return true;
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
         __assertResourceExists(connection, accessorResource);

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
                  throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
                  throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
   public void grantDomainPermissions(Resource accessorResource,
                                      String domainName,
                                      Set<DomainPermission> domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(domainPermissions);
      __assertPermissionsSetNotEmpty(domainPermissions);

      try {
         connection = __getConnection();

         __grantDirectDomainPermissions(connection, accessorResource, domainName, domainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void grantDomainPermissions(Resource accessorResource,
                                      String domainName,
                                      DomainPermission domainPermission,
                                      DomainPermission... domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(domainPermission);
      __assertVarargPermissionsSpecified(domainPermissions);

      final Set<DomainPermission> requestedDomainPermissions = __getSetWithoutNullsOrDuplicates(domainPermission,
                                                                                                domainPermissions);

      try {
         connection = __getConnection();

         __grantDirectDomainPermissions(connection, accessorResource, domainName, requestedDomainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __grantDirectDomainPermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               String domainName,
                                               Set<DomainPermission> requestedDomainPermissions) {
      __assertUniqueDomainPermissionsNames(requestedDomainPermissions);

      // determine the domain ID of the domain, for use in the grant below
      Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // validate requested set is not null; empty set is valid and would remove any direct domain permissions
      if (requestedDomainPermissions == null) {
         throw new IllegalArgumentException("Set of requested domain permissions may not be null");
      }

      __assertResourceExists(connection, accessorResource);

      // check if the grantor (=session resource) has permissions to grant the requested permissions
      final Set<DomainPermission>
            grantorPermissions
            = __getEffectiveDomainPermissions(connection,
                                              sessionResource,
                                              domainName);

      // check if the grantor (=session resource) has super user permissions to the target domain
      if (!grantorPermissions.contains(DomainPermission_SUPER_USER)
            && !grantorPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {

         final Set<DomainPermission> unauthorizedPermissions
               = __subtractDomainPermissionsIfGrantableFrom(requestedDomainPermissions, grantorPermissions);

         if (unauthorizedPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "grant the following domain permission(s): " + unauthorizedPermissions);
         }
      }

      final Set<DomainPermission> directAccessorPermissions
            = __getDirectDomainPermissions(connection, accessorResource, domainId);

      final Set<DomainPermission> addPermissions = new HashSet<>(requestedDomainPermissions.size());
      final Set<DomainPermission> updatePermissions = new HashSet<>(requestedDomainPermissions.size());

      for (DomainPermission requestedPermission : requestedDomainPermissions) {
         boolean existingPermission = false;

         for (DomainPermission existingDirectPermission : directAccessorPermissions) {
            if (requestedPermission.equalsIgnoreGrant(existingDirectPermission)) {
               // we found a match by permission name - now let's see if we need to update existing or leave it unchanged
               if (!requestedPermission.equals(existingDirectPermission) &&
                     !requestedPermission.isGrantableFrom(existingDirectPermission)) {
                  // requested permission has higher granting rights than the already existing direct permission,
                  // so we need to update it
                  updatePermissions.add(requestedPermission);
               }

               existingPermission = true;
               break;
            }
         }

         if (!existingPermission) {
            // couldn't find requested permission in set of already existing direct permissions, by name, so we need to add it
            addPermissions.add(requestedPermission);
         }
      }

      // update any existing permissions that accessor to has to this domain directly
      grantDomainPermissionSysPersister.updateDomainSysPermissions(connection,
                                                                   accessorResource,
                                                                   sessionResource,
                                                                   domainId,
                                                                   updatePermissions);

      // add the new permissions
      grantDomainPermissionSysPersister.addDomainSysPermissions(connection,
                                                                accessorResource,
                                                                sessionResource,
                                                                domainId,
                                                                addPermissions);
   }

   private void __assertUniqueDomainPermissionsNames(Set<DomainPermission> domainPermissions) {
      final Set<String> uniquePermissionNames = new HashSet<>(domainPermissions.size());

      for (final DomainPermission domainPermissionPermission : domainPermissions) {
         if (uniquePermissionNames.contains(domainPermissionPermission.getPermissionName())) {
            throw new IllegalArgumentException("Duplicate permission: " + domainPermissionPermission.getPermissionName()
                                                     + " that only differs in 'withGrant' option");
         }
         else {
            uniquePermissionNames.add(domainPermissionPermission.getPermissionName());
         }
      }
   }

   @Override
   public void revokeDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       Set<DomainPermission> domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(domainPermissions);
      __assertPermissionsSetNotEmpty(domainPermissions);

      try {
         connection = __getConnection();

         __revokeDirectDomainPermissions(connection, accessorResource, domainName, domainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void revokeDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(domainPermission);
      __assertVarargPermissionsSpecified(domainPermissions);

      final Set<DomainPermission> requestedDomainPermissions = __getSetWithoutNullsOrDuplicates(domainPermission,
                                                                                                domainPermissions);

      try {
         connection = __getConnection();

         __revokeDirectDomainPermissions(connection, accessorResource, domainName, requestedDomainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __revokeDirectDomainPermissions(SQLConnection connection,
                                                Resource accessorResource,
                                                String domainName,
                                                Set<DomainPermission> requestedDomainPermissions) {
      __assertUniqueDomainPermissionsNames(requestedDomainPermissions);

      // determine the domain ID of the domain, for use in the revocation below
      Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // validate requested set is not null
      if (requestedDomainPermissions == null) {
         throw new IllegalArgumentException("Set of requested domain permissions to be revoked may not be null");
      }

      __assertResourceExists(connection, accessorResource);

      final Set<DomainPermission>
            grantorPermissions
            = __getEffectiveDomainPermissions(connection,
                                              sessionResource,
                                              domainName);

      // check if the grantor (=session resource) has super user permissions to the target domain or
      // has permissions to grant the requested permissions
      if (!grantorPermissions.contains(DomainPermission_SUPER_USER)
            && !grantorPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {

         final Set<DomainPermission> unauthorizedPermissions
               = __subtractDomainPermissionsIfGrantableFrom(requestedDomainPermissions, grantorPermissions);

         if (unauthorizedPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "revoke the following domain permission(s): " + unauthorizedPermissions);
         }
      }

      final Set<DomainPermission> directAccessorPermissions
            = __getDirectDomainPermissions(connection, accessorResource, domainId);

      final Set<DomainPermission> removePermissions = new HashSet<>(requestedDomainPermissions.size());

      for (DomainPermission requestedPermission : requestedDomainPermissions) {
         for (DomainPermission existingDirectPermission : directAccessorPermissions) {
            if (requestedPermission.equalsIgnoreGrant(existingDirectPermission)) {
               // requested permission has same name and regardless of granting rights we need to remove it
               removePermissions.add(requestedPermission);
               break;
            }
         }
      }

      // remove any existing permissions that accessor has to this domain directly
      grantDomainPermissionSysPersister.removeDomainSysPermissions(connection,
                                                                   accessorResource,
                                                                   domainId,
                                                                   removePermissions);
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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

      return __getEffectiveDomainPermissions(connection, accessorResource, domainId);
   }

   private Set<DomainPermission> __getEffectiveDomainPermissions(SQLConnection connection,
                                                                 Resource accessorResource,
                                                                 Id<DomainId> domainId) {
      // only system permissions are possible on a domain
      final Set<DomainPermission> domainSysPermissionsIncludingInherited
            = grantDomainPermissionSysPersister.getDomainSysPermissionsIncludeInherited(connection,
                                                                                        accessorResource,
                                                                                        domainId);
      for (DomainPermission permission : domainSysPermissionsIncludingInherited) {
         // check if super-user privileges apply and construct set of all possible permissions, if necessary
         if (DomainPermissions.SUPER_USER.equals(permission.getPermissionName())) {
            return __getApplicableDomainPermissions();
         }
      }

      return __collapseDomainPermissions(domainSysPermissionsIncludingInherited);
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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

         return __getEffectiveDomainPermissionsMap(connection, accessorResource);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Map<String, Set<DomainPermission>> __getEffectiveDomainPermissionsMap(SQLConnection connection,
                                                                                 Resource accessorResource) {
      final Map<String, Set<DomainPermission>> domainSysPermissionsIncludingInherited
            = grantDomainPermissionSysPersister.getDomainSysPermissionsIncludeInherited(connection,
                                                                                        accessorResource);

      for (String domainName : domainSysPermissionsIncludingInherited.keySet()) {
         final Set<DomainPermission> domainPermissions = domainSysPermissionsIncludingInherited.get(domainName);

         if (domainPermissions.contains(DomainPermission_SUPER_USER)
               || domainPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {
            domainSysPermissionsIncludingInherited.put(domainName, __getApplicableDomainPermissions());
         }
      }

      return __collapseDomainPermissions(domainSysPermissionsIncludingInherited);
   }

   private static Set<DomainPermission> __getApplicableDomainPermissions() {
      Set<DomainPermission> superDomainPermissions = new HashSet<>(3);
      superDomainPermissions.add(DomainPermission_SUPER_USER_GRANT);
      superDomainPermissions.add(DomainPermission_CREATE_CHILD_DOMAIN_GRANT);
      superDomainPermissions.add(DomainPermission_DELETE_GRANT);

      return superDomainPermissions;
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
      __assertUniqueSystemOrPostCreateDomainPermissionNames(requestedDomainCreatePermissions);
      __assertResourceExists(connection, accessorResource);

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
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
         // if at least one permission is specified, then there must be a *CREATE permission in the set
         if (!__setContainsDomainCreateSystemPermission(domainCreatePermissions)) {
            throw new IllegalArgumentException("Domain create permission *CREATE must be specified");
         }
      }
   }

   private boolean __setContainsDomainCreateSystemPermission(Set<DomainCreatePermission> domainCreatePermissions) {
      for (final DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
         if (domainCreatePermission.isSystemPermission()
               && DomainCreatePermissions.CREATE.equals(domainCreatePermission.getPermissionName())) {
            return true;
         }
      }
      return false;
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
   public void grantDomainCreatePermissions(Resource accessorResource,
                                            Set<DomainCreatePermission> domainCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionsSpecified(domainCreatePermissions);
      __assertPermissionsSetNotEmpty(domainCreatePermissions);

      try {
         connection = __getConnection();

         __grantDirectDomainCreatePermissions(connection, accessorResource, domainCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void grantDomainCreatePermissions(Resource accessorResource,
                                            DomainCreatePermission domainCreatePermission,
                                            DomainCreatePermission... domainCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionSpecified(domainCreatePermission);
      __assertVarargPermissionsSpecified(domainCreatePermissions);

      final Set<DomainCreatePermission> requestedDomainCreatePermissions
            = __getSetWithoutNullsOrDuplicates(domainCreatePermission, domainCreatePermissions);

      try {
         connection = __getConnection();

         __grantDirectDomainCreatePermissions(connection, accessorResource, requestedDomainCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __grantDirectDomainCreatePermissions(SQLConnection connection,
                                                     Resource accessorResource,
                                                     Set<DomainCreatePermission> requestedDomainCreatePermissions) {
      __assertUniqueSystemOrPostCreateDomainPermissionNames(requestedDomainCreatePermissions);
      __assertResourceExists(connection, accessorResource);

      // check if grantor (=session resource) is authorized to add requested permissions
      final Set<DomainCreatePermission>
            grantorPermissions
            = __getEffectiveDomainCreatePermissions(connection, sessionResource);

      final Set<DomainCreatePermission>
            unauthorizedPermissions
            = __subtractDomainCreatePermissionsIfGrantableFrom(requestedDomainCreatePermissions, grantorPermissions);

      if (unauthorizedPermissions.size() > 0) {
         throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                           "grant the following domain create permission(s): " + unauthorizedPermissions);
      }

      final Set<DomainCreatePermission> directAccessorPermissions
            = __getDirectDomainCreatePermissions(connection, accessorResource);

      if (directAccessorPermissions.isEmpty()) {
         // our invariant is that a resource's direct create permissions must include the *CREATE system permission;
         // if there are no direct create permissions, then the requested permissions to be granted need to include *CREATE
         __assertSetContainsDomainCreateSystemPermission(requestedDomainCreatePermissions);
      }

      final Set<DomainCreatePermission> addPermissions = new HashSet<>(requestedDomainCreatePermissions.size());
      final Set<DomainCreatePermission> updatePermissions = new HashSet<>(requestedDomainCreatePermissions.size());

      for (DomainCreatePermission requestedPermission : requestedDomainCreatePermissions) {
         boolean existingPermission = false;

         if (requestedPermission.isSystemPermission()) {
            for (DomainCreatePermission existingDirectPermission : directAccessorPermissions) {

               if (existingDirectPermission.isSystemPermission() &&
                     requestedPermission.getSystemPermissionId() == existingDirectPermission.getSystemPermissionId()) {
                  // we found a match by sysId - now let's see if we need to update existing or leave it unchanged
                  if (!requestedPermission.equals(existingDirectPermission) &&
                        !requestedPermission.isGrantableFrom(existingDirectPermission)) {
                     // requested permission has higher granting rights than
                     // the already existing direct permission, so we need to update it
                     updatePermissions.add(requestedPermission);
                  }

                  existingPermission = true;
                  break;
               }
            }
         }
         else {
            final DomainPermission requestedPostCreateDomainPermission = requestedPermission.getPostCreateDomainPermission();
            for (DomainCreatePermission existingDirectPermission : directAccessorPermissions) {
               if (!existingDirectPermission.isSystemPermission()) {
                  final DomainPermission existingPostCreateDomainPermission
                        = existingDirectPermission.getPostCreateDomainPermission();

                  if (requestedPostCreateDomainPermission.equalsIgnoreGrant(existingPostCreateDomainPermission)) {
                     // found a match in name - let's check compatibility first
                     if (requestedPermission.isWithGrant() != requestedPostCreateDomainPermission.isWithGrant()
                           && existingDirectPermission.isWithGrant() != existingPostCreateDomainPermission.isWithGrant()
                           && requestedPermission.isWithGrant() != existingDirectPermission.isWithGrant()) {
                        // the requested permission is incompatible to the existing permission because we can't
                        // perform grant operations (a)/G -> (a/G) or (a/G) -> (a)/G without removing either the
                        // create or post-create granting option
                        throw new IllegalArgumentException("Requested create permissions "
                                                                 + requestedDomainCreatePermissions
                                                                 + " are incompatible with existing create permissions "
                                                                 + directAccessorPermissions);
                     }

                     // now let's see if we need to update existing permission or leave it unchanged
                     if (!requestedPermission.equals(existingDirectPermission)
                           && ((requestedPermission.isWithGrant() && requestedPostCreateDomainPermission.isWithGrant())
                           || (!existingDirectPermission.isWithGrant() && !existingPostCreateDomainPermission.isWithGrant()))) {
                        // the two permissions match in name, but the requested has higher granting rights,
                        // so we need to update
                        updatePermissions.add(requestedPermission);
                     }
                     // because we found a match in name, we can skip comparing requested against other existing permissions
                     existingPermission = true;
                     break;
                  }
               }
            }
         }

         if (!existingPermission) {
            // couldn't find requested permission in set of already existing direct permissions, by name, so we need to add it
            addPermissions.add(requestedPermission);
         }
      }

      // update the domain system permissions (*CREATE), if necessary
      grantDomainCreatePermissionSysPersister.updateDomainCreateSysPermissions(connection,
                                                                               accessorResource,
                                                                               sessionResource,
                                                                               updatePermissions);
      // update the domain post create system permissions, if necessary
      grantDomainCreatePermissionPostCreateSysPersister
            .updateDomainCreatePostCreateSysPermissions(connection,
                                                        accessorResource,
                                                        sessionResource,
                                                        updatePermissions);

      // add any new domain system permissions (*CREATE)
      grantDomainCreatePermissionSysPersister.addDomainCreateSysPermissions(connection,
                                                                            accessorResource,
                                                                            sessionResource,
                                                                            addPermissions);
      // add any new domain post create system permissions
      grantDomainCreatePermissionPostCreateSysPersister
            .addDomainCreatePostCreateSysPermissions(connection,
                                                     accessorResource,
                                                     sessionResource,
                                                     addPermissions);
   }

   private void __assertUniqueSystemOrPostCreateDomainPermissionNames(Set<DomainCreatePermission> domainCreatePermissions) {
      final Set<String> uniqueSystemPermissionNames = new HashSet<>(domainCreatePermissions.size());
      final Set<String> uniquePostCreatePermissionNames = new HashSet<>(domainCreatePermissions.size());

      for (final DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
         if (domainCreatePermission.isSystemPermission()) {
            if (uniqueSystemPermissionNames.contains(domainCreatePermission.getPermissionName())) {
               throw new IllegalArgumentException("Duplicate permission: "
                                                        + domainCreatePermission.getPermissionName()
                                                        + " that only differs in 'withGrant' option");
            }
            else {
               uniqueSystemPermissionNames.add(domainCreatePermission.getPermissionName());
            }
         }
         else {
            final DomainPermission postCreateDomainPermission = domainCreatePermission.getPostCreateDomainPermission();

            if (uniquePostCreatePermissionNames.contains(postCreateDomainPermission.getPermissionName())) {
               throw new IllegalArgumentException("Duplicate permission: "
                                                        + postCreateDomainPermission.getPermissionName()
                                                        + " that only differs in 'withGrant' option");
            }
            else {
               uniquePostCreatePermissionNames.add(postCreateDomainPermission.getPermissionName());
            }
         }
      }
   }

   @Override
   public void revokeDomainCreatePermissions(Resource accessorResource,
                                             Set<DomainCreatePermission> domainCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionsSpecified(domainCreatePermissions);
      __assertPermissionsSetNotEmpty(domainCreatePermissions);

      try {
         connection = __getConnection();

         __revokeDirectDomainCreatePermissions(connection, accessorResource, domainCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void revokeDomainCreatePermissions(Resource accessorResource,
                                             DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionSpecified(domainCreatePermission);
      __assertVarargPermissionsSpecified(domainCreatePermissions);

      final Set<DomainCreatePermission> requestedDomainCreatePermissions
            = __getSetWithoutNullsOrDuplicates(domainCreatePermission, domainCreatePermissions);

      try {
         connection = __getConnection();

         __revokeDirectDomainCreatePermissions(connection, accessorResource, requestedDomainCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __revokeDirectDomainCreatePermissions(SQLConnection connection,
                                                      Resource accessorResource,
                                                      Set<DomainCreatePermission> requestedDomainCreatePermissions) {
      __assertUniqueSystemOrPostCreateDomainPermissionNames(requestedDomainCreatePermissions);
      __assertResourceExists(connection, accessorResource);

      // check if grantor (=session resource) is authorized to revoke requested permissions
      final Set<DomainCreatePermission>
            grantorPermissions
            = __getEffectiveDomainCreatePermissions(connection, sessionResource);

      final Set<DomainCreatePermission>
            unauthorizedPermissions
            = __subtractDomainCreatePermissionsIfGrantableFrom(requestedDomainCreatePermissions, grantorPermissions);

      if (unauthorizedPermissions.size() > 0) {
         throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                           "revoke the following domain create permission(s): " + unauthorizedPermissions);
      }

      final Set<DomainCreatePermission> directAccessorPermissions
            = __getDirectDomainCreatePermissions(connection, accessorResource);

      if ((directAccessorPermissions.size() > requestedDomainCreatePermissions.size()) &&
            __setContainsDomainCreateSystemPermission(requestedDomainCreatePermissions)) {
         // our invariant is that a resource's direct create permissions must include the *CREATE system permission;
         // if after revoking the requested permissions, the remaining set wouldn't include the *CREATE, we'd have a problem
         throw new IllegalArgumentException(
               "Attempt to revoke a subset of domain create permissions that includes the *CREATE system permission: "
                     + requestedDomainCreatePermissions);
      }

      final Set<DomainCreatePermission> removePermissions = new HashSet<>(requestedDomainCreatePermissions.size());

      for (DomainCreatePermission requestedPermission : requestedDomainCreatePermissions) {
         if (requestedPermission.isSystemPermission()) {
            for (DomainCreatePermission existingDirectPermission : directAccessorPermissions) {
               if (existingDirectPermission.isSystemPermission() &&
                     requestedPermission.getSystemPermissionId() == existingDirectPermission.getSystemPermissionId()) {
                  // requested permission has same system Id as an already existing direct permission, so remove it
                  removePermissions.add(requestedPermission);
                  break;
               }
            }
         }
         else {
            final DomainPermission requestedPostCreateDomainPermission = requestedPermission.getPostCreateDomainPermission();
            for (DomainCreatePermission existingDirectPermission : directAccessorPermissions) {
               if (!existingDirectPermission.isSystemPermission()) {
                  // now let's look at the post-create permissions
                  if (requestedPostCreateDomainPermission.equalsIgnoreGrant(existingDirectPermission.getPostCreateDomainPermission())) {
                     // requested post-create permission has same name as an already existing direct permission, so remove it
                     removePermissions.add(requestedPermission);
                     break;
                  }
               }
            }
         }
      }

      // remove the domain system permissions (*CREATE), if necessary
      grantDomainCreatePermissionSysPersister.removeDomainCreateSysPermissions(connection,
                                                                               accessorResource,
                                                                               removePermissions);
      // remove the domain post create system permissions, if necessary
      grantDomainCreatePermissionPostCreateSysPersister.removeDomainCreatePostCreateSysPermissions(connection,
                                                                                                   accessorResource,
                                                                                                   removePermissions);
   }

   @Override
   public Set<DomainCreatePermission> getDomainCreatePermissions(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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
                                            String domainName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourceCreatePermissions);

      try {
         connection = __getConnection();

         __setDirectResourceCreatePermissions(connection,
                                              accessorResource,
                                              resourceClassName,
                                              domainName,
                                              resourceCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __setDirectResourceCreatePermissions(SQLConnection connection,
                                                     Resource accessorResource,
                                                     String resourceClassName,
                                                     String domainName,
                                                     Set<ResourceCreatePermission> requestedResourceCreatePermissions) {
      __assertResourceExists(connection, accessorResource);

      // verify that resource class is defined and get its metadata
      final ResourceClassInternalInfo resourceClassInfo = __getResourceClassInternalInfo(connection,
                                                                                         resourceClassName);

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
               = __getEffectiveResourceCreatePermissionsIgnoringSuperUserPrivileges(connection,
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
               throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
               throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
      final List<String> validPermissionNames =
            __getApplicableResourcePermissionNames(connection, resourceClassInternalInfo);
      final Set<String> uniqueSystemPermissionNames = new HashSet<>(resourceCreatePermissions.size());
      final Set<String> uniquePostCreatePermissionNames = new HashSet<>(resourceCreatePermissions.size());

      for (final ResourceCreatePermission resourceCreatePermission : resourceCreatePermissions) {
         if (resourceCreatePermission.isSystemPermission()) {
            if (uniqueSystemPermissionNames.contains(resourceCreatePermission.getPermissionName())) {
               throw new IllegalArgumentException("Duplicate permission: "
                                                        + resourceCreatePermission.getPermissionName()
                                                        + " that only differs in 'withGrant' option");
            }
            else {
               uniqueSystemPermissionNames.add(resourceCreatePermission.getPermissionName());
            }
         }
         else {
            final ResourcePermission postCreateResourcePermission = resourceCreatePermission.getPostCreateResourcePermission();

            if (!validPermissionNames.contains(postCreateResourcePermission.getPermissionName())) {
               if (postCreateResourcePermission.isSystemPermission()) {
                  // currently the only invalid system permissions are for unauthenticatable resource classes
                  throw new IllegalArgumentException("Permission: "
                                                           + postCreateResourcePermission.getPermissionName()
                                                           + ", not valid for unauthenticatable resource");
               }
               else {
                  throw new IllegalArgumentException("Permission: "
                                                           + postCreateResourcePermission.getPermissionName()
                                                           + " is not defined for resource class: "
                                                           + resourceClassInternalInfo.getResourceClassName());
               }
            }

            if (uniquePostCreatePermissionNames.contains(postCreateResourcePermission.getPermissionName())) {
               throw new IllegalArgumentException("Duplicate permission: "
                                                        + postCreateResourcePermission.getPermissionName()
                                                        + " that only differs in 'withGrant' option");
            }
            else {
               uniquePostCreatePermissionNames.add(postCreateResourcePermission.getPermissionName());
            }
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
   public void grantResourceCreatePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              String domainName,
                                              Set<ResourceCreatePermission> resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourceCreatePermissions);
      __assertPermissionsSetNotEmpty(resourceCreatePermissions);

      try {
         connection = __getConnection();

         __grantDirectResourceCreatePermissions(connection,
                                                accessorResource,
                                                resourceClassName,
                                                domainName,
                                                resourceCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void grantResourceCreatePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              String domainName,
                                              ResourceCreatePermission resourceCreatePermission,
                                              ResourceCreatePermission... resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourceCreatePermission);
      __assertVarargPermissionsSpecified(resourceCreatePermissions);

      final Set<ResourceCreatePermission> requestedResourceCreatePermissions
            = __getSetWithoutNullsOrDuplicates(resourceCreatePermission, resourceCreatePermissions);

      try {
         connection = __getConnection();

         __grantDirectResourceCreatePermissions(connection,
                                                accessorResource,
                                                resourceClassName,
                                                domainName,
                                                requestedResourceCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __grantDirectResourceCreatePermissions(SQLConnection connection,
                                                       Resource accessorResource,
                                                       String resourceClassName,
                                                       String domainName,
                                                       Set<ResourceCreatePermission> requestedResourceCreatePermissions) {
      __assertResourceExists(connection, accessorResource);

      // verify that resource class is defined and get its metadata
      final ResourceClassInternalInfo resourceClassInfo = __getResourceClassInternalInfo(connection,
                                                                                         resourceClassName);

      final Id<ResourceClassId> resourceClassId = Id.from(resourceClassInfo.getResourceClassId());

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // ensure that the post create permissions are all in the correct resource class
      __assertUniquePostCreatePermissionsNamesForResourceClass(connection, requestedResourceCreatePermissions, resourceClassInfo);

      // check if the grantor (=session resource) is authorized to grant the requested permissions
      if (!__isSuperUserOfDomain(connection, sessionResource, domainName)) {
         final Set<ResourceCreatePermission> grantorPermissions
               = __getEffectiveResourceCreatePermissionsIgnoringSuperUserPrivileges(connection,
                                                                                    sessionResource,
                                                                                    resourceClassName,
                                                                                    domainName);

         final Set<ResourceCreatePermission> unauthorizedAddPermissions
               = __subtractResourceCreatePermissionsIfGrantableFrom(requestedResourceCreatePermissions, grantorPermissions);

         if (unauthorizedAddPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "grant the following permission(s): " + unauthorizedAddPermissions);
         }
      }

      // ensure that the *CREATE system permissions was specified
      final Set<ResourceCreatePermission>
            directAccessorPermissions
            = __getDirectResourceCreatePermissions(connection,
                                                   accessorResource,
                                                   resourceClassId,
                                                   domainId);

      if (directAccessorPermissions.isEmpty()) {
         // our invariant is that a resource's direct create permissions must include the *CREATE system permission;
         // if there are no direct create permissions, then the requested permissions to be granted needs to include *CREATE
         __assertSetContainsResourceCreateSystemPermission(requestedResourceCreatePermissions);
      }

      final Set<ResourceCreatePermission> addPermissions = new HashSet<>(requestedResourceCreatePermissions.size());
      final Set<ResourceCreatePermission> updatePermissions = new HashSet<>(requestedResourceCreatePermissions.size());

      for (ResourceCreatePermission requestedPermission : requestedResourceCreatePermissions) {
         boolean existingPermission = false;

         if (requestedPermission.isSystemPermission()) {
            for (ResourceCreatePermission existingDirectPermission : directAccessorPermissions) {
               if (existingDirectPermission.isSystemPermission() &&
                     requestedPermission.getSystemPermissionId() == existingDirectPermission.getSystemPermissionId()) {
                  // we found a match by sysId - now let's see if we need to update existing or leave it unchanged
                  if (!requestedPermission.equals(existingDirectPermission) &&
                        !requestedPermission.isGrantableFrom(existingDirectPermission)) {
                     // requested permission has higher granting rights than
                     // the already existing direct permission, so we need to update it
                     updatePermissions.add(requestedPermission);
                  }

                  existingPermission = true;
                  break;
               }
            }
         }
         else {
            final ResourcePermission requestedPostCreateResourcePermission
                  = requestedPermission.getPostCreateResourcePermission();
            for (ResourceCreatePermission existingDirectPermission : directAccessorPermissions) {
               if (!existingDirectPermission.isSystemPermission()) {
                  final ResourcePermission existingPostCreateResourcePermission
                        = existingDirectPermission.getPostCreateResourcePermission();

                  if (requestedPostCreateResourcePermission.equalsIgnoreGrant(existingPostCreateResourcePermission)) {
                     // found a match in name - let's check compatibility first
                     if (requestedPermission.isWithGrant() != requestedPostCreateResourcePermission.isWithGrant()
                           && existingDirectPermission.isWithGrant() != existingPostCreateResourcePermission.isWithGrant()
                           && requestedPermission.isWithGrant() != existingDirectPermission.isWithGrant()) {
                        // the requested permission is incompatible to the existing permission because we can't
                        // perform grant operations (a)/G -> (a/G) or (a/G) -> (a)/G without removing either the
                        // create or post-create granting option
                        throw new IllegalArgumentException("Requested create permissions "
                                                                 + requestedResourceCreatePermissions
                                                                 + " are incompatible with existing create permissions "
                                                                 + directAccessorPermissions);
                     }

                     // now let's see if we need to update existing permission or leave it unchanged
                     if (!requestedPermission.equals(existingDirectPermission)
                           && ((requestedPermission.isWithGrant() && requestedPostCreateResourcePermission.isWithGrant())
                           || (!existingDirectPermission.isWithGrant() && !existingPostCreateResourcePermission.isWithGrant()))) {
                        // the two permissions match in name, but the requested has higher granting rights,
                        // so we need to update
                        updatePermissions.add(requestedPermission);
                     }

                     // because we found a match in name, we can skip comparing requested against other existing permissions
                     existingPermission = true;
                     break;
                  }
               }
            }
         }

         if (!existingPermission) {
            // couldn't find requested permission in set of already existing direct permissions, by name, so we need to add it
            addPermissions.add(requestedPermission);
         }
      }

      // update *CREATE system permission, if necessary
      grantResourceCreatePermissionSysPersister.updateResourceCreateSysPermissions(connection,
                                                                                   accessorResource,
                                                                                   resourceClassId,
                                                                                   domainId,
                                                                                   updatePermissions,
                                                                                   sessionResource);

      // update any post create system permissions, if necessary
      grantResourceCreatePermissionPostCreateSysPersister.updateResourceCreatePostCreateSysPermissions(connection,
                                                                                                       accessorResource,
                                                                                                       resourceClassId,
                                                                                                       domainId,
                                                                                                       updatePermissions,
                                                                                                       sessionResource);

      // update any post create non-system permissions, if necessary
      grantResourceCreatePermissionPostCreatePersister.updateResourceCreatePostCreatePermissions(connection,
                                                                                                 accessorResource,
                                                                                                 resourceClassId,
                                                                                                 domainId,
                                                                                                 updatePermissions,
                                                                                                 sessionResource);
      // grant the *CREATE system permissions, if necessary
      grantResourceCreatePermissionSysPersister.addResourceCreateSysPermissions(connection,
                                                                                accessorResource,
                                                                                resourceClassId,
                                                                                domainId,
                                                                                addPermissions,
                                                                                sessionResource);

      // grant any post create system permissions, if necessary
      grantResourceCreatePermissionPostCreateSysPersister.addResourceCreatePostCreateSysPermissions(connection,
                                                                                                    accessorResource,
                                                                                                    resourceClassId,
                                                                                                    domainId,
                                                                                                    addPermissions,
                                                                                                    sessionResource);

      // grant any post create non-system permissions, if necessary
      grantResourceCreatePermissionPostCreatePersister.addResourceCreatePostCreatePermissions(connection,
                                                                                              accessorResource,
                                                                                              resourceClassId,
                                                                                              domainId,
                                                                                              addPermissions,
                                                                                              sessionResource);
   }

   @Override
   public void revokeResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               Set<ResourceCreatePermission> resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourceCreatePermissions);
      __assertPermissionsSetNotEmpty(resourceCreatePermissions);

      try {
         connection = __getConnection();

         __revokeDirectResourceCreatePermissions(connection,
                                                 accessorResource,
                                                 resourceClassName,
                                                 domainName,
                                                 resourceCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void revokeResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourceCreatePermission);
      __assertVarargPermissionsSpecified(resourceCreatePermissions);

      final Set<ResourceCreatePermission> requestedResourceCreatePermissions
            = __getSetWithoutNullsOrDuplicates(resourceCreatePermission, resourceCreatePermissions);

      try {
         connection = __getConnection();

         __revokeDirectResourceCreatePermissions(connection,
                                                 accessorResource,
                                                 resourceClassName,
                                                 domainName,
                                                 requestedResourceCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __revokeDirectResourceCreatePermissions(SQLConnection connection,
                                                        Resource accessorResource,
                                                        String resourceClassName,
                                                        String domainName,
                                                        Set<ResourceCreatePermission> requestedResourceCreatePermissions) {
      __assertResourceExists(connection, accessorResource);

      // verify that resource class is defined and get its metadata
      final ResourceClassInternalInfo resourceClassInfo = __getResourceClassInternalInfo(connection,
                                                                                         resourceClassName);

      final Id<ResourceClassId> resourceClassId = Id.from(resourceClassInfo.getResourceClassId());

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      __assertUniquePostCreatePermissionsNamesForResourceClass(connection,
                                                               requestedResourceCreatePermissions,
                                                               resourceClassInfo);

      // check if the grantor (=session resource) is authorized to grant the requested permissions
      if (!__isSuperUserOfDomain(connection, sessionResource, domainName)) {
         final Set<ResourceCreatePermission> grantorPermissions
               = __getEffectiveResourceCreatePermissionsIgnoringSuperUserPrivileges(connection,
                                                                                    sessionResource,
                                                                                    resourceClassName,
                                                                                    domainName);

         final Set<ResourceCreatePermission> unauthorizedPermissions
               = __subtractResourceCreatePermissionsIfGrantableFrom(requestedResourceCreatePermissions,
                                                                    grantorPermissions);

         if (unauthorizedPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "revoke the following permission(s): " + unauthorizedPermissions);
         }
      }

      // ensure that the *CREATE system permissions will remain if not all are cleared
      final Set<ResourceCreatePermission>
            directAccessorPermissions
            = __getDirectResourceCreatePermissions(connection,
                                                   accessorResource,
                                                   resourceClassId,
                                                   domainId);

      if ((directAccessorPermissions.size() > requestedResourceCreatePermissions.size()) &&
            __setContainsResourceCreateSystemPermission(requestedResourceCreatePermissions)) {
         // our invariant is that a resource's direct create permissions must include the *CREATE system permission;
         // if after revoking the requested permissions, the remaining set wouldn't include the *CREATE, we'd have a problem
         throw new IllegalArgumentException(
               "Attempt to revoke a subset of resource create permissions that includes the *CREATE system permission: "
                     + requestedResourceCreatePermissions);
      }

      final Set<ResourceCreatePermission> removePermissions = new HashSet<>(requestedResourceCreatePermissions.size());

      for (ResourceCreatePermission requestedPermission : requestedResourceCreatePermissions) {
         if (requestedPermission.isSystemPermission()) {
            for (ResourceCreatePermission existingDirectPermission : directAccessorPermissions) {
               if (existingDirectPermission.isSystemPermission() &&
                     requestedPermission.getSystemPermissionId() == existingDirectPermission.getSystemPermissionId()) {
                  // requested permission has same system Id as an already existing direct permission, so remove it
                  removePermissions.add(requestedPermission);
                  break;
               }
            }
         }
         else {
            final ResourcePermission requestedPostCreateResourcePermission
                  = requestedPermission.getPostCreateResourcePermission();
            for (ResourceCreatePermission existingDirectPermission : directAccessorPermissions) {
               if (!existingDirectPermission.isSystemPermission()) {
                  // now let's look at the post-create permissions
                  if (requestedPostCreateResourcePermission
                        .equalsIgnoreGrant(existingDirectPermission.getPostCreateResourcePermission())) {
                     // requested post-create permission has same name as an already existing direct permission, so remove it
                     removePermissions.add(requestedPermission);
                     break;
                  }
               }
            }
         }
      }

      // remove *CREATE system permission, if necessary
      grantResourceCreatePermissionSysPersister.removeResourceCreateSysPermissions(connection,
                                                                                   accessorResource,
                                                                                   resourceClassId,
                                                                                   domainId,
                                                                                   removePermissions);

      // remove any post create system permissions, if necessary
      grantResourceCreatePermissionPostCreateSysPersister.removeResourceCreatePostCreateSysPermissions(connection,
                                                                                                       accessorResource,
                                                                                                       resourceClassId,
                                                                                                       domainId,
                                                                                                       removePermissions);

      // remove any post create non-system permissions, if necessary
      grantResourceCreatePermissionPostCreatePersister.removeResourceCreatePostCreatePermissions(connection,
                                                                                                 accessorResource,
                                                                                                 resourceClassId,
                                                                                                 domainId,
                                                                                                 removePermissions);
   }

   private boolean __setContainsResourceCreateSystemPermission(Set<ResourceCreatePermission> resourceCreatePermissions) {
      for (final ResourceCreatePermission resourceCreatePermission : resourceCreatePermissions) {
         if (resourceCreatePermission.isSystemPermission()
               && ResourceCreatePermissions.CREATE.equals(resourceCreatePermission.getPermissionName())) {
            return true;
         }
      }
      return false;
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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getResourceCreatePermissionsMap(Resource accessorResource) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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
            .putAll(grantResourceCreatePermissionSysPersister.getResourceCreateSysPermissions(connection,
                                                                                              accessorResource));

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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

   private Set<ResourceCreatePermission> __getEffectiveResourceCreatePermissionsIgnoringSuperUserPrivileges(SQLConnection connection,
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

   private Set<ResourceCreatePermission> __getEffectiveResourceCreatePermissions(SQLConnection connection,
                                                                                 Resource accessorResource,
                                                                                 String resourceClassName,
                                                                                 String domainName) {
      // verify that resource class is defined
      final ResourceClassInternalInfo resourceClassInternalInfo
            = __getResourceClassInternalInfo(connection, resourceClassName);

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      if (__isSuperUserOfDomain(connection, accessorResource, domainName)) {
         return __getApplicableResourceCreatePermissions(connection, resourceClassInternalInfo);
      }

      Id<ResourceClassId> resourceClassId = Id.from(resourceClassInternalInfo.getResourceClassId());

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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

      // finally, collect all applicable create permissions when accessor has super-user privileges to any domain
      // and add them into the globalALLPermissionsMap
      final Map<String, Map<String, Set<ResourceCreatePermission>>> allSuperResourceCreatePermissionsMap = new HashMap<>();
      Map<String, Set<ResourceCreatePermission>> superResourceCreatePermissionsMap = null;

      final Map<String, Set<DomainPermission>> effectiveDomainPermissionsMap
            = __getEffectiveDomainPermissionsMap(connection, accessorResource);

      for (String domainName : effectiveDomainPermissionsMap.keySet()) {
         final Set<DomainPermission> effectiveDomainPermissions = effectiveDomainPermissionsMap.get(domainName);
         if (effectiveDomainPermissions.contains(DomainPermission_SUPER_USER)
               || effectiveDomainPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {

            if (superResourceCreatePermissionsMap == null) {
               // lazy-construct super-user-privileged resource-permissions map by resource classes
               final List<String> resourceClassNames = resourceClassPersister.getResourceClassNames(connection);
               superResourceCreatePermissionsMap = new HashMap<>(resourceClassNames.size());
               for (String resourceClassName : resourceClassNames) {
                  final Set<ResourceCreatePermission> applicableResourceCreatePermissions
                        = __getApplicableResourceCreatePermissions(connection,
                                                                   __getResourceClassInternalInfo(connection,
                                                                                                  resourceClassName));

                  superResourceCreatePermissionsMap.put(resourceClassName, applicableResourceCreatePermissions);
               }
            }
            allSuperResourceCreatePermissionsMap.put(domainName, superResourceCreatePermissionsMap);
         }
      }

      __mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(allSuperResourceCreatePermissionsMap,
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
         __assertResourceExists(connection, accessorResource);

         if (!__isSuperUserOfResource(connection, grantorResource, accessedResource)) {
            // next check if the grantor (i.e. session resource) has permissions to grant the requested permissions
            final Set<ResourcePermission>
                  grantorResourcePermissions
                  = __getEffectiveResourcePermissionsIgnoringSuperUserPrivileges(connection,
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
                  throw NotAuthorizedException.newInstanceForAction(grantorResource,
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
                  throw NotAuthorizedException.newInstanceForAction(grantorResource,
                                                                    "remove the following permission(s): " + unauthorizedRemovePermissions);
               }
            }
         }

         // if inherit permissions are about to be granted, first check for cycles
         if (requestedResourcePermissions.contains(ResourcePermission_INHERIT)
               || requestedResourcePermissions.contains(ResourcePermission_INHERIT_GRANT)) {
            Set<ResourcePermission> reversePathResourcePermissions
                  = __getEffectiveResourcePermissionsIgnoringSuperUserPrivileges(connection,
                                                                                 accessedResource,
                                                                                 accessorResource);

            if (reversePathResourcePermissions.contains(ResourcePermission_INHERIT)
                  || reversePathResourcePermissions.contains(ResourcePermission_INHERIT_GRANT)
                  || accessorResource.equals(accessedResource)) {
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
                                                                          accessedResourceClassInternalInfo
                                                                                .getResourceClassId()),
                                                                    requestedResourcePermissions,
                                                                    grantorResource);

      // add the new direct non-system permissions
      grantResourcePermissionPersister.addResourcePermissions(connection,
                                                              accessorResource,
                                                              accessedResource,
                                                              Id.<ResourceClassId>from(accessedResourceClassInternalInfo
                                                                                             .getResourceClassId()),
                                                              requestedResourcePermissions,
                                                              grantorResource);
   }

   private void __assertUniqueResourcePermissionsNamesForResourceClass(SQLConnection connection,
                                                                       Set<ResourcePermission> resourcePermissions,
                                                                       ResourceClassInternalInfo resourceClassInternalInfo) {
      final List<String> validPermissionNames
            = __getApplicableResourcePermissionNames(connection, resourceClassInternalInfo);
      final Set<String> uniquePermissionNames = new HashSet<>(resourcePermissions.size());

      for (final ResourcePermission resourcePermission : resourcePermissions) {
         if (!validPermissionNames.contains(resourcePermission.getPermissionName())) {
            if (resourcePermission.isSystemPermission()) {
               // currently the only invalid system permissions are for unauthenticatable resource classes
               throw new IllegalArgumentException("Permission: "
                                                        + resourcePermission.getPermissionName()
                                                        + ", not valid for unauthenticatable resource");
            }
            else {
               throw new IllegalArgumentException("Permission: "
                                                        + resourcePermission.getPermissionName()
                                                        + " is not defined for resource class: "
                                                        + resourceClassInternalInfo.getResourceClassName());
            }
         }

         if (uniquePermissionNames.contains(resourcePermission.getPermissionName())) {
            throw new IllegalArgumentException("Duplicate permission: "
                                                     + resourcePermission.getPermissionName()
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
   public void grantResourcePermissions(Resource accessorResource,
                                        Resource accessedResource,
                                        Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();

         __grantDirectResourcePermissions(connection, accessorResource, accessedResource, resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void grantResourcePermissions(Resource accessorResource,
                                        Resource accessedResource,
                                        ResourcePermission resourcePermission,
                                        ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();

         __grantDirectResourcePermissions(connection, accessorResource, accessedResource, requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __grantDirectResourcePermissions(SQLConnection connection,
                                                 Resource accessorResource,
                                                 Resource accessedResource,
                                                 Set<ResourcePermission> requestedResourcePermissions) {
      __assertResourceExists(connection, accessorResource);

      final ResourceClassInternalInfo accessedResourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfoByResourceId(connection, accessedResource);

      // next ensure that the requested permissions are all in the correct resource class
      __assertUniqueResourcePermissionsNamesForResourceClass(connection,
                                                             requestedResourcePermissions,
                                                             accessedResourceClassInternalInfo);

      // check for authorization
      if (!__isSuperUserOfResource(connection, sessionResource, accessedResource)) {
         final Set<ResourcePermission>
               grantorResourcePermissions
               = __getEffectiveResourcePermissionsIgnoringSuperUserPrivileges(connection,
                                                                              sessionResource,
                                                                              accessedResource);

         final Set<ResourcePermission>
               unauthorizedPermissions
               = __subtractResourcePermissionsIfGrantableFrom(requestedResourcePermissions, grantorResourcePermissions);

         if (unauthorizedPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "grant the following permission(s): " + unauthorizedPermissions);
         }
      }

      final Set<ResourcePermission> directAccessorResourcePermissions
            = __getDirectResourcePermissions(connection, accessorResource, accessedResource);

      final Set<ResourcePermission> addPermissions = new HashSet<>(requestedResourcePermissions.size());
      final Set<ResourcePermission> updatePermissions = new HashSet<>(requestedResourcePermissions.size());

      for (ResourcePermission requestedPermission : requestedResourcePermissions) {
         boolean existingPermission = false;

         for (ResourcePermission existingDirectPermission : directAccessorResourcePermissions) {
            if (requestedPermission.equalsIgnoreGrant(existingDirectPermission)) {
               // found a match by name - now let's see if we need to update existing or leave it unchanged
               if (!requestedPermission.equals(existingDirectPermission) &&
                     !requestedPermission.isGrantableFrom(existingDirectPermission)) {
                  // requested permission has higher granting rights than the already existing direct permission,
                  // so we need to update it
                  updatePermissions.add(requestedPermission);
               }

               existingPermission = true;
               break;
            }
         }

         if (!existingPermission) {
            // couldn't find requested permission in set of already existing direct permissions, by name, so we need to add it
            addPermissions.add(requestedPermission);
         }
      }

      // if inherit permissions are about to be granted, first check for cycles
      if (addPermissions.contains(ResourcePermission_INHERIT)
            || addPermissions.contains(ResourcePermission_INHERIT_GRANT)) {
         Set<ResourcePermission> reversePathResourcePermissions
               = __getEffectiveResourcePermissionsIgnoringSuperUserPrivileges(connection,
                                                                              accessedResource,
                                                                              accessorResource);

         if (reversePathResourcePermissions.contains(ResourcePermission_INHERIT)
               || reversePathResourcePermissions.contains(ResourcePermission_INHERIT_GRANT)
               || accessorResource.equals(accessedResource)) {
            throw new OaccException("Granting the requested permission(s): "
                                          + requestedResourcePermissions
                                          + " will cause a cycle between: "
                                          + accessorResource
                                          + " and: "
                                          + accessedResource);
         }
      }

      // update any necessary direct system permissions between the accessor and the accessed resource
      grantResourcePermissionSysPersister.updateResourceSysPermissions(connection,
                                                                       accessorResource,
                                                                       accessedResource,
                                                                       Id.<ResourceClassId>from(
                                                                             accessedResourceClassInternalInfo.getResourceClassId()),
                                                                       updatePermissions,
                                                                       sessionResource);

      // update any necessary direct non-system permissions between the accessor and the accessed resource
      grantResourcePermissionPersister.updateResourcePermissions(connection,
                                                                 accessorResource,
                                                                 accessedResource,
                                                                 Id.<ResourceClassId>from(
                                                                       accessedResourceClassInternalInfo.getResourceClassId()),
                                                                 updatePermissions,
                                                                 sessionResource);

      // add the new direct system permissions
      grantResourcePermissionSysPersister.addResourceSysPermissions(connection,
                                                                    accessorResource,
                                                                    accessedResource,
                                                                    Id.<ResourceClassId>from(
                                                                          accessedResourceClassInternalInfo.getResourceClassId()),
                                                                    addPermissions,
                                                                    sessionResource);

      // add the new direct non-system permissions
      grantResourcePermissionPersister.addResourcePermissions(connection,
                                                              accessorResource,
                                                              accessedResource,
                                                              Id.<ResourceClassId>from(accessedResourceClassInternalInfo.getResourceClassId()),
                                                              addPermissions,
                                                              sessionResource);
   }

   @Override
   public void revokeResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();

         __revokeDirectResourcePermissions(connection, accessorResource, accessedResource, resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void revokeResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> obsoleteResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();

         __revokeDirectResourcePermissions(connection, accessorResource, accessedResource, obsoleteResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __revokeDirectResourcePermissions(SQLConnection connection,
                                                  Resource accessorResource,
                                                  Resource accessedResource,
                                                  Set<ResourcePermission> obsoleteResourcePermissions) {
      __assertResourceExists(connection, accessorResource);

      final ResourceClassInternalInfo accessedResourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfoByResourceId(connection, accessedResource);

      // next ensure that the requested permissions are unique in name
      __assertUniqueResourcePermissionsNamesForResourceClass(connection,
                                                             obsoleteResourcePermissions,
                                                             accessedResourceClassInternalInfo);

      // check for authorization
      if (!__isSuperUserOfResource(connection, sessionResource, accessedResource)) {
         final Set<ResourcePermission>
               grantorResourcePermissions
               = __getEffectiveResourcePermissionsIgnoringSuperUserPrivileges(connection,
                                                                              sessionResource,
                                                                              accessedResource);

         final Set<ResourcePermission>
               unauthorizedPermissions
               = __subtractResourcePermissionsIfGrantableFrom(obsoleteResourcePermissions, grantorResourcePermissions);

         if (unauthorizedPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "revoke the following permission(s): " + unauthorizedPermissions);
         }
      }

      final Set<ResourcePermission> directAccessorResourcePermissions
            = __getDirectResourcePermissions(connection, accessorResource, accessedResource);

      final Set<ResourcePermission> removePermissions = new HashSet<>(obsoleteResourcePermissions.size());

      for (ResourcePermission requestedPermission : obsoleteResourcePermissions) {
         for (ResourcePermission existingDirectPermission : directAccessorResourcePermissions) {
            if (requestedPermission.equalsIgnoreGrant(existingDirectPermission)) {
               // requested permission has same name and regardless of granting rights we need to remove it
               removePermissions.add(requestedPermission);
               break;
            }
         }
      }

      // update any necessary direct system permissions between the accessor and the accessed resource
      grantResourcePermissionSysPersister.removeResourceSysPermissions(connection,
                                                                       accessorResource,
                                                                       accessedResource,
                                                                       Id.<ResourceClassId>from(
                                                                             accessedResourceClassInternalInfo
                                                                                   .getResourceClassId()),
                                                                       removePermissions);

      // update any necessary direct non-system permissions between the accessor and the accessed resource
      grantResourcePermissionPersister.removeResourcePermissions(connection,
                                                                 accessorResource,
                                                                 accessedResource,
                                                                 Id.<ResourceClassId>from(
                                                                       accessedResourceClassInternalInfo
                                                                             .getResourceClassId()),
                                                                 removePermissions);
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

         __assertResourceExists(connection, accessorResource);
         __assertResourceExists(connection, accessedResource);
         __assertQueryAuthorization(connection, accessorResource);

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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

      final Id<DomainId> accessedDomainId = resourcePersister.getDomainIdByResource(connection, accessedResource);
      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfoByResourceId(connection, accessedResource);

      if (__isSuperUserOfDomain(connection, accessorResource, accessedDomainId)) {
         return __getApplicableResourcePermissions(connection, resourceClassInternalInfo);
      }

      // collect the system permissions that the accessor resource has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionSysPersister
                                       .getResourceSysPermissionsIncludeInherited(connection,
                                                                                  accessorResource,
                                                                                  accessedResource));

      // collect the non-system permissions that the accessor has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionPersister.getResourcePermissionsIncludeInherited(connection,
                                                                                                         accessorResource,
                                                                                                         accessedResource));

      final Id<ResourceClassId> accessedResourceClassId = Id.from(resourceClassInternalInfo.getResourceClassId());

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

   private Set<ResourcePermission> __getEffectiveResourcePermissionsIgnoringSuperUserPrivileges(SQLConnection connection,
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
                                            String domainName,
                                            Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __setDirectGlobalPermissions(connection,
                                      accessorResource,
                                      resourceClassName,
                                      domainName,
                                      resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __setDirectGlobalPermissions(SQLConnection connection,
                                             Resource accessorResource,
                                             String resourceClassName,
                                             String domainName,
                                             Set<ResourcePermission> requestedResourcePermissions) {
      __assertResourceExists(connection, accessorResource);

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
               = __getEffectiveGlobalResourcePermissionsIgnoringSuperUserPrivileges(connection,
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
               throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
               throw NotAuthorizedException.newInstanceForAction(sessionResource,
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
      final List<String> validPermissionNames = __getApplicableResourcePermissionNames(connection,
                                                                                       resourceClassInternalInfo);
      final HashSet<String> uniquePermissionNames = new HashSet<>(requestedResourcePermissions.size());

      for (ResourcePermission resourcePermission : requestedResourcePermissions) {
         if (resourcePermission.isSystemPermission() && ResourcePermission_INHERIT.equals(resourcePermission)) {
            // we prohibit granting the system INHERIT permission, since cycle checking may be prohibitively compute intensive
            throw new IllegalArgumentException("Permission: "
                                                     + String.valueOf(resourcePermission)
                                                     + ", not valid in this context");
         }

         if (!validPermissionNames.contains(resourcePermission.getPermissionName())) {
            if (resourcePermission.isSystemPermission()) {
               // currently the only invalid system permissions are for unauthenticatable resource classes
               throw new IllegalArgumentException("Permission "
                                                        + resourcePermission.getPermissionName()
                                                        + " not valid for unauthenticatable resource of class "
                                                        + resourceClassInternalInfo.getResourceClassName());
            }
            else {
               throw new IllegalArgumentException("Permission: "
                                                        + resourcePermission.getPermissionName()
                                                        + " is not defined for resource class: "
                                                        + resourceClassInternalInfo.getResourceClassName());
            }
         }

         if (uniquePermissionNames.contains(resourcePermission.getPermissionName())) {
            throw new IllegalArgumentException("Duplicate permission: "
                                                     + resourcePermission.getPermissionName()
                                                     + " that only differs in 'withGrant' option");
         }
         else {
            uniquePermissionNames.add(resourcePermission.getPermissionName());
         }
      }
   }


   @Override
   public void grantGlobalResourcePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              String domainName,
                                              Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __grantDirectGlobalPermissions(connection,
                                        accessorResource,
                                        resourceClassName,
                                        domainName,
                                        resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void grantGlobalResourcePermissions(Resource accessorResource,
                                              String resourceClassName,
                                              String domainName,
                                              ResourcePermission resourcePermission,
                                              ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __grantDirectGlobalPermissions(connection,
                                        accessorResource,
                                        resourceClassName,
                                        domainName,
                                        requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __grantDirectGlobalPermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               Set<ResourcePermission> requestedResourcePermissions) {
      __assertResourceExists(connection, accessorResource);

      // verify that resource class is defined
      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // next ensure that the requested permissions are all in the correct resource class
      __assertUniqueGlobalResourcePermissionNamesForResourceClass(connection, requestedResourcePermissions, resourceClassInternalInfo);

      // check for authorization
      if (!__isSuperUserOfDomain(connection, sessionResource, domainName)) {
         final Set<ResourcePermission> grantorPermissions
               = __getEffectiveGlobalResourcePermissionsIgnoringSuperUserPrivileges(connection,
                                                                                    sessionResource,
                                                                                    resourceClassName,
                                                                                    domainName);

         final Set<ResourcePermission> unauthorizedPermissions
               = __subtractResourcePermissionsIfGrantableFrom(requestedResourcePermissions, grantorPermissions);

         if (unauthorizedPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "grant the following global permission(s): " + unauthorizedPermissions);
         }
      }

      final Set<ResourcePermission> directAccessorPermissions
            = __getDirectGlobalResourcePermissions(connection, accessorResource, resourceClassId, domainId);

      final Set<ResourcePermission> addPermissions = new HashSet<>(requestedResourcePermissions.size());
      final Set<ResourcePermission> updatePermissions = new HashSet<>(requestedResourcePermissions.size());

      for (ResourcePermission requestedPermission : requestedResourcePermissions) {
         boolean existingPermission = false;

         for (ResourcePermission existingDirectPermission : directAccessorPermissions) {
            if (requestedPermission.equalsIgnoreGrant(existingDirectPermission)) {
               // found a match by name - now let's check if we need to update existing or leave it unchanged
               if (!requestedPermission.equals(existingDirectPermission) &&
                     !requestedPermission.isGrantableFrom(existingDirectPermission)) {
                  // requested permission has higher granting rights than the already existing direct permission,
                  // so we need to update it
                  updatePermissions.add(requestedPermission);
               }

               existingPermission = true;
               break;
            }
         }

         if (!existingPermission) {
            // couldn't find requested permission in set of already existing direct permissions, by name, so we need to add it
            addPermissions.add(requestedPermission);
         }
      }

      // update any necessary direct system permissions between the accessor and the accessed resource
      grantGlobalResourcePermissionSysPersister.updateGlobalSysPermissions(connection,
                                                                           accessorResource,
                                                                           resourceClassId,
                                                                           domainId,
                                                                           updatePermissions,
                                                                           sessionResource);

      // update any necessary direct non-system permissions between the accessor and the accessed resource
      grantGlobalResourcePermissionPersister.updateGlobalResourcePermissions(connection,
                                                                             accessorResource,
                                                                             resourceClassId,
                                                                             domainId,
                                                                             updatePermissions,
                                                                             sessionResource);

      // add the new system permissions
      grantGlobalResourcePermissionSysPersister.addGlobalSysPermissions(connection,
                                                                        accessorResource,
                                                                        resourceClassId,
                                                                        domainId,
                                                                        addPermissions,
                                                                        sessionResource);

      // add the new non-system permissions
      grantGlobalResourcePermissionPersister.addGlobalResourcePermissions(connection,
                                                                          accessorResource,
                                                                          resourceClassId,
                                                                          domainId,
                                                                          addPermissions,
                                                                          sessionResource);
   }

   @Override
   public void revokeGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __revokeDirectGlobalPermissions(connection,
                                         accessorResource,
                                         resourceClassName,
                                         domainName,
                                         resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public void revokeGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         __revokeDirectGlobalPermissions(connection,
                                         accessorResource,
                                         resourceClassName,
                                         domainName,
                                         requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private void __revokeDirectGlobalPermissions(SQLConnection connection,
                                                Resource accessorResource,
                                                String resourceClassName,
                                                String domainName,
                                                Set<ResourcePermission> requestedResourcePermissions) {
      __assertResourceExists(connection, accessorResource);

      // verify that resource class is defined
      final ResourceClassInternalInfo resourceClassInfo = __getResourceClassInternalInfo(connection,
                                                                                         resourceClassName);

      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      // next ensure that the requested permissions are valid and unique in name
      __assertUniqueResourcePermissionsNamesForResourceClass(connection,
                                                             requestedResourcePermissions,
                                                             resourceClassInfo);

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      // check for authorization
      if (!__isSuperUserOfDomain(connection, sessionResource, domainName)) {
         final Set<ResourcePermission> grantorPermissions
               = __getEffectiveGlobalResourcePermissionsIgnoringSuperUserPrivileges(connection,
                                                                                    sessionResource,
                                                                                    resourceClassName,
                                                                                    domainName);

         final Set<ResourcePermission> unauthorizedPermissions
               = __subtractResourcePermissionsIfGrantableFrom(requestedResourcePermissions, grantorPermissions);

         if (unauthorizedPermissions.size() > 0) {
            throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                              "revoke the following global permission(s): " + unauthorizedPermissions);
         }
      }

      final Set<ResourcePermission> directAccessorPermissions
            = __getDirectGlobalResourcePermissions(connection, accessorResource, resourceClassId, domainId);

      final Set<ResourcePermission> removePermissions = new HashSet<>(requestedResourcePermissions.size());

      for (ResourcePermission requestedPermission : requestedResourcePermissions) {
         for (ResourcePermission existingDirectPermission : directAccessorPermissions) {
            if (requestedPermission.equalsIgnoreGrant(existingDirectPermission)) {
               // requested permission has same name and regardless of granting rights we need to remove it
               removePermissions.add(requestedPermission);
               break;
            }
         }
      }

      // remove any necessary direct system permissions
      grantGlobalResourcePermissionSysPersister.removeGlobalSysPermissions(connection,
                                                                           accessorResource,
                                                                           resourceClassId,
                                                                           domainId,
                                                                           removePermissions);

      // remove any necessary direct non-system permissions
      grantGlobalResourcePermissionPersister.removeGlobalResourcePermissions(connection,
                                                                             accessorResource,
                                                                             resourceClassId,
                                                                             domainId,
                                                                             removePermissions);
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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

   private Set<ResourcePermission> __getEffectiveGlobalResourcePermissionsIgnoringSuperUserPrivileges(SQLConnection connection,
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

   private Set<ResourcePermission> __getEffectiveGlobalResourcePermissions(SQLConnection connection,
                                                                           Resource accessorResource,
                                                                           String resourceClassName,
                                                                           String domainName) {
      // verify that resource class is defined
      final ResourceClassInternalInfo resourceClassInternalInfo = __getResourceClassInternalInfo(connection,
                                                                                                 resourceClassName);

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new IllegalArgumentException("Could not find domain: " + domainName);
      }

      if (__isSuperUserOfDomain(connection, accessorResource, domainName)) {
         return __getApplicableResourcePermissions(connection, resourceClassInternalInfo);
      }

      final Id<ResourceClassId> resourceClassId = Id.from(resourceClassInternalInfo.getResourceClassId());
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

   private Set<ResourcePermission> __getApplicableResourcePermissions(SQLConnection connection,
                                                                      ResourceClassInternalInfo resourceClassInternalInfo) {
      final List<String> resourcePermissionNames
            = __getApplicableResourcePermissionNames(connection, resourceClassInternalInfo);

      Set<ResourcePermission> superResourcePermissions = new HashSet<>(resourcePermissionNames.size());

      for (String permissionName : resourcePermissionNames) {
         superResourcePermissions.add(ResourcePermissions.getInstance(permissionName, true));
      }

      return superResourcePermissions;
   }

   private Set<ResourceCreatePermission> __getApplicableResourceCreatePermissions(SQLConnection connection,
                                                                                  ResourceClassInternalInfo resourceClassInternalInfo) {

      final List<String> resourcePermissionNames
            = __getApplicableResourcePermissionNames(connection, resourceClassInternalInfo);

      Set<ResourceCreatePermission> superResourceCreatePermissions = new HashSet<>(resourcePermissionNames.size()+1);

      superResourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));

      for (String permissionName : resourcePermissionNames) {
         superResourceCreatePermissions.add(ResourceCreatePermissions
                                                  .getInstance(ResourcePermissions
                                                                     .getInstance(permissionName, true),
                                                               true));
      }

      return superResourceCreatePermissions;
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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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
                                                                .getGlobalResourcePermissions(connection,
                                                                                              accessorResource),
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

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

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

      // finally, collect all applicable permissions when accessor has super-user privileges to any domain
      // and add them into the globalALLPermissionsMap
      final Map<String, Map<String, Set<ResourcePermission>>> superGlobalResourcePermissionsMap = new HashMap<>();
      Map<String, Set<ResourcePermission>> superResourcePermissionsMap = null;

      final Map<String, Set<DomainPermission>> effectiveDomainPermissionsMap
            = __getEffectiveDomainPermissionsMap(connection, accessorResource);

      for (String domainName : effectiveDomainPermissionsMap.keySet()) {
         final Set<DomainPermission> effectiveDomainPermissions = effectiveDomainPermissionsMap.get(domainName);
         if (effectiveDomainPermissions.contains(DomainPermission_SUPER_USER)
               || effectiveDomainPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {

            if (superResourcePermissionsMap == null) {
               // lazy-construct super-user-privileged resource-permissions map by resource classes
               final List<String> resourceClassNames = resourceClassPersister.getResourceClassNames(connection);
               superResourcePermissionsMap = new HashMap<>(resourceClassNames.size());
               for (String resourceClassName : resourceClassNames) {
                  final Set<ResourcePermission> applicableResourcePermissions
                        = __getApplicableResourcePermissions(connection,
                                                             __getResourceClassInternalInfo(connection,
                                                                                            resourceClassName));

                  superResourcePermissionsMap.put(resourceClassName, applicableResourcePermissions);
               }
            }
            superGlobalResourcePermissionsMap.put(domainName, superResourcePermissionsMap);
         }
      }

      __mergeSourcePermissionsMapIntoTargetPermissionsMap(superGlobalResourcePermissionsMap, globalALLPermissionsMap);

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

      if (sessionResource.equals(resource)) {
         return sessionResourceDomainName;
      }
      else {
         try {
            connection = __getConnection();

            return domainPersister.getResourceDomainNameByResourceId(connection, resource);
         }
         finally {
            __closeConnection(connection);
         }
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

         final ResourceClassInternalInfo resourceClassInternalInfo = __getResourceClassInternalInfo(connection,
                                                                                                    resourceClassName);

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
   public void assertPostCreateDomainPermissions(Resource accessorResource,
                                                 Set<DomainPermission> domainPermissions) {
      if (!hasPostCreateDomainPermissions(accessorResource, domainPermissions)) {
         throw NotAuthorizedException.newInstanceForPostCreateDomainPermissions(accessorResource,
                                                                                domainPermissions);
      }
   }

   @Override
   public void assertPostCreateDomainPermissions(Resource accessorResource,
                                                 DomainPermission domainPermission,
                                                 DomainPermission... domainPermissions) {
      if (!hasPostCreateDomainPermissions(accessorResource, domainPermission, domainPermissions)) {
         throw NotAuthorizedException.newInstanceForPostCreateDomainPermissions(accessorResource,
                                                                                domainPermission,
                                                                                domainPermissions);
      }
   }

   @Override
   public boolean hasPostCreateDomainPermissions(Resource accessorResource,
                                                 Set<DomainPermission> domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionsSpecified(domainPermissions);
      __assertPermissionsSetNotEmpty(domainPermissions);

      try {
         connection = __getConnection();
         return __hasPostCreateDomainPermissions(connection, accessorResource, domainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public boolean hasPostCreateDomainPermissions(Resource accessorResource,
                                                 DomainPermission domainPermission,
                                                 DomainPermission... domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionSpecified(domainPermission);
      __assertVarargPermissionsSpecified(domainPermissions);

      final Set<DomainPermission> requestedDomainPermissions = __getSetWithoutNullsOrDuplicates(domainPermission,
                                                                                                domainPermissions);

      try {
         connection = __getConnection();
         return __hasPostCreateDomainPermissions(connection,
                                                 accessorResource,
                                                 requestedDomainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasPostCreateDomainPermissions(SQLConnection connection,
                                                    Resource accessorResource,
                                                    Set<DomainPermission> requestedDomainPermissions) {
      __assertResourceExists(connection, accessorResource);
      __assertQueryAuthorization(connection, accessorResource);

      boolean hasPermission = false;

      // first check if the accessor even has *CREATE permission for domains
      final Set<DomainCreatePermission> effectiveDomainCreatePermissions
            = __getEffectiveDomainCreatePermissions(connection, accessorResource);

      for (DomainCreatePermission domainCreatePermission : effectiveDomainCreatePermissions) {
         if (domainCreatePermission.isSystemPermission()
               && DomainCreatePermissions.CREATE.equals(domainCreatePermission.getPermissionName())) {
            hasPermission = true;
            break;
         }
      }

      if (hasPermission) {
         // check if the requested permissions are permissible from the set of effective post-create permissions
         final Set<DomainPermission> postCreateDomainPermissions
               = __getPostCreateDomainPermissions(effectiveDomainCreatePermissions);

         for (DomainPermission requestedDomainPermission : requestedDomainPermissions) {
            if (!__isPermissible(requestedDomainPermission, postCreateDomainPermissions)) {
               hasPermission = false;
               break;
            }
         }

         if (!hasPermission) {
            hasPermission = postCreateDomainPermissions.contains(DomainPermission_SUPER_USER)
                  || postCreateDomainPermissions.contains(DomainPermission_SUPER_USER_GRANT);
         }
      }
      return hasPermission;
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
   public void assertDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       Set<DomainPermission> domainPermissions) {
      if (!hasDomainPermissions(accessorResource, domainName, domainPermissions)) {
         throw NotAuthorizedException.newInstanceForDomainPermissions(accessorResource,
                                                                      domainName,
                                                                      domainPermissions);
      }
   }

   @Override
   public void assertDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      if (!hasDomainPermissions(accessorResource, domainName, domainPermission, domainPermissions)) {
         throw NotAuthorizedException.newInstanceForDomainPermissions(accessorResource,
                                                                      domainName,
                                                                      domainPermission,
                                                                      domainPermissions);
      }
   }

   @Override
   public boolean hasDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       Set<DomainPermission> domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(domainPermissions);
      __assertPermissionsSetNotEmpty(domainPermissions);

      try {
         connection = __getConnection();

         return __hasDomainPermissions(connection, accessorResource, domainName, domainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public boolean hasDomainPermissions(Resource accessorResource,
                                       String domainName,
                                       DomainPermission domainPermission,
                                       DomainPermission... domainPermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(domainPermission);
      __assertVarargPermissionsSpecified(domainPermissions);

      final Set<DomainPermission> requestedDomainPermissions = __getSetWithoutNullsOrDuplicates(domainPermission,
                                                                                                domainPermissions);

      try {
         connection = __getConnection();

         return __hasDomainPermissions(connection, accessorResource, domainName, requestedDomainPermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasDomainPermissions(SQLConnection connection,
                                          Resource accessorResource,
                                          String domainName,
                                          Set<DomainPermission> requestedDomainPermissions) {
      __assertResourceExists(connection, accessorResource);
      __assertQueryAuthorization(connection, accessorResource);

      // first check for effective permissions
      final Set<DomainPermission> effectiveDomainPermissions = __getEffectiveDomainPermissions(connection,
                                                                                               accessorResource,
                                                                                               domainName);
      boolean hasPermission = true;

      for (DomainPermission domainPermission : requestedDomainPermissions) {
         if (!__isPermissible(domainPermission, effectiveDomainPermissions)) {
            hasPermission = false;
            break;
         }
      }

      // next check super-user permissions to the domain of the accessed resource
      if (!hasPermission) {
         hasPermission = __isSuperUserOfDomain(connection, accessorResource, domainName);
      }

      return hasPermission;
   }

   @Override
   public void assertDomainCreatePermissions(Resource accessorResource,
                                             Set<DomainCreatePermission> domainCreatePermissions) {
      if (!hasDomainCreatePermissions(accessorResource, domainCreatePermissions)) {
         throw NotAuthorizedException.newInstanceForDomainCreatePermissions(accessorResource,
                                                                            domainCreatePermissions);
      }
   }

   @Override
   public void assertDomainCreatePermissions(Resource accessorResource,
                                             DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      if (!hasDomainCreatePermissions(accessorResource, domainCreatePermission, domainCreatePermissions)) {
         throw NotAuthorizedException.newInstanceForDomainCreatePermissions(accessorResource,
                                                                            domainCreatePermission,
                                                                            domainCreatePermissions);
      }
   }

   @Override
   public boolean hasDomainCreatePermissions(Resource accessorResource,
                                             Set<DomainCreatePermission> domainCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionsSpecified(domainCreatePermissions);
      __assertPermissionsSetNotEmpty(domainCreatePermissions);

      try {
         connection = __getConnection();

         return __hasDomainCreatePermissions(connection, accessorResource, domainCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public boolean hasDomainCreatePermissions(Resource accessorResource,
                                             DomainCreatePermission domainCreatePermission,
                                             DomainCreatePermission... domainCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertPermissionSpecified(domainCreatePermission);
      __assertVarargPermissionsSpecified(domainCreatePermissions);

      final Set<DomainCreatePermission> requestedDomainCreatePermissions
            = __getSetWithoutNullsOrDuplicates(domainCreatePermission, domainCreatePermissions);

      try {
         connection = __getConnection();

         return __hasDomainCreatePermissions(connection, accessorResource, requestedDomainCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasDomainCreatePermissions(SQLConnection connection,
                                                Resource accessorResource,
                                                Set<DomainCreatePermission> queriedDomainCreatePermissions) {
      __assertResourceExists(connection, accessorResource);
      __assertQueryAuthorization(connection, accessorResource);

      final Set<DomainCreatePermission> effectiveDomainCreatePermissions
            = __getEffectiveDomainCreatePermissions(connection, accessorResource);

      for (DomainCreatePermission domainCreatePermission : queriedDomainCreatePermissions) {
         if (!__isPermissible(domainCreatePermission, effectiveDomainCreatePermissions)) {
            return false;
         }
      }

      return true;
   }

   private boolean __isPermissible(DomainCreatePermission queriedDomainCreatePermission,
                                   Set<DomainCreatePermission> domainCreatePermissions) {
      for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
         if (queriedDomainCreatePermission.equals(domainCreatePermission)
               || queriedDomainCreatePermission.isGrantableFrom(domainCreatePermission)) {
            return true;
         }
      }
      return false;
   }

   @Override
   public void assertPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   String domainName,
                                                   Set<ResourcePermission> resourcePermissions) {
      if (!hasPostCreateResourcePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            resourcePermissions)) {
         throw NotAuthorizedException.newInstanceForPostCreateResourcePermissions(accessorResource,
                                                                                  resourceClassName,
                                                                                  domainName,
                                                                                  resourcePermissions);
      }
   }

   @Override
   public void assertPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   String domainName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      if (!hasPostCreateResourcePermissions(accessorResource,
                                            resourceClassName,
                                            domainName,
                                            resourcePermission,
                                            resourcePermissions)) {
         throw NotAuthorizedException.newInstanceForPostCreateResourcePermissions(accessorResource,
                                                                                  resourceClassName,
                                                                                  domainName,
                                                                                  resourcePermission,
                                                                                  resourcePermissions);
      }
   }

   @Override
   public boolean hasPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   String domainName,
                                                   Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __hasPostCreateResourcePermissions(connection,
                                                   accessorResource,
                                                   resourceClassName,
                                                   domainName,
                                                   resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public boolean hasPostCreateResourcePermissions(Resource accessorResource,
                                                   String resourceClassName,
                                                   String domainName,
                                                   ResourcePermission resourcePermission,
                                                   ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __hasPostCreateResourcePermissions(connection,
                                                   accessorResource,
                                                   resourceClassName,
                                                   domainName,
                                                   requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasPostCreateResourcePermissions(SQLConnection connection,
                                                      Resource accessorResource,
                                                      String resourceClassName,
                                                      String domainName,
                                                      Set<ResourcePermission> requestedResourcePermissions) {
      __assertResourceExists(connection, accessorResource);
      __assertPermissionsValid(connection, resourceClassName, requestedResourcePermissions);
      __assertQueryAuthorization(connection, accessorResource);

      boolean hasPermission = false;

      // first check if the accessor even has *CREATE permission for the resource class and domain
      final Set<ResourceCreatePermission> effectiveResourceCreatePermissions
            = __getEffectiveResourceCreatePermissions(connection,
                                                      accessorResource,
                                                      resourceClassName,
                                                      domainName);

      for (ResourceCreatePermission resourceCreatePermission : effectiveResourceCreatePermissions) {
         if (resourceCreatePermission.isSystemPermission()
               && ResourceCreatePermissions.CREATE.equals(resourceCreatePermission.getPermissionName())) {
            hasPermission = true;
            break;
         }
      }

      if (hasPermission) {
         // check if the requested permission is permissible from the set of effective post-create permissions
         final Set<ResourcePermission> postCreateResourcePermissions
               = __getPostCreateResourcePermissions(effectiveResourceCreatePermissions);

         final Set<ResourcePermission> nonPostCreateResourcePermissions
               = new HashSet<>(requestedResourcePermissions.size());

         for (ResourcePermission requestedResourcePermission : requestedResourcePermissions) {
            if (!__isPermissible(requestedResourcePermission, postCreateResourcePermissions)) {
               nonPostCreateResourcePermissions.add(requestedResourcePermission);
            }
         }

         if (!nonPostCreateResourcePermissions.isEmpty()) {
            // check if the requested permission is permissible from the set of effective global permissions
            final Set<ResourcePermission> globalResourcePermissions
                  = __getEffectiveGlobalResourcePermissions(connection,
                                                            accessorResource,
                                                            resourceClassName,
                                                            domainName);

            for (ResourcePermission requestedResourcePermission : nonPostCreateResourcePermissions) {
               if (!__isPermissible(requestedResourcePermission, globalResourcePermissions)) {
                  hasPermission = false;
                  break;
               }
            }
         }
      }

      if (!hasPermission) {
         hasPermission = __isSuperUserOfDomain(connection, accessorResource, domainName);
      }

      return hasPermission;
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
   public void assertGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               Set<ResourcePermission> resourcePermissions) {
      if (!hasGlobalResourcePermissions(accessorResource,
                                        resourceClassName,
                                        domainName,
                                        resourcePermissions)) {
         throw NotAuthorizedException.newInstanceForGlobalResourcePermissions(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              resourcePermissions);
      }
   }

   @Override
   public void assertGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      if (!hasGlobalResourcePermissions(accessorResource,
                                        resourceClassName,
                                        domainName,
                                        resourcePermission,
                                        resourcePermissions)) {
         throw NotAuthorizedException.newInstanceForGlobalResourcePermissions(accessorResource,
                                                                              resourceClassName,
                                                                              domainName,
                                                                              resourcePermission,
                                                                              resourcePermissions);
      }
   }

   @Override
   public boolean hasGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __hasGlobalResourcePermissions(connection,
                                               accessorResource,
                                               resourceClassName,
                                               domainName,
                                               resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public boolean hasGlobalResourcePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourcePermission resourcePermission,
                                               ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();
         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __hasGlobalResourcePermissions(connection,
                                               accessorResource,
                                               resourceClassName,
                                               domainName,
                                               requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasGlobalResourcePermissions(SQLConnection connection,
                                                  Resource accessorResource,
                                                  String resourceClassName,
                                                  String domainName,
                                                  Set<ResourcePermission> requestedResourcePermissions) {
      __assertResourceExists(connection, accessorResource);
      __assertPermissionsValid(connection, resourceClassName, requestedResourcePermissions);
      __assertQueryAuthorization(connection, accessorResource);

      final Set<ResourcePermission>
            globalResourcePermissions = __getEffectiveGlobalResourcePermissions(connection,
                                                                                accessorResource,
                                                                                resourceClassName,
                                                                                domainName);
      boolean hasPermission = true;

      for (ResourcePermission requestedResourcePermission : requestedResourcePermissions) {
         if (!__isPermissible(requestedResourcePermission, globalResourcePermissions)) {
            hasPermission = false;
            break;
         }
      }

      if (!hasPermission) {
         hasPermission = __isSuperUserOfDomain(connection, accessorResource, domainName);
      }
      return hasPermission;
   }

   @Override
   public void assertResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         Set<ResourcePermission> resourcePermissions) {
      if (!hasResourcePermissions(accessorResource, accessedResource, resourcePermissions)) {
         throw NotAuthorizedException.newInstanceForResourcePermissions(accessorResource,
                                                                        accessedResource,
                                                                        resourcePermissions);
      }
   }

   @Override
   public void assertResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      if (!hasResourcePermissions(accessorResource, accessedResource, resourcePermission, resourcePermissions)) {
         throw NotAuthorizedException.newInstanceForResourcePermissions(accessorResource,
                                                                        accessedResource,
                                                                        resourcePermission,
                                                                        resourcePermissions);
      }
   }

   @Override
   public boolean hasResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();

         return __hasResourcePermissions(connection, accessorResource, accessedResource, resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public boolean hasResourcePermissions(Resource accessorResource,
                                         Resource accessedResource,
                                         ResourcePermission resourcePermission,
                                         ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceSpecified(accessedResource);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();

         return __hasResourcePermissions(connection, accessorResource, accessedResource, requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasResourcePermissions(SQLConnection connection,
                                            Resource accessorResource,
                                            Resource accessedResource,
                                            Set<ResourcePermission> requestedResourcePermissions) {
      __assertResourceExists(connection, accessorResource);
      __assertQueryAuthorization(connection, accessorResource);

      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfoByResourceId(connection, accessedResource);
      __assertPermissionsValid(connection,
                               resourceClassInternalInfo.getResourceClassName(),
                               requestedResourcePermissions);

      // first check for effective permissions
      final Set<ResourcePermission> effectiveResourcePermissions
            = __getEffectiveResourcePermissions(connection,
                                                accessorResource,
                                                accessedResource);

      boolean hasPermission = true;

      for (ResourcePermission requestedResourcePermission : requestedResourcePermissions) {
         if (!__isPermissible(requestedResourcePermission, effectiveResourcePermissions)) {
            hasPermission = false;
            break;
         }
      }

      // next check super-user permissions to the domain of the accessed resource
      if (!hasPermission) {
         final String domainName
               = domainPersister.getResourceDomainNameByResourceId(connection, accessedResource);

         hasPermission = __isSuperUserOfDomain(connection, accessorResource, domainName);
      }

      return hasPermission;
   }

   @Override
   public void assertResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               Set<ResourceCreatePermission> resourceCreatePermissions) {
      if (!hasResourceCreatePermissions(accessorResource,
                                        resourceClassName,
                                        domainName,
                                        resourceCreatePermissions)) {
         throw NotAuthorizedException.newInstanceForResourceCreatePermissions(accessorResource,
                                                                              resourceCreatePermissions);
      }
   }

   @Override
   public void assertResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      if (!hasResourceCreatePermissions(accessorResource,
                                        resourceClassName,
                                        domainName,
                                        resourceCreatePermission,
                                        resourceCreatePermissions)) {
         throw NotAuthorizedException.newInstanceForResourceCreatePermissions(accessorResource,
                                                                              resourceCreatePermission,
                                                                              resourceCreatePermissions);
      }
   }

   @Override
   public boolean hasResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               Set<ResourceCreatePermission> resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourceCreatePermissions);
      __assertPermissionsSetNotEmpty(resourceCreatePermissions);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __hasResourceCreatePermissions(connection,
                                               accessorResource,
                                               resourceClassName,
                                               domainName,
                                               resourceCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public boolean hasResourceCreatePermissions(Resource accessorResource,
                                               String resourceClassName,
                                               String domainName,
                                               ResourceCreatePermission resourceCreatePermission,
                                               ResourceCreatePermission... resourceCreatePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourceCreatePermission);
      __assertVarargPermissionsSpecified(resourceCreatePermissions);

      final Set<ResourceCreatePermission> requestedResourceCreatePermissions
            = __getSetWithoutNullsOrDuplicates(resourceCreatePermission, resourceCreatePermissions);

      try {
         connection = __getConnection();

         resourceClassName = resourceClassName.trim();
         domainName = domainName.trim();

         return __hasResourceCreatePermissions(connection,
                                               accessorResource,
                                               resourceClassName,
                                               domainName,
                                               requestedResourceCreatePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private boolean __hasResourceCreatePermissions(SQLConnection connection,
                                                  Resource accessorResource,
                                                  String resourceClassName,
                                                  String domainName,
                                                  Set<ResourceCreatePermission> requestedResourceCreatePermissions) {
      __assertResourceExists(connection, accessorResource);
      __assertPermissionsValid(connection,
                               resourceClassName,
                               __getPostCreateResourcePermissions(requestedResourceCreatePermissions));
      __assertQueryAuthorization(connection, accessorResource);

      final Set<ResourceCreatePermission> effectiveResourceCreatePermissions
            = __getEffectiveResourceCreatePermissions(connection,
                                                      accessorResource,
                                                      resourceClassName,
                                                      domainName);
      boolean hasPermission = true;

      // first check for effective create permissions
      for (ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
         if (!__isPermissible(resourceCreatePermission, effectiveResourceCreatePermissions)) {
            hasPermission = false;
            break;
         }
      }

      // next check super-user permissions to the domain
      if (!hasPermission) {
         hasPermission = __isSuperUserOfDomain(connection, accessorResource, domainName);
      }

      return hasPermission;
   }

   private boolean __isPermissible(ResourceCreatePermission queriedResourceCreatePermission,
                                   Set<ResourceCreatePermission> resourceCreatePermissions) {
      for (ResourceCreatePermission resourceCreatePermission : resourceCreatePermissions) {
         if (queriedResourceCreatePermission.equals(resourceCreatePermission)
               || queriedResourceCreatePermission.isGrantableFrom(resourceCreatePermission)) {
            return true;
         }
      }
      return false;
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissions(Resource accessorResource,
                                                          String resourceClassName,
                                                          Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

         resourceClassName = resourceClassName.trim();

         return __getResourcesByPermissions(connection,
                                            accessorResource,
                                            resourceClassName,
                                            resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissions(Resource accessorResource,
                                                          String resourceClassName,
                                                          ResourcePermission resourcePermission,
                                                          ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

         resourceClassName = resourceClassName.trim();

         return __getResourcesByPermissions(connection,
                                            accessorResource,
                                            resourceClassName,
                                            requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<Resource> __getResourcesByPermissions(SQLConnection connection,
                                                     Resource accessorResource,
                                                     String resourceClassName,
                                                     Set<ResourcePermission> requestedResourcePermissions) {
      // first verify that resource class is defined
      Id<ResourceClassId> resourceClassId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      // verify permissions are valid for resource class
      __assertPermissionsValid(connection, resourceClassName, requestedResourcePermissions);

      Set<Resource> resources = new HashSet<>();

      for (ResourcePermission resourcePermission : requestedResourcePermissions) {
         Set<Resource> currentResources = new HashSet<>();

         if (resourcePermission.isSystemPermission()) {
            // get the list of objects of the specified type that the session has access to via direct permissions
            currentResources.addAll(grantResourcePermissionSysPersister
                                          .getResourcesByResourceSysPermission(connection,
                                                                               accessorResource,
                                                                               resourceClassId,
                                                                               resourcePermission));

            // get the list of objects of the specified type that the session has access to via global permissions
            currentResources.addAll(grantGlobalResourcePermissionSysPersister
                                          .getResourcesByGlobalSysPermission(connection,
                                                                             accessorResource,
                                                                             resourceClassId,
                                                                             resourcePermission));
         }
         else {
            // check if the non-system permission name is valid
            permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection,
                                                                                         resourceClassId,
                                                                                         resourcePermission
                                                                                               .getPermissionName());

            if (permissionId == null) {
               throw new IllegalArgumentException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
            }

            // get the list of objects of the specified type that the session has access to via direct permissions
            currentResources.addAll(grantResourcePermissionPersister
                                          .getResourcesByResourcePermission(connection,
                                                                            accessorResource,
                                                                            resourceClassId,
                                                                            resourcePermission,
                                                                            permissionId));

            // get the list of objects of the specified type that the session has access to via global permissions
            currentResources.addAll(grantGlobalResourcePermissionPersister
                                          .getResourcesByGlobalResourcePermission(connection,
                                                                                  accessorResource,
                                                                                  resourceClassId,
                                                                                  resourcePermission,
                                                                                  permissionId));
         }

         if (currentResources.isEmpty()) {
            // we got an empty set for a permission, we are done since this and all future intersects will be empty
            resources = currentResources;
            break;
         }
         else {
            // the only way resources will be empty below is if we never entered this else clause before
            if (resources.isEmpty()) {
               resources = currentResources;
            }
            else {
               // compute the intersection of previous iterations and the current resources
               resources.retainAll(currentResources);
               if (resources.isEmpty()) {
                  // if intersection with previous results is empty, then all future intersections will be empty, as well
                  break;
               }
            }
         }
      }

      // finally get the list of objects of the specified type that the session has access to via super user permissions
      resources.addAll(grantDomainPermissionSysPersister.getResourcesByDomainSuperUserPermission(connection,
                                                                                                 accessorResource,
                                                                                                 resourceClassId));
      return resources;
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissionsAndDomain(Resource accessorResource,
                                                                   String resourceClassName,
                                                                   String domainName,
                                                                   Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

         resourceClassName = resourceClassName.trim();

         return __getResourcesByPermissionsAndDomain(connection,
                                                     accessorResource,
                                                     resourceClassName,
                                                     domainName,
                                                     resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<Resource> getResourcesByResourcePermissionsAndDomain(Resource accessorResource,
                                                                   String resourceClassName,
                                                                   String domainName,
                                                                   ResourcePermission resourcePermission,
                                                                   ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessorResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertDomainSpecified(domainName);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessorResource);
         __assertQueryAuthorization(connection, accessorResource);

         resourceClassName = resourceClassName.trim();

         return __getResourcesByPermissionsAndDomain(connection,
                                                     accessorResource,
                                                     resourceClassName,
                                                     domainName,
                                                     requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<Resource> __getResourcesByPermissionsAndDomain(SQLConnection connection,
                                                              Resource accessorResource,
                                                              String resourceClassName,
                                                              String domainName,
                                                              Set<ResourcePermission> requestedResourcePermissions) {
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

      // verify permissions are valid for resource class
      __assertPermissionsValid(connection, resourceClassName, requestedResourcePermissions);

      Set<Resource> resources = new HashSet<>();

      for (ResourcePermission resourcePermission : requestedResourcePermissions) {
         Set<Resource> currentResources = new HashSet<>();

         if (resourcePermission.isSystemPermission()) {
            // get the list of objects of the specified type that the session has access to via direct permissions
            currentResources.addAll(grantResourcePermissionSysPersister
                                          .getResourcesByResourceSysPermission(connection,
                                                                               accessorResource,
                                                                               resourceClassId,
                                                                               domainId,
                                                                               resourcePermission));

            // get the list of objects of the specified type that the session has access to via global permissions
            currentResources.addAll(grantGlobalResourcePermissionSysPersister
                                          .getResourcesByGlobalSysPermission(connection,
                                                                             accessorResource,
                                                                             resourceClassId,
                                                                             domainId,
                                                                             resourcePermission));
         }
         else {
            // check if the non-system permission name is valid
            permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection,
                                                                                         resourceClassId,
                                                                                         resourcePermission
                                                                                               .getPermissionName());

            if (permissionId == null) {
               throw new IllegalArgumentException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
            }

            // get the list of objects of the specified type that the session has access to via direct permissions
            currentResources.addAll(grantResourcePermissionPersister
                                          .getResourcesByResourcePermission(connection,
                                                                            accessorResource,
                                                                            resourceClassId,
                                                                            domainId,
                                                                            resourcePermission,
                                                                            permissionId));

            // get the list of objects of the specified type that the session has access to via global permissions
            currentResources.addAll(grantGlobalResourcePermissionPersister
                                          .getResourcesByGlobalResourcePermission(connection,
                                                                                  accessorResource,
                                                                                  resourceClassId,
                                                                                  domainId,
                                                                                  resourcePermission,
                                                                                  permissionId));
         }
         if (currentResources.isEmpty()) {
            // we got an empty set for a permission, we are done since this and all future intersects will be empty
            resources = currentResources;
            break;
         }
         else {
            // the only way resources will be empty below is if we never entered this else clause before
            if (resources.isEmpty()) {
               resources = currentResources;
            }
            else {
               // compute the intersection of previous iterations and the current resources
               resources.retainAll(currentResources);
               if (resources.isEmpty()) {
                  // if intersection with previous results is empty, then all future intersections will be empty, as well
                  break;
               }
            }
         }
      }

      // finally get the list of objects of the specified type that the session has access to via super user permissions
      resources.addAll(grantDomainPermissionSysPersister.getResourcesByDomainSuperUserPermission(connection,
                                                                                                 accessorResource,
                                                                                                 resourceClassId,
                                                                                                 domainId));
      return resources;
   }

   @Override
   public Set<Resource> getAccessorResourcesByResourcePermissions(Resource accessedResource,
                                                                  String resourceClassName,
                                                                  Set<ResourcePermission> resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessedResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionsSpecified(resourcePermissions);
      __assertPermissionsSetNotEmpty(resourcePermissions);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessedResource);
         __assertQueryAuthorization(connection, accessedResource);

         resourceClassName = resourceClassName.trim();

         return __getAccessorResourcesByResourcePermissions(connection,
                                                            accessedResource,
                                                            resourceClassName,
                                                            resourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   @Override
   public Set<Resource> getAccessorResourcesByResourcePermissions(Resource accessedResource,
                                                                  String resourceClassName,
                                                                  ResourcePermission resourcePermission,
                                                                  ResourcePermission... resourcePermissions) {
      SQLConnection connection = null;

      __assertAuthenticated();
      __assertResourceSpecified(accessedResource);
      __assertResourceClassSpecified(resourceClassName);
      __assertPermissionSpecified(resourcePermission);
      __assertVarargPermissionsSpecified(resourcePermissions);

      final Set<ResourcePermission> requestedResourcePermissions
            = __getSetWithoutNullsOrDuplicates(resourcePermission, resourcePermissions);

      try {
         connection = __getConnection();

         __assertResourceExists(connection, accessedResource);
         __assertQueryAuthorization(connection, accessedResource);

         resourceClassName = resourceClassName.trim();

         return __getAccessorResourcesByResourcePermissions(connection,
                                                            accessedResource,
                                                            resourceClassName,
                                                            requestedResourcePermissions);
      }
      finally {
         __closeConnection(connection);
      }
   }

   private Set<Resource> __getAccessorResourcesByResourcePermissions(SQLConnection connection,
                                                                     Resource accessedResource,
                                                                     String resourceClassName,
                                                                     Set<ResourcePermission> requestedResourcePermissions) {
      // first verify that resource class is defined
      Id<ResourceClassId> resourceClassId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      // verify permissions are valid for the resource class
      __assertPermissionsValid(connection, resourceClassName, requestedResourcePermissions);

      Set<Resource> resources = new HashSet<>();

      for (ResourcePermission resourcePermission : requestedResourcePermissions) {
         Set<Resource> currentResources = new HashSet<>();

         if (resourcePermission.isSystemPermission()) {
            // get the list of objects of the specified type that the session has access to via direct permissions
            currentResources.addAll(grantResourcePermissionSysPersister
                                          .getAccessorResourcesByResourceSysPermission(connection,
                                                                                       accessedResource,
                                                                                       resourceClassId,
                                                                                       resourcePermission));
         }
         else {
            // check if the non-system permission name is valid
            permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection,
                                                                                         resourceClassId,
                                                                                         resourcePermission
                                                                                               .getPermissionName());

            if (permissionId == null) {
               throw new IllegalArgumentException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
            }

            // get the list of objects of the specified type that the session has access to via direct permissions
            currentResources.addAll(grantResourcePermissionPersister
                                          .getAccessorResourcesByResourcePermission(connection,
                                                                                    accessedResource,
                                                                                    resourceClassId,
                                                                                    resourcePermission,
                                                                                    permissionId));
         }
         if (currentResources.isEmpty()) {
            // we got an empty set for a permission, we are done since this and all future intersects will be empty
            resources = currentResources;
            break;
         }
         else {
            // the only way resources will be empty below is if we never entered this else clause before
            if (resources.isEmpty()) {
               resources = currentResources;
            }
            else {
               // compute the intersection of previous iterations and the current resources
               resources.retainAll(currentResources);
               if (resources.isEmpty()) {
                  // if intersection with previous results is empty, then all future intersections will be empty, as well
                  break;
               }
            }
         }
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

         return __getApplicableResourcePermissionNames(connection, resourceClassName);
      }
      finally {
         __closeConnection(connection);
      }
   }

   // private shared helper methods

   private List<String> __getApplicableResourcePermissionNames(SQLConnection connection,
                                                               String resourceClassName) {
      return __getApplicableResourcePermissionNames(connection,
                                                    __getResourceClassInternalInfo(connection, resourceClassName));
   }

   private List<String> __getApplicableResourcePermissionNames(SQLConnection connection,
                                                               ResourceClassInternalInfo resourceClassInternalInfo) {
      final List<String> permissionNames
            = resourceClassPermissionPersister.getPermissionNames(connection,
                                                                  resourceClassInternalInfo.getResourceClassName());
      permissionNames.add(ResourcePermissions.INHERIT);
      permissionNames.add(ResourcePermissions.DELETE);
      permissionNames.add(ResourcePermissions.QUERY);

      if (resourceClassInternalInfo.isAuthenticatable()) {
         permissionNames.add(ResourcePermissions.IMPERSONATE);
         permissionNames.add(ResourcePermissions.RESET_CREDENTIALS);
      }
      return permissionNames;
   }

   private ResourceClassInternalInfo __getResourceClassInternalInfo(SQLConnection connection,
                                                                    String resourceClassName) {
      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);

      // check if the resource class is valid
      if (resourceClassInternalInfo == null) {
         throw new IllegalArgumentException("Could not find resource class: " + resourceClassName);
      }

      return resourceClassInternalInfo;
   }

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

   private boolean __isSuperUserOfDomain(SQLConnection connection,
                                         Resource accessorResource,
                                         Id<DomainId> queriedDomainId) {
      Set<DomainPermission> domainPermissions = __getEffectiveDomainPermissions(connection,
                                                                                accessorResource,
                                                                                queriedDomainId);

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
         throw NotAuthorizedException.newInstanceForAction(sessionResource,
                                                           "perform operation reserved for the system resource");
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

   private void __assertVarargPermissionsSpecified(ResourcePermission... resourcePermissions) {
      if (resourcePermissions == null) {
         throw new NullPointerException("An array or a sequence of resource permissions are required, but the null value was specified");
      }
   }

   private void __assertPermissionSpecified(ResourceCreatePermission resourceCreatePermission) {
      if (resourceCreatePermission == null) {
         throw new NullPointerException("Resource create permission required, none specified");
      }
   }

   private void __assertVarargPermissionsSpecified(ResourceCreatePermission... resourceCreatePermissions) {
      if (resourceCreatePermissions == null) {
         throw new NullPointerException("An array or a sequence of resource create permissions are required, but the null value was specified");
      }
   }

   private void __assertPermissionSpecified(DomainCreatePermission domainCreatePermission) {
      if (domainCreatePermission == null) {
         throw new NullPointerException("Domain create permission required, none specified");
      }
   }

   private void __assertVarargPermissionsSpecified(DomainCreatePermission... domainCreatePermissions) {
      if (domainCreatePermissions == null) {
         throw new NullPointerException("An array or a sequence of domain create permissions are required, but the null value was specified");
      }
   }

   private void __assertPermissionSpecified(DomainPermission domainPermission) {
      if (domainPermission == null) {
         throw new NullPointerException("Domain permission required, none specified");
      }
   }

   private void __assertVarargPermissionsSpecified(DomainPermission... domainPermissions) {
      if (domainPermissions == null) {
         throw new NullPointerException("An array or a sequence of domain permissions are required, but the null value was specified");
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

   private void __assertPermissionsSetNotEmpty(Set permissionSet) {
      if (permissionSet.isEmpty()) {
         throw new IllegalArgumentException("Set of permissions required, empty set specified");
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

   private void __assertPermissionsValid(SQLConnection connection,
                                         String resourceClassName,
                                         Set<ResourcePermission> resourcePermissions) {
      final List<String> permissionNames = __getApplicableResourcePermissionNames(connection, resourceClassName);

      for (ResourcePermission resourcePermission : resourcePermissions) {
         if (!permissionNames.contains(resourcePermission.getPermissionName())) {
            if (resourcePermission.isSystemPermission()) {
               // currently the only invalid system permissions are for unauthenticatable resource classes
               throw new IllegalArgumentException("Permission "
                                                        + resourcePermission.getPermissionName()
                                                        + " not valid for unauthenticatable resource class "
                                                        + resourceClassName);
            }
            else {
               throw new IllegalArgumentException("Permission: "
                                                        + resourcePermission.getPermissionName()
                                                        + " is not defined for resource class: "
                                                        + resourceClassName);
            }
         }
      }
   }

   private void __assertResourceExists(SQLConnection connection,
                                       Resource resource) {
      // look up resource, but only if it's not the session or authenticated resource (which are already known to exist)
      if (!sessionResource.equals(resource) && !authenticatedResource.equals(resource)) {
         // the persister method will throw an IllegalArgumentException if the lookup fails
         resourcePersister.verifyResourceExists(connection, resource);
      }
   }

   private void __assertQueryAuthorization(SQLConnection connection,
                                           Resource accessorResource) {
      if (!sessionResource.equals(accessorResource)) {
         final Set<ResourcePermission> effectiveResourcePermissions = __getEffectiveResourcePermissions(connection,
                                                                                                        sessionResource,
                                                                                                        accessorResource);
         if (!effectiveResourcePermissions.contains(ResourcePermission_QUERY)
               && !effectiveResourcePermissions.contains(ResourcePermission_QUERY_GRANT)
               && !effectiveResourcePermissions.contains(ResourcePermission_IMPERSONATE)
               && !effectiveResourcePermissions.contains(ResourcePermission_IMPERSONATE_GRANT)) {
            throw NotAuthorizedException.newInstanceForActionOnResource(sessionResource,
                                                                        "query",
                                                                        accessorResource);
         }
      }
   }

   @SafeVarargs
   private static <T> Set<T> __getSetWithoutNullsOrDuplicates(T firstElement, T... elements) {
      // not null constraint
      if (elements == null) {
         throw new NullPointerException("An array or a sequence of arguments are required, but none were specified");
      }

      final HashSet<T> resultSet = new HashSet<>(elements.length + 1);
      resultSet.add(firstElement);

      for (T element : elements) {
         // non-null elements constraint
         if (element == null) {
            throw new NullPointerException("A " + elements.getClass().getSimpleName()
                                                 + " argument (or sequence of varargs) without null elements is required, but received: "
                                                 + Arrays.asList(elements));
         }

         // duplicate elements get ignored silently
         if (!resultSet.add(element)) {
            throw new IllegalArgumentException("Duplicate element: " + element);
         }
      }

      return resultSet;
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