/*
 * Copyright 2009-2014, Acciente LLC
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
import com.acciente.oacc.AccessControlException;
import com.acciente.oacc.AuthenticationProvider;
import com.acciente.oacc.AuthenticationProviderContext;
import com.acciente.oacc.Credentials;
import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.PasswordCredentials;
import com.acciente.oacc.Resource;
import com.acciente.oacc.ResourceClassInfo;
import com.acciente.oacc.ResourceCreatePermission;
import com.acciente.oacc.ResourcePermission;
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
import org.jasypt.util.password.PasswordEncryptor;
import org.jasypt.util.password.StrongPasswordEncryptor;

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
   private DataSource        dataSource;
   private Connection        connection;
   private PasswordEncryptor passwordEncryptor;

   // state
   private final AuthenticationProvider authenticationProvider;

   // The resource that authenticated in this session with a password
   private Resource authenticatedResource;
   private String   authenticatedResourceDomainName;

   // The resource as which the session's credentials are checked. This would be the same as the resource
   // that initially authenticated with a password unless a another resource is being impersonated
   private Resource sessionResource;
   private String   sessionResourceDomainName;

   // resource ID constants
   private static final int SYSTEM_RESOURCE_ID = 0;

   // domain permissions constants
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN
         = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN, false);
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN_GRANT
         = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN, true);
   private static final DomainPermission DomainPermission_SUPER_USER
         = DomainPermission.getInstance(DomainPermission.SUPER_USER, false);
   private static final DomainPermission DomainPermission_SUPER_USER_GRANT
         = DomainPermission.getInstance(DomainPermission.SUPER_USER, true);

   // resource permissions constants
   private static final ResourcePermission ResourcePermission_INHERIT
         = ResourcePermission.getInstance(ResourcePermission.INHERIT, false);
   private static final ResourcePermission ResourcePermission_INHERIT_GRANT
         = ResourcePermission.getInstance(ResourcePermission.INHERIT, true);
   private static final ResourcePermission ResourcePermission_IMPERSONATE
         = ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, false);
   private static final ResourcePermission ResourcePermission_IMPERSONATE_GRANT
         = ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, true);
   private static final ResourcePermission ResourcePermission_RESET_PASSWORD
         = ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD, false);
   private static final ResourcePermission ResourcePermission_RESET_PASSWORD_GRANT
         = ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD, true);

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
                                                              SQLDialect sqlDialect)
         throws AccessControlException {
      return new SQLAccessControlContext(connection, schemaName, sqlDialect, null);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLDialect sqlDialect)
         throws AccessControlException {
      return new SQLAccessControlContext(dataSource, schemaName, sqlDialect, null);
   }

   public static AccessControlContext getAccessControlContext(Connection connection,
                                                              String schemaName,
                                                              SQLDialect sqlDialect,
                                                              AuthenticationProvider authenticationProvider)
         throws AccessControlException {
      return new SQLAccessControlContext(connection, schemaName, sqlDialect, authenticationProvider);
   }

   public static AccessControlContext getAccessControlContext(DataSource dataSource,
                                                              String schemaName,
                                                              SQLDialect sqlDialect,
                                                              AuthenticationProvider authenticationProvider)
         throws AccessControlException {
      return new SQLAccessControlContext(dataSource, schemaName, sqlDialect, authenticationProvider);
   }

   public static void preSerialize(AccessControlContext accessControlContext) {
      if (accessControlContext instanceof SQLAccessControlContext) {
         SQLAccessControlContext sqlAccessControlContext = (SQLAccessControlContext) accessControlContext;
         sqlAccessControlContext.preSerialize();
      }
   }

   public static void postDeserialize(AccessControlContext accessControlContext, Connection connection) {
      if (accessControlContext instanceof SQLAccessControlContext) {
         SQLAccessControlContext sqlAccessControlContext = (SQLAccessControlContext) accessControlContext;
         sqlAccessControlContext.postDeserialize(connection);
      }
   }

   public static void postDeserialize(AccessControlContext accessControlContext, DataSource dataSource) {
      if (accessControlContext instanceof SQLAccessControlContext) {
         SQLAccessControlContext sqlAccessControlContext = (SQLAccessControlContext) accessControlContext;
         sqlAccessControlContext.postDeserialize(dataSource);
      }
   }

   private SQLAccessControlContext(Connection connection,
                                   String schemaName,
                                   SQLDialect sqlDialect,
                                   AuthenticationProvider authenticationProvider) throws AccessControlException {
      this(schemaName, sqlDialect, authenticationProvider);
      this.connection = connection;
   }

   private SQLAccessControlContext(DataSource dataSource,
                                   String schemaName,
                                   SQLDialect sqlDialect,
                                   AuthenticationProvider authenticationProvider) throws AccessControlException {
      this(schemaName, sqlDialect, authenticationProvider);
      this.dataSource = dataSource;
   }

   private SQLAccessControlContext(String schemaName,
                                   SQLDialect sqlDialect,
                                   AuthenticationProvider authenticationProvider) throws AccessControlException {
      this.passwordEncryptor = new StrongPasswordEncryptor();
      if (authenticationProvider == null) {
         // use the built-in authentication provider when no custom implementation is provided
         this.authenticationProvider = new PasswordAuthenticationProvider();
      }
      else {
         authenticationProvider.setContext(new AuthenticationProviderContextImpl(new PasswordAuthenticationProvider()));
         this.authenticationProvider = authenticationProvider;
      }

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

   private void preSerialize() {
      this.dataSource = null;
      this.connection = null;
      this.passwordEncryptor = null;
   }

   private void postDeserialize(DataSource dataSource) {
      this.dataSource = dataSource;
      this.connection = null;
      this.passwordEncryptor = new StrongPasswordEncryptor();
   }

   private void postDeserialize(Connection connection) {
      this.dataSource = null;
      this.connection = connection;
      this.passwordEncryptor = new StrongPasswordEncryptor();
   }

   @Override
   public void authenticate(Credentials credentials) throws AccessControlException {
      // before delegating to the authentication provider we do some basic validation
      SQLConnection connection = null;
      final String resourceDomainForResource;
      try {
         connection = getConnection();

         final ResourceClassInternalInfo resourceClassInternalInfo
               = resourceClassPersister.getResourceClassInfoByResourceId(connection, credentials.getResource());

         // complain if the resource is not marked as supporting authentication
         if (!resourceClassInternalInfo.isAuthenticatable()) {
            throw new AccessControlException(credentials.getResource()
                                                   + " is not of an authenticatable type, type: "
                                                   + resourceClassInternalInfo.getResourceClassName());
         }
         resourceDomainForResource = domainPersister.getResourceDomainNameByResourceId(connection,
                                                                                       credentials.getResource());
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }

      // now we delegate to the authentication provider
      authenticationProvider.authenticate(credentials);

      authenticatedResource = credentials.getResource();
      authenticatedResourceDomainName = resourceDomainForResource;

      sessionResource = authenticatedResource;
      sessionResourceDomainName = authenticatedResourceDomainName;
   }

   @Override
   public void unauthenticate()
         throws AccessControlException {
      sessionResource = authenticatedResource = null;
      sessionResourceDomainName = authenticatedResourceDomainName = null;
   }


   @Override
   public void impersonate(Resource resource) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __assertImpersonatePermission(connection, resource);

         // switch the session credentials to the new resource
         sessionResource = resource;
         sessionResourceDomainName = domainPersister.getResourceDomainNameByResourceId(connection, resource);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __assertImpersonatePermission(SQLConnection connection, Resource resource) throws AccessControlException {
      // this call will throw an exception if the resource is not found
      resourcePersister.verifyResourceExists(connection, resource);

      final ResourceClassInternalInfo resourceClassInternalInfo = resourceClassPersister.getResourceClassInfoByResourceId(connection, resource);

      // complain if the resource has no password set
      if (!resourceClassInternalInfo.isAuthenticatable()) {
         throw new AccessControlException(resource
                                          + " is not of an authenticatable type, type: "
                                          + resourceClassInternalInfo.getResourceClassName(),
                                    true);
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
               globalResourcePermissions = __getEffectiveGlobalPermissions(connection,
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
         if (__isSuperUserOfResource(connection, resource)) {
            impersonatePermissionOK = true;
         }
      }

      if (!impersonatePermissionOK) {
         throw new AccessControlException("Not authorized to impersonate: " + resource,
                                    true);
      }
   }

   @Override
   public void unimpersonate()
         throws AccessControlException {
      sessionResource = authenticatedResource;
      sessionResourceDomainName = authenticatedResourceDomainName;
   }

   @Override
   public void updateCredentials(Credentials newCredentials) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         boolean resetPasswordPermissionOK = false;

         // first check direct permissions
         final Resource resource = newCredentials.getResource();

         final ResourceClassInternalInfo
               resourceClassInfo = resourceClassPersister.getResourceClassInfoByResourceId(connection, resource);

         final Set<ResourcePermission>
               resourcePermissions = __getEffectiveResourcePermissions(connection, authenticatedResource, resource);

         if (resourcePermissions.contains(ResourcePermission_RESET_PASSWORD)
               || resourcePermissions.contains(ResourcePermission_RESET_PASSWORD_GRANT)) {
            resetPasswordPermissionOK = true;
         }

         if (!resetPasswordPermissionOK) {
            // next check global direct permissions
            final String
                  domainName = domainPersister.getResourceDomainNameByResourceId(connection, resource);
            final Set<ResourcePermission>
                  globalResourcePermissions = __getEffectiveGlobalPermissions(connection,
                                                                              authenticatedResource,
                                                                              resourceClassInfo.getResourceClassName(),
                                                                              domainName);

            if (globalResourcePermissions.contains(ResourcePermission_RESET_PASSWORD)
                  || globalResourcePermissions.contains(ResourcePermission_RESET_PASSWORD_GRANT)) {
               resetPasswordPermissionOK = true;
            }
         }

         if (!resetPasswordPermissionOK) {
            // finally check for super user permissions
            if (__isSuperUserOfResource(connection, resource)) {
               resetPasswordPermissionOK = true;
            }
         }

         if (!resetPasswordPermissionOK) {
            throw new AccessControlException("Not authorized to reset password for: " + resource,
                                       true);
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }

      authenticationProvider.updateCredentials(newCredentials);
   }

   @Override
   public void createResourceClass(String resourceClassName,
                                   boolean authenticatable,
                                   boolean unuthenticatedCreateAllowed) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertSysAuth();  // check if the auth resource is permitted to create resource classes
      assertResourceClassNameValid(resourceClassName);

      try {
         connection = getConnection();

         resourceClassName = resourceClassName.trim();

         // check if this resource class already exists
         if (resourceClassPersister.getResourceClassId(connection, resourceClassName) != null) {
            throw new AccessControlException("Duplicate resource class: " + resourceClassName);
         }

         resourceClassPersister.addResourceClass(connection, resourceClassName, authenticatable, unuthenticatedCreateAllowed);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void createResourcePermission(String resourceClassName, String permissionName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertSysAuth();  // check if the auth resource is permitted to create resource classes
      assertPermissionNameValid(permissionName);

      try {
         connection = getConnection();

         resourceClassName = resourceClassName.trim();
         permissionName = permissionName.trim();

         // first verify that resource class is defined
         Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

         if (resourceClassId == null) {
            throw new AccessControlException("Could not find resource class: " + resourceClassName);
         }

         // check if the permission name is already defined!
         Id<ResourcePermissionId> permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection, resourceClassId, permissionName);

         if (permissionId != null) {
            throw new AccessControlException("Duplicate permission: " + permissionName + " for resource class: " + resourceClassName);
         }

         resourceClassPermissionPersister.addResourceClassPermission(connection, resourceClassId, permissionName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void createDomain(String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertDomainSpecified(domainName);

      try {
         connection = getConnection();
         domainName = domainName.trim();

         __createDomain(connection, domainName, null);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void createDomain(String domainName,
                            String parentDomainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertDomainSpecified(domainName);
      assertParentDomainSpecified(parentDomainName);

      try {
         connection = getConnection();

         __createDomain(connection, domainName, parentDomainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __createDomain(SQLConnection connection,
                               String domainName,
                               String parentDomainName) throws AccessControlException {
      // we need to check if the currently authenticated resource is allowed to create domains
      final Set<DomainCreatePermission> domainCreatePermissions
            = grantDomainCreatePermissionSysPersister.getDomainCreatePermissions(connection, sessionResource);

      // if there is at least one permission, then it implies that this resource is allow to create domains
      if (domainCreatePermissions.isEmpty()) {
         throw new AccessControlException("Not authorized to create domains, domain: " + domainName,
                                          true);
      }

      // determine the post create permissions on the new domain
      final Set<DomainPermission> newDomainPermissions = __getPostCreateDomainPermissions(
            grantDomainCreatePermissionPostCreateSysPersister.getDomainPostCreatePermissions(connection,
                                                                                             sessionResource));
      // check to ensure that the requested domain name does not already exist
      if (domainPersister.getResourceDomainId(connection, domainName) != null) {
         throw new AccessControlException("Duplicate domain: " + domainName);
      }

      if (parentDomainName == null) {
         // create the new root domain
         domainPersister.addResourceDomain(connection, domainName);
      }
      else {
         // check to ensure that the parent domain name exists
         Id<DomainId> parentDomainId = domainPersister.getResourceDomainId(connection, parentDomainName);

         if (parentDomainId == null) {
            throw new AccessControlException("Parent domain: " + domainName + " not found!");
         }

         // we need to check if the currently authenticated resource is allowed to create child domains in the parent
         Set<DomainPermission> parentDomainPermissions;

         parentDomainPermissions = __getEffectiveDomainPermissions(connection, sessionResource, parentDomainName);

         if (!parentDomainPermissions.contains(DomainPermission_CREATE_CHILD_DOMAIN)
               && !parentDomainPermissions.contains(DomainPermission_CREATE_CHILD_DOMAIN_GRANT)
               && !parentDomainPermissions.contains(DomainPermission_SUPER_USER)
               && !parentDomainPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {
            throw new AccessControlException("Not authorized to create child domains in domain: "
                                             + parentDomainName,
                                       true);
         }

         // create the new child domain
         domainPersister.addResourceDomain(connection, domainName, parentDomainId);
      }

      if (newDomainPermissions.size() > 0) {
         // grant the currently authenticated resource the privileges to the new domain
         __setDomainPermissions(connection,
                                sessionResource,
                                domainName,
                                newDomainPermissions,
                                true);
      }
   }

   @Override
   public Resource createResource(String resourceClassName) throws AccessControlException {
      SQLConnection connection = null;

      try {
         connection = getConnection();

         return __createResource(connection, resourceClassName, sessionResourceDomainName, null);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Resource createResource(String resourceClassName, String domainName) throws AccessControlException {
      SQLConnection connection = null;

      try {
         connection = getConnection();

         return __createResource(connection, resourceClassName, domainName, null);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Resource createAuthenticatableResource(String resourceClassName, String password) throws AccessControlException {
      SQLConnection connection = null;

      assertPasswordOK(password);

      try {
         connection = getConnection();

         return __createResource(connection, resourceClassName, sessionResourceDomainName, password);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Resource createAuthenticatableResource(String resourceClassName,
                                                 String domainName,
                                                 String password) throws AccessControlException {
      SQLConnection connection = null;

      assertPasswordOK(password);

      try {
         connection = getConnection();

         return __createResource(connection, resourceClassName, domainName, password);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Resource __createResource(SQLConnection connection,
                                     String resourceClassName,
                                     String domainName,
                                     String password) throws AccessControlException {
      assertResourceClassNotBlank(resourceClassName);
      assertDomainSpecified(domainName);

      // validate the resource class
      resourceClassName = resourceClassName.trim();
      final ResourceClassInternalInfo resourceClassInternalInfo
            = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);

      // check if the resource class is valid
      if (resourceClassInternalInfo == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      if (!resourceClassInternalInfo.isUnauthenticatedCreateAllowed()) {
         assertAuth();
      }

      // check if a password is required and if it is consistent with if a password was provided
      if (resourceClassInternalInfo.isAuthenticatable()) {
         assertPasswordOK(password);
      }
      else {
         assertPasswordEmpty(password);

         // if we came here the password was null or whitespace, so set it to null
         password = null;
      }

      // validate the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
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
            newResourcePermissions.add(ResourcePermission.getInstance(permissionName, true));
         }

         if (resourceClassInternalInfo.isAuthenticatable()) {
            newResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD, true));
            newResourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE, true));
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
            createPermissionOK = __isSuperUserOfDomain(connection, domainName);
         }

         if (!createPermissionOK) {
            throw new AccessControlException("Not authorized to create resource, class: " + resourceClassName,
                                       true);
         }
      }

      // generate a resource id for the new resource
      final Id<ResourceId> newResourceId = resourcePersister.getNextResourceId(connection);

      if (newResourceId == null) {
         throw new AccessControlException("Error generating new resource ID");
      }

      // create the new resource
      final String encryptedBoundPassword;
      if (password == null) {
         encryptedBoundPassword = null;
      }
      else {
         final String boundPassword = PasswordUtils.computeBoundPassword(newResourceId, password);

         encryptedBoundPassword = passwordEncryptor.encryptPassword(boundPassword);
      }
      resourcePersister.createResource(connection,
                                       newResourceId,
                                       Id.<ResourceClassId>from(resourceClassInternalInfo.getResourceClassId()),
                                       domainId,
                                       encryptedBoundPassword);

      // set permissions on the new resource, if applicable
      final Resource newResource = Resource.getInstance(newResourceId.getValue());

      if (newResourcePermissions != null && newResourcePermissions.size() > 0) {
         if (sessionResource != null) {
            __setResourcePermissions(connection,
                                     sessionResource,
                                     newResource,
                                     newResourcePermissions,
                                     sessionResource,
                                     true);
         }
         else {
            // if this session is unauthenticated the permissions are granted to the newly created resource
            __setResourcePermissions(connection,
                                     newResource,
                                     newResource,
                                     newResourcePermissions,
                                     newResource,
                                     true);
         }
      }

      return newResource;
   }

   @Override
   public void setDomainPermissions(Resource accessorResource,
                                    String domainName,
                                    Set<DomainPermission> permissions) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __setDomainPermissions(connection, accessorResource, domainName, permissions, false);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __setDomainPermissions(SQLConnection connection,
                                       Resource accessorResource,
                                       String domainName,
                                       Set<DomainPermission> requestedDomainPermissions,
                                       boolean newDomainMode) throws AccessControlException {
      // determine the domain ID of the domain, for use in the grant below
      Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
      }

      // check if requested set contains *CREATE permission, which is nonsensical as an applied (i.e. non-create) permission
      if (requestedDomainPermissions == null) {
         throw new AccessControlException("Set of requested domain permissions may not be null");
      }

      if (!newDomainMode) {
         // check if the auth resource (grantor) has permissions to grant the requested permissions
         final Set<DomainPermission> grantorDomainPermissions;
         final Set<DomainPermission> unauthorizedAddPermissions;
         final Set<DomainPermission> unauthorizedRemovePermissions;

         grantorDomainPermissions = __getEffectiveDomainPermissions(connection,
                                                                    sessionResource,
                                                                    domainName);

         // check if the auth resource has super user permissions to the target domain
         if (!grantorDomainPermissions.contains(DomainPermission_SUPER_USER)
               && !grantorDomainPermissions.contains(DomainPermission_SUPER_USER_GRANT)) {
            unauthorizedAddPermissions
                  = __subtractDomainPermissions(requestedDomainPermissions, grantorDomainPermissions);

            if (unauthorizedAddPermissions.size() > 0) {
               throw new AccessControlException("Not authorized to add the following domain permission(s): "
                                                + unauthorizedAddPermissions,
                                          true);
            }

            unauthorizedRemovePermissions
                  = __subtractDomainPermissions(__getEffectiveDomainPermissions(connection,
                                                                                accessorResource,
                                                                                domainName),
                                                grantorDomainPermissions);

            if (unauthorizedRemovePermissions.size() > 0) {
               throw new AccessControlException("Not authorized to remove the following domain permission(s): "
                                                + unauthorizedRemovePermissions,
                                          true);
            }
         }

         // revoke any existing permissions that this grantor gave this accessor to this domain
         grantDomainPermissionSysPersister.removeDomainSysPermissions(connection, accessorResource, domainId);
      }

      // add the new permissions
      grantDomainPermissionSysPersister.addDomainSysPermissions(connection,
                                                                        accessorResource,
                                                                        sessionResource,
                                                                        domainId,
                                                                        requestedDomainPermissions);
   }

   private Set<DomainPermission> __subtractDomainPermissions(Set<DomainPermission> requestedDomainPermissions,
                                                             Set<DomainPermission> grantorDomainPermissions) {
      // we start with the assumption that all the requested permissions are unauthorized!
      Set<DomainPermission> unauthorizedDomainPermissions = new HashSet<>(requestedDomainPermissions);

      // check if the grantor has grant permissions to each permission
      for (DomainPermission requestedDomainPermission : requestedDomainPermissions) {
         // is the permission to check a system permission?
         if (requestedDomainPermission.isSystemPermission()) {
            for (DomainPermission grantorDomainPermission : grantorDomainPermissions) {
               // is the permission to check against a system permission?
               if (grantorDomainPermission.isSystemPermission()) {
                  if (grantorDomainPermission.isWithGrant()
                        && grantorDomainPermission.getSystemPermissionId() == requestedDomainPermission.getSystemPermissionId()
                        ) {
                     unauthorizedDomainPermissions.remove(requestedDomainPermission);
                     break;
                  }
               }
            }
         }
         else {
            for (DomainPermission grantorDomainPermission : grantorDomainPermissions) {
               // is the permission to check against a system permission?
               if (!grantorDomainPermission.isSystemPermission()) {
                  if (grantorDomainPermission.isWithGrant()
                        && grantorDomainPermission.getPermissionName().equals(requestedDomainPermission.getPermissionName())) {
                     unauthorizedDomainPermissions.remove(requestedDomainPermission);
                     break;
                  }
               }
            }
         }
      }

      return unauthorizedDomainPermissions;
   }

   @Override
   public Set<DomainPermission> getEffectiveDomainPermissions(Resource accessorResource,
                                                              String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getEffectiveDomainPermissions(connection, accessorResource, domainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Set<DomainPermission> __getEffectiveDomainPermissions(SQLConnection connection,
                                                                 Resource accessorResource,
                                                                 String domainName) throws AccessControlException {
      Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
      }

      // only system permissions are possible on a domain
      return grantDomainPermissionSysPersister.getDomainSysPermissions(connection, accessorResource, domainId);
   }

   @Override
   public Map<String, Set<DomainPermission>> getEffectiveDomainPermissionsMap(Resource accessorResource) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return grantDomainPermissionSysPersister.getDomainSysPermissions(connection, accessorResource);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void setDomainCreatePermissions(Resource accessorResource,
                                          Set<DomainCreatePermission> domainCreatePermissions) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __setDomainCreatePermissions(connection, accessorResource, domainCreatePermissions);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __setDomainCreatePermissions(SQLConnection connection,
                                             Resource accessorResource,
                                             Set<DomainCreatePermission> requestedDomainCreatePermissions) throws AccessControlException {
      boolean createSysPermissionFound = false;

      // first check that the CREATE permission is specified
      for (DomainCreatePermission domainCreatePermission : requestedDomainCreatePermissions) {
         if (domainCreatePermission.isSystemPermission()
               && domainCreatePermission.getSysPermissionName().equals(DomainCreatePermission.CREATE)) {
            createSysPermissionFound = true;
         }
      }

      if (requestedDomainCreatePermissions.size() > 0 && !createSysPermissionFound) {
         throw new AccessControlException("Domain create permission *CREATE must be specified");
      }

      // check if grantor is authorized to add/remove requisite permissions
      final Set<DomainCreatePermission> grantorPermissions = new HashSet<>();
      grantorPermissions
            .addAll(grantDomainCreatePermissionSysPersister.getDomainCreatePermissions(connection,
                                                                                       sessionResource));
      grantorPermissions
            .addAll(grantDomainCreatePermissionPostCreateSysPersister.getDomainPostCreatePermissions(connection,
                                                                                                     sessionResource));

      // check if the auth resource (grantor) has permissions to add the new permissions
      final Set<DomainCreatePermission>
            unauthorizedAddPermissions
            = __subtractDomainCreatePermissions(requestedDomainCreatePermissions,
                                                grantorPermissions);
      if (unauthorizedAddPermissions.size() > 0) {
         throw new AccessControlException("Not authorized to add the following domain permission(s): "
                                          + unauthorizedAddPermissions,
                                    true);
      }

      // check if the auth resource (grantor) has permissions to remove the current permissions
      final Set<DomainCreatePermission> accessorCurrentPermissions = new HashSet<>();
      accessorCurrentPermissions
            .addAll(grantDomainCreatePermissionSysPersister.getDomainCreatePermissions(connection,
                                                                                       accessorResource));
      accessorCurrentPermissions
            .addAll(grantDomainCreatePermissionPostCreateSysPersister.getDomainPostCreatePermissions(connection,
                                                                                                     accessorResource));
      final Set<DomainCreatePermission>
            unauthorizedRemovePermissions
            = __subtractDomainCreatePermissions(accessorCurrentPermissions,
                                                grantorPermissions);
      if (unauthorizedRemovePermissions.size() > 0) {
         throw new AccessControlException("Not authorized to remove the following domain permission(s): "
                                          + unauthorizedRemovePermissions,
                                    true);
      }

      // NOTE: our current data model only support system permissions for domains

      // revoke any existing domain system permission (*CREATE) this accessor has to this domain
      grantDomainCreatePermissionSysPersister.removeDomainCreatePermissions(connection, accessorResource);
      // revoke any existing domain post create system permissions this accessor has to this domain
      grantDomainCreatePermissionPostCreateSysPersister.removeDomainPostCreatePermissions(connection, accessorResource);

      // add the domain system permissions (*CREATE)
      grantDomainCreatePermissionSysPersister.addDomainCreatePermissions(connection,
                                                                         accessorResource,
                                                                         sessionResource,
                                                                         requestedDomainCreatePermissions);
      // add the domain post create system permissions
      grantDomainCreatePermissionPostCreateSysPersister.addDomainPostCreatePermissions(connection,
                                                                                       accessorResource,
                                                                                       sessionResource,
                                                                                       requestedDomainCreatePermissions);
   }

   private Set<DomainCreatePermission> __subtractDomainCreatePermissions(Set<DomainCreatePermission> requestedDomainCreatePermissions,
                                                                         Set<DomainCreatePermission> grantorDomainCreatePermissions) {
      // we start with the assumption that all the requested permissions are unauthorized!
      Set<DomainCreatePermission> unauthorizedDomainCreatePermissions = new HashSet<>(requestedDomainCreatePermissions);

      // check if the grantor has grant permissions to each permission
      for (DomainCreatePermission requestedDomainCreatePermission : requestedDomainCreatePermissions) {
         // is the permission to check a system permission?
         if (requestedDomainCreatePermission.isSystemPermission()) {
            for (DomainCreatePermission grantorDomainCreatePermission : grantorDomainCreatePermissions) {
               // is the permission to check against a system permission?
               if (grantorDomainCreatePermission.isSystemPermission()) {
                  if (grantorDomainCreatePermission.isWithGrant()
                        && grantorDomainCreatePermission.getSystemPermissionId()
                        == requestedDomainCreatePermission.getSystemPermissionId()
                        ) {
                     unauthorizedDomainCreatePermissions.remove(requestedDomainCreatePermission);
                     break;
                  }
               }
            }
         }
         // is the permission to check a post create system permission?
         else if (requestedDomainCreatePermission.getPostCreateDomainPermission().isSystemPermission()) {
            for (DomainCreatePermission grantorDomainCreatePermission : grantorDomainCreatePermissions) {
               // is the permission to check against a post create system permission?
               if (!grantorDomainCreatePermission.isSystemPermission()
                     && grantorDomainCreatePermission.getPostCreateDomainPermission().isSystemPermission()) {
                  if (grantorDomainCreatePermission.isWithGrant()
                        && grantorDomainCreatePermission.getPostCreateDomainPermission().getSystemPermissionId()
                        == requestedDomainCreatePermission.getPostCreateDomainPermission().getSystemPermissionId()
                        ) {
                     unauthorizedDomainCreatePermissions.remove(requestedDomainCreatePermission);
                     break;
                  }
               }
            }
         }
         else {
            for (DomainCreatePermission grantorDomainCreatePermission : grantorDomainCreatePermissions) {
               // is the permission to check against a system permission?
               if (!grantorDomainCreatePermission.getPostCreateDomainPermission().isSystemPermission()) {
                  if (grantorDomainCreatePermission.isWithGrant()
                        && grantorDomainCreatePermission.getPostCreateDomainPermission().getPermissionName().equals(requestedDomainCreatePermission.getPostCreateDomainPermission().getPermissionName())) {
                     unauthorizedDomainCreatePermissions.remove(requestedDomainCreatePermission);
                     break;
                  }
               }
            }
         }
      }

      return unauthorizedDomainCreatePermissions;
   }

   @Override
   public Set<DomainCreatePermission> getEffectiveDomainCreatePermissions(Resource accessorResource) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         final Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
         domainCreatePermissions
               .addAll(grantDomainCreatePermissionSysPersister.getDomainCreatePermissions(connection,
                                                                                          accessorResource));
         domainCreatePermissions
               .addAll(grantDomainCreatePermissionPostCreateSysPersister.getDomainPostCreatePermissions(connection,
                                                                                                        accessorResource));
         return domainCreatePermissions;
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions,
                                            String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertResourceClassNotBlank(resourceClassName);

      try {
         connection = getConnection();

         __setResourceCreatePermissions(connection,
                                        accessorResource,
                                        resourceClassName,
                                        resourceCreatePermissions, domainName
         );
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void setResourceCreatePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourceCreatePermission> resourceCreatePermissions) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertResourceClassNotBlank(resourceClassName);

      try {
         connection = getConnection();

         __setResourceCreatePermissions(connection,
                                        accessorResource,
                                        resourceClassName,
                                        resourceCreatePermissions,
                                        sessionResourceDomainName
         );
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __setResourceCreatePermissions(SQLConnection connection,
                                               Resource accessorResource,
                                               String resourceClassName,
                                               Set<ResourceCreatePermission> requestedResourceCreatePermissions,
                                               String domainName) throws AccessControlException {
      // verify that resource class is defined
      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
      }

      final List<String> validPermissionNames = resourceClassPermissionPersister.getPermissionNames(connection, resourceClassName);
      boolean createSysPermissionFound = false;

      // next ensure that the post create permissions are all in the correct resource class
      final HashSet<String> uniquePermissionNames = new HashSet<>(requestedResourceCreatePermissions.size());
      for (final ResourceCreatePermission resourceCreatePermission : requestedResourceCreatePermissions) {
         // track if there is a CREATE system permission in the list
         if (resourceCreatePermission.isSystemPermission()
               && resourceCreatePermission.getSysPermissionName().equals(ResourceCreatePermission.CREATE)) {
            createSysPermissionFound = true;
         }
         else {
            final ResourcePermission postCreateResourcePermission = resourceCreatePermission.getPostCreateResourcePermission();

            if (!postCreateResourcePermission.isSystemPermission()) {
               // every non-system permission must be defined for the resource class specified
               if (!validPermissionNames.contains(postCreateResourcePermission.getPermissionName())) {
                  throw new AccessControlException("Permission: " + postCreateResourcePermission.getPermissionName()
                                                   + " does not exist for the specified resource class: "
                                                   + resourceClassName);
               }
            }

            if (uniquePermissionNames.contains(postCreateResourcePermission.getPermissionName())) {
               throw new AccessControlException("Duplicate permission: "
                                                + postCreateResourcePermission.getPermissionName() + " that only differs in 'withGrant' option");
            }
            else {
               uniquePermissionNames.add(postCreateResourcePermission.getPermissionName());
            }
         }
      }

      // if at least one permission is specified, then there must be a *CREATE permission in the set
      if (requestedResourceCreatePermissions.size() != 0 && !createSysPermissionFound) {
         throw new AccessControlException("Permission: *CREATE must be specified");
      }

      // next check if the auth resource (grantor) has permissions to grant the requested permissions
      if (!__isSuperUserOfDomain(connection, domainName)) {
         final Set<ResourceCreatePermission>
               grantorResourceCreatePermissions
               = __getEffectiveResourceCreatePermissions(connection,
                                                         sessionResource,
                                                         resourceClassName,
                                                         domainName);
         final Set<ResourceCreatePermission>
               unauthorizedAddResourceCreatePermissions
               = __subtractResourceCreatePermissions(requestedResourceCreatePermissions, grantorResourceCreatePermissions);

         if (unauthorizedAddResourceCreatePermissions.size() > 0) {
            throw new AccessControlException("Not authorized to add the following permission(s): "
                                             + unauthorizedAddResourceCreatePermissions,
                                       true);
         }

         final Set<ResourceCreatePermission>
               unauthorizedRemoveResourceCreatePermissions
               = __subtractResourceCreatePermissions(__getEffectiveResourceCreatePermissions(connection,
                                                                                             accessorResource,
                                                                                             resourceClassName,
                                                                                             domainName),
                                                     grantorResourceCreatePermissions);

         if (unauthorizedRemoveResourceCreatePermissions.size() > 0) {
            throw new AccessControlException("Not authorized to remove the following permission(s): "
                                             + unauthorizedRemoveResourceCreatePermissions,
                                       true);
         }
      }

      // revoke any existing *CREATE system permissions this accessor has to this resource class
      grantResourceCreatePermissionSysPersister.removeCreateSysPermissions(connection,
                                                                           accessorResource,
                                                                           resourceClassId,
                                                                           domainId);


      // revoke any existing post create system permissions this accessor has to this resource class
      grantResourceCreatePermissionPostCreateSysPersister.removePostCreateSysPermissions(connection,
                                                                                         accessorResource,
                                                                                         resourceClassId,
                                                                                         domainId);

      // revoke any existing post create non-system permissions this accessor has to this resource class
      grantResourceCreatePermissionPostCreatePersister.removePostCreatePermissions(connection,
                                                                                   accessorResource,
                                                                                   resourceClassId,
                                                                                   domainId);

      // grant the *CREATE system permissions
      grantResourceCreatePermissionSysPersister.addCreateSysPermissions(connection,
                                                                        accessorResource,
                                                                        resourceClassId,
                                                                        domainId,
                                                                        requestedResourceCreatePermissions,
                                                                        sessionResource);

      // grant the post create system permissions
      grantResourceCreatePermissionPostCreateSysPersister.addPostCreateSysPermissions(connection,
                                                                                      accessorResource,
                                                                                      resourceClassId,
                                                                                      domainId,
                                                                                      requestedResourceCreatePermissions,
                                                                                      sessionResource);

      // grant the post create non-system permissions
      grantResourceCreatePermissionPostCreatePersister.addPostCreatePermissions(connection,
                                                                                accessorResource,
                                                                                resourceClassId,
                                                                                domainId,
                                                                                requestedResourceCreatePermissions,
                                                                                sessionResource);
   }

   private Set<ResourceCreatePermission> __subtractResourceCreatePermissions(Set<ResourceCreatePermission> requestedResourceCreatePermissions,
                                                                             Set<ResourceCreatePermission> grantorResourceCreatePermissions) {
      // we start with the assumption that all the requested permissions are unauthorized!
      Set<ResourceCreatePermission> unauthorizedResourceCreatePermissions = new HashSet<>(requestedResourceCreatePermissions);

      // check if the grantor has grant permissions to each permission
      for (ResourceCreatePermission requestedResourceCreatePermission : requestedResourceCreatePermissions) {
         // is the permission to check a system permission?
         if (requestedResourceCreatePermission.isSystemPermission()) {
            for (ResourceCreatePermission grantorResourceCreatePermission : grantorResourceCreatePermissions) {
               // is the permission to check against a system permission?
               if (grantorResourceCreatePermission.isSystemPermission()) {
                  if (grantorResourceCreatePermission.isWithGrant()
                        && grantorResourceCreatePermission.getSystemPermissionId()
                        == requestedResourceCreatePermission.getSystemPermissionId()
                        ) {
                     unauthorizedResourceCreatePermissions.remove(requestedResourceCreatePermission);
                     break;
                  }
               }
            }
         }
         else {
            // is the post create permission to check a system permission?
            if (requestedResourceCreatePermission.getPostCreateResourcePermission().isSystemPermission()) {
               for (ResourceCreatePermission grantorResourceCreatePermission : grantorResourceCreatePermissions) {
                  // is the post create permission to check against a system permission?
                  if (!grantorResourceCreatePermission.isSystemPermission()
                        && grantorResourceCreatePermission.getPostCreateResourcePermission().isSystemPermission()) {
                     if (grantorResourceCreatePermission.isWithGrant()
                           && grantorResourceCreatePermission.getPostCreateResourcePermission().getSystemPermissionId()
                           == requestedResourceCreatePermission.getPostCreateResourcePermission().getSystemPermissionId()
                           ) {
                        unauthorizedResourceCreatePermissions.remove(requestedResourceCreatePermission);
                        break;
                     }
                  }
               }
            }
            else {
               for (ResourceCreatePermission grantorResourceCreatePermission : grantorResourceCreatePermissions) {
                  // is the post create permission to check against a system permission?
                  if (!grantorResourceCreatePermission.isSystemPermission()
                        && !grantorResourceCreatePermission.getPostCreateResourcePermission().isSystemPermission()) {
                     if (grantorResourceCreatePermission.isWithGrant()
                           && grantorResourceCreatePermission.getPostCreateResourcePermission().getPermissionName().equals(requestedResourceCreatePermission.getPostCreateResourcePermission().getPermissionName())) {
                        unauthorizedResourceCreatePermissions.remove(requestedResourceCreatePermission);
                        break;
                     }
                  }
               }
            }
         }
      }

      return unauthorizedResourceCreatePermissions;
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName,
                                                                              String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertResourceClassNotBlank(resourceClassName);

      try {
         connection = getConnection();

         return __getEffectiveResourceCreatePermissions(connection,
                                                        accessorResource,
                                                        resourceClassName,
                                                        domainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Set<ResourceCreatePermission> getEffectiveResourceCreatePermissions(Resource accessorResource,
                                                                              String resourceClassName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertResourceClassNotBlank(resourceClassName);

      try {
         connection = getConnection();

         return __getEffectiveResourceCreatePermissions(connection,
                                                        accessorResource,
                                                        resourceClassName,
                                                        sessionResourceDomainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Set<ResourceCreatePermission> __getEffectiveResourceCreatePermissions(SQLConnection connection,
                                                                                 Resource accessorResource,
                                                                                 String resourceClassName,
                                                                                 String domainName) throws AccessControlException {
      // verify that resource class is defined
      Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      // verify that domain is defined
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
      }

      // collect the create permissions that this resource has to this resource class
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();

      // first read the *CREATE system permission the accessor has to the specified resource class
      resourceCreatePermissions.addAll(
            grantResourceCreatePermissionSysPersister.getCreateSysPermissions(connection,
                                                                              accessorResource,
                                                                              resourceClassId,
                                                                              domainId));

      // next read the post create system permissions the accessor has to the specified resource class
      resourceCreatePermissions.addAll(
            grantResourceCreatePermissionPostCreateSysPersister.getPostCreateSysPermissions(connection,
                                                                                            accessorResource,
                                                                                            resourceClassId,
                                                                                            domainId));

      // next read the post create non-system permissions the accessor has to the specified resource class
      resourceCreatePermissions.addAll(
            grantResourceCreatePermissionPostCreatePersister.getPostCreatePermissions(connection,
                                                                                      accessorResource,
                                                                                      resourceClassId,
                                                                                      domainId));
      return resourceCreatePermissions;
   }

   @Override
   public Map<String, Map<String, Set<ResourceCreatePermission>>> getEffectiveResourceCreatePermissionsMap(Resource accessorResource)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getEffectiveResourceCreatePermissionsMap(connection,
                                                           accessorResource);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Map<String, Map<String, Set<ResourceCreatePermission>>> __getEffectiveResourceCreatePermissionsMap(
         SQLConnection connection,
         Resource accessorResource)
         throws AccessControlException {
      // collect all the create permissions that the accessor has
      Map<String, Map<String, Set<ResourceCreatePermission>>> allResourceCreatePermissionsMap = new HashMap<>();

      // read the *CREATE system permissions and add to createALLPermissionsMap
      mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(
            grantResourceCreatePermissionSysPersister.getCreateSysPermissions(connection, accessorResource),
            allResourceCreatePermissionsMap);

      // read the post create system permissions and add to createALLPermissionsMap
      mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(
            grantResourceCreatePermissionPostCreateSysPersister.getPostCreateSysPermissions(connection, accessorResource),
            allResourceCreatePermissionsMap);

      // read the post create non-system permissions and add to createALLPermissionsMap
      mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(
            grantResourceCreatePermissionPostCreatePersister.getPostCreatePermissions(connection, accessorResource),
            allResourceCreatePermissionsMap);

      return allResourceCreatePermissionsMap;
   }

   private void mergeSourceCreatePermissionsMapIntoTargetCreatePermissionsMap(Map<String, Map<String, Set<ResourceCreatePermission>>> sourceCreatePermissionsMap,
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

   @Override
   public void setResourcePermissions(Resource accessorResource,
                                      Resource accessedResource,
                                      Set<ResourcePermission> resourcePermissions) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __setResourcePermissions(connection,
                                  accessorResource,
                                  accessedResource,
                                  resourcePermissions,
                                  sessionResource,
                                  false);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __setResourcePermissions(SQLConnection connection,
                                         Resource accessorResource,
                                         Resource accessedResource,
                                         Set<ResourcePermission> requestedResourcePermissions,
                                         Resource grantorResource,
                                         boolean newResourceMode) throws AccessControlException {
      final ResourceClassInternalInfo accessedResourceClassInternalInfo;
      final String accessedResourceClassName;
      final String accessedResourceDomainName;

      accessedResourceClassInternalInfo = resourceClassPersister.getResourceClassInfoByResourceId(connection, accessedResource);
      accessedResourceClassName = accessedResourceClassInternalInfo.getResourceClassName();
      accessedResourceDomainName = domainPersister.getResourceDomainNameByResourceId(connection, accessedResource);

      // next ensure that the post create permissions are all in the correct resource class
      final List<String> validPermissionNames = resourceClassPermissionPersister.getPermissionNames(connection, accessedResourceClassName);
      final Set<String> uniquePermissionNames = new HashSet<>(requestedResourcePermissions.size());
      for (final ResourcePermission resourcePermission : requestedResourcePermissions) {
         // we prohibit granting the system CREATE permission, since it would not make sense here
         if (resourcePermission.isSystemPermission()) {
            if (!accessedResourceClassInternalInfo.isAuthenticatable()
                  && (resourcePermission.getPermissionName().equals(ResourcePermission.IMPERSONATE)
                  || resourcePermission.getPermissionName().equals(ResourcePermission.RESET_PASSWORD))) {
               throw new AccessControlException("Permission: " + resourcePermission + ", not valid for unauthenticatable resource");
            }
         }
         else {
            // every non-system permission must be defined for the resource class specified
            if (!validPermissionNames.contains(resourcePermission.getPermissionName())) {
               throw new AccessControlException("Permission: " + resourcePermission.getPermissionName()
                                                + " does not exist for the specified resource class: "
                                                + accessedResourceClassName);
            }
         }
         if (uniquePermissionNames.contains(resourcePermission.getPermissionName())) {
            throw new AccessControlException("Duplicate permission: "
                                             + resourcePermission.getPermissionName() + " that only differs in 'withGrant' option");
         }
         else {
            uniquePermissionNames.add(resourcePermission.getPermissionName());
         }
      }

      // if this method is being called to set the post create permissions on a newly created resource
      // we do not perform the security checks below, since it would be incorrect
      if (!newResourceMode) {
         if (!__isSuperUserOfResource(connection, accessedResource)) {
            // next check if the auth resource (grantor) has permissions to grant the requested permissions
            final Set<ResourcePermission>
                  grantorResourcePermissions
                  = __getEffectiveResourcePermissions(connection,
                                                      sessionResource,
                                                      accessedResource);
            Set<ResourcePermission>
                  unauthorizedAddPermissions
                  = __subtractPermissions(requestedResourcePermissions,
                                          grantorResourcePermissions);
            Set<ResourcePermission>
                  grantorGlobalResourcePermissions = null; // we will load these permission on demand below

            if (unauthorizedAddPermissions.size() > 0) {
               // if there are insufficient permissions check if the grantor has access via global permissions
               grantorGlobalResourcePermissions
                     = __getEffectiveGlobalPermissions(connection,
                                                       sessionResource,
                                                       accessedResourceClassName,
                                                       accessedResourceDomainName);

               unauthorizedAddPermissions
                     = __subtractPermissions(requestedResourcePermissions,
                                             grantorGlobalResourcePermissions);
            }

            // if that did not do it, then complain
            if (unauthorizedAddPermissions.size() > 0) {
               throw new AccessControlException("Not authorized to add the following permission(s): "
                                                + unauthorizedAddPermissions,
                                          true);
            }

            final Set<ResourcePermission>
                  accessorResourcePermissions
                  = __getEffectiveResourcePermissions(connection,
                                                      accessorResource,
                                                      accessedResource);

            Set<ResourcePermission>
                  unauthorizedRemovePermissions
                  = __subtractPermissions(accessorResourcePermissions,
                                          grantorResourcePermissions);

            if (unauthorizedRemovePermissions.size() > 0) {
               // if there are insufficient permissions check if the grantor has access via global permissions
               if (grantorGlobalResourcePermissions == null) {
                  grantorGlobalResourcePermissions
                        = __getEffectiveGlobalPermissions(connection,
                                                          sessionResource,
                                                          accessedResourceClassName,
                                                          accessedResourceDomainName);
               }

               unauthorizedRemovePermissions
                     = __subtractPermissions(accessorResourcePermissions,
                                             grantorGlobalResourcePermissions);

            }

            if (unauthorizedRemovePermissions.size() > 0) {
               throw new AccessControlException("Not authorized to remove the following permission(s): "
                                                + unauthorizedRemovePermissions,
                                          true);
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
               throw new AccessControlException("Granting the requested permission(s): "
                                                + requestedResourcePermissions
                                                + " will cause a cycle between: "
                                                + accessorResource
                                                + " and: "
                                                + accessedResource,
                                          true);
            }
         }

         // revoke any existing system permissions that this grantor gave this accessor to this resource
         grantResourcePermissionSysPersister.removeSysPermissions(connection, accessorResource, accessedResource);

         // revoke any existing non-system permissions that this grantor gave this accessor to this resource
         grantResourcePermissionPersister.removePermissions(connection, accessorResource, accessedResource);
      }

      // add the new system permissions
      grantResourcePermissionSysPersister.addSysPermissions(connection,
                                                            accessorResource,
                                                            accessedResource,
                                                            Id.<ResourceClassId>from(accessedResourceClassInternalInfo.getResourceClassId()),
                                                            requestedResourcePermissions,
                                                            grantorResource);

      // add the new non-system permissions
      grantResourcePermissionPersister.addPermissions(connection,
                                                      accessorResource,
                                                      accessedResource,
                                                      Id.<ResourceClassId>from(accessedResourceClassInternalInfo.getResourceClassId()),
                                                      requestedResourcePermissions,
                                                      grantorResource);
   }

   private Set<ResourcePermission> __subtractPermissions(Set<ResourcePermission> requestedResourcePermissions,
                                                         Set<ResourcePermission> grantorResourcePermissions) {
      // we start with the assumption that all the requested permissions are unauthorized!
      Set<ResourcePermission> unauthorizedResourcePermissions = new HashSet<>(requestedResourcePermissions);

      // check if the grantor has grant permissions to each permission
      for (ResourcePermission requestedResourcePermission : requestedResourcePermissions) {
         // is the permission to check a system permission?
         if (requestedResourcePermission.isSystemPermission()) {
            for (ResourcePermission grantorResourcePermission : grantorResourcePermissions) {
               // is the permission to check against a system permission?
               if (grantorResourcePermission.isSystemPermission()) {
                  if (grantorResourcePermission.isWithGrant()
                        && grantorResourcePermission.getSystemPermissionId() == requestedResourcePermission.getSystemPermissionId()
                        ) {
                     unauthorizedResourcePermissions.remove(requestedResourcePermission);
                     break;
                  }
               }
            }
         }
         else {
            for (ResourcePermission grantorResourcePermission : grantorResourcePermissions) {
               // is the permission to check against a system permission?
               if (!grantorResourcePermission.isSystemPermission()) {
                  if (grantorResourcePermission.isWithGrant()
                        && grantorResourcePermission.getPermissionName().equals(requestedResourcePermission.getPermissionName())) {
                     unauthorizedResourcePermissions.remove(requestedResourcePermission);
                     break;
                  }
               }
            }
         }
      }

      return unauthorizedResourcePermissions;
   }

   @Override
   public Set<ResourcePermission> getEffectiveResourcePermissions(Resource accessorResource, Resource accessedResource)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getEffectiveResourcePermissions(connection, accessorResource, accessedResource);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Set<ResourcePermission> __getEffectiveResourcePermissions(SQLConnection connection,
                                                                     Resource accessorResource,
                                                                     Resource accessedResource)
         throws AccessControlException {
      Set<ResourcePermission> resourcePermissions = new HashSet<>();

      // collect the system permissions that the accessor resource has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionSysPersister.getSysPermissions(connection,
                                                                                       accessorResource,
                                                                                       accessedResource));

      // first collect the non-system permissions that the accessor has to the accessed resource
      resourcePermissions.addAll(grantResourcePermissionPersister.getPermissions(connection,
                                                                                 accessorResource,
                                                                                 accessedResource));

      return resourcePermissions;
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions,
                                            String domainName)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __setGlobalPermissions(connection,
                                accessorResource,
                                resourceClassName,
                                resourcePermissions,
                                domainName
         );
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void setGlobalResourcePermissions(Resource accessorResource,
                                            String resourceClassName,
                                            Set<ResourcePermission> resourcePermissions) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __setGlobalPermissions(connection,
                                accessorResource,
                                resourceClassName,
                                resourcePermissions, sessionResourceDomainName
         );
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __setGlobalPermissions(SQLConnection connection,
                                       Resource accessorResource,
                                       String resourceClassName,
                                       Set<ResourcePermission> requestedResourcePermissions,
                                       String domainName)
         throws AccessControlException {
      // verify that resource class is defined
      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
      }

      // next ensure that the post create permissions are all in the correct resource class
      final List<String> validPermissionNames = resourceClassPermissionPersister.getPermissionNames(connection, resourceClassName);
      final ResourceClassInternalInfo resourceClassInternalInfo = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);
      final HashSet<String> uniquePermissionNames = new HashSet<>(requestedResourcePermissions.size());

      for (final ResourcePermission resourcePermission : requestedResourcePermissions) {
         // we prohibit granting the system INHERIT permission, since cycle checking may be prohibitively compute intensive
         if (resourcePermission.isSystemPermission()) {
            if (resourcePermission.equals(ResourcePermission_INHERIT)) {
               throw new AccessControlException("Permission: " + resourcePermission + ", not valid in this context");
            }
            if (!resourceClassInternalInfo.isAuthenticatable()
                  && (resourcePermission.getPermissionName().equals(ResourcePermission.IMPERSONATE)
                  || resourcePermission.getPermissionName().equals(ResourcePermission.RESET_PASSWORD))) {
               throw new AccessControlException("Permission: " + resourcePermission + ", not valid for unauthenticatable resource");
            }
         }
         else {
            // every non-system permission must be defined for the resource class specified
            if (!validPermissionNames.contains(resourcePermission.getPermissionName())) {
               throw new AccessControlException("Permission: " + resourcePermission.getPermissionName()
                                                + " does not exist for the specified resource class: "
                                                + resourceClassName);
            }
         }
         if (uniquePermissionNames.contains(resourcePermission.getPermissionName())) {
            throw new AccessControlException("Duplicate permission: "
                                             + resourcePermission.getPermissionName() + " that only differs in 'withGrant' option");
         }
         else {
            uniquePermissionNames.add(resourcePermission.getPermissionName());
         }
      }

      if (!__isSuperUserOfDomain(connection, domainName)) {
         final Set<ResourcePermission>
               grantorResourcePermissions
               = __getEffectiveGlobalPermissions(connection,
                                                 sessionResource,
                                                 resourceClassName,
                                                 domainName);
         final Set<ResourcePermission>
               unauthorizedAddPermissions
               = __subtractPermissions(requestedResourcePermissions,
                                       grantorResourcePermissions);

         if (unauthorizedAddPermissions.size() > 0) {
            throw new AccessControlException("Not authorized to add the following permission(s): "
                                             + unauthorizedAddPermissions,
                                       true);
         }

         final Set<ResourcePermission>
               unauthorizedRemovePermissions
               = __subtractPermissions(__getEffectiveGlobalPermissions(connection,
                                                                       accessorResource,
                                                                       resourceClassName,
                                                                       domainName),
                                       grantorResourcePermissions);

         if (unauthorizedRemovePermissions.size() > 0) {
            throw new AccessControlException("Not authorized to remove the following permission(s): "
                                             + unauthorizedRemovePermissions,
                                       true);
         }
      }

      // revoke any existing system permissions this accessor has to this domain + resource class
      grantGlobalResourcePermissionSysPersister.removeGlobalSysPermissions(connection,
                                                                           accessorResource,
                                                                           resourceClassId,
                                                                           domainId);

      // revoke any existing non-system permissions that this grantor gave this accessor to this domain to the resource class
      grantGlobalResourcePermissionPersister.removeGlobalPermissions(connection,
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
      grantGlobalResourcePermissionPersister.addGlobalPermissions(connection,
                                                                  accessorResource,
                                                                  resourceClassId,
                                                                  domainId,
                                                                  requestedResourcePermissions,
                                                                  sessionResource);
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName,
                                                                        String domainName)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getEffectiveGlobalPermissions(connection,
                                                accessorResource,
                                                resourceClassName,
                                                domainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Set<ResourcePermission> getEffectiveGlobalResourcePermissions(Resource accessorResource,
                                                                        String resourceClassName)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getEffectiveGlobalPermissions(connection,
                                                accessorResource,
                                                resourceClassName,
                                                sessionResourceDomainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Set<ResourcePermission> __getEffectiveGlobalPermissions(SQLConnection connection,
                                                                   Resource accessorResource,
                                                                   String resourceClassName,
                                                                   String domainName)
         throws AccessControlException {
      // verify that resource class is defined
      final Id<ResourceClassId> resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      // verify the domain
      final Id<DomainId> domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
      }

      Set<ResourcePermission> resourcePermissions = new HashSet<>();

      // first collect the system permissions that the accessor has to the accessed resource
      resourcePermissions.addAll(grantGlobalResourcePermissionSysPersister.getGlobalSysPermissions(connection,
                                                                                                   accessorResource,
                                                                                                   resourceClassId,
                                                                                                   domainId));

      // first collect the non-system permissions that the accessor this resource has to the accessor resource
      resourcePermissions.addAll(grantGlobalResourcePermissionPersister.getGlobalPermissions(connection,
                                                                                             accessorResource,
                                                                                             resourceClassId,
                                                                                             domainId));
      return resourcePermissions;
   }

   @Override
   public Map<String, Map<String, Set<ResourcePermission>>> getEffectiveGlobalResourcePermissionsMap(Resource accessorResource)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getEffectiveGlobalPermissions(connection, accessorResource);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Map<String, Map<String, Set<ResourcePermission>>> __getEffectiveGlobalPermissions(SQLConnection connection,
                                                                                             Resource accessorResource)
         throws AccessControlException {
      final Map<String, Map<String, Set<ResourcePermission>>> globalALLPermissionsMap = new HashMap<>();

      // collect the system permissions that the accessor has and add it into the globalALLPermissionsMap
      mergeSourcePermissionsMapIntoTargetPermissionsMap(
            grantGlobalResourcePermissionSysPersister.getGlobalSysPermissions(connection, accessorResource),
            globalALLPermissionsMap);

      // next collect the non-system permissions that the accessor has and add it into the globalALLPermissionsMap
      mergeSourcePermissionsMapIntoTargetPermissionsMap(
            grantGlobalResourcePermissionPersister.getGlobalPermissions(connection, accessorResource),
            globalALLPermissionsMap);

      return globalALLPermissionsMap;
   }

   private void mergeSourcePermissionsMapIntoTargetPermissionsMap(Map<String, Map<String, Set<ResourcePermission>>> sourcePermissionsMap,
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

   @Override
   public String getDomainNameByResource(Resource resource) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return domainPersister.getResourceDomainNameByResourceId(connection, resource);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Set<String> getDomainDescendants(String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertDomainSpecified(domainName);

      try {
         connection = getConnection();
         domainName = domainName.trim();

         return domainPersister.getResourceDomainNameDescendants(connection, domainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public ResourceClassInfo getResourceClassInfo(String resourceClassName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         final ResourceClassInternalInfo resourceClassInternalInfo = resourceClassPersister.getResourceClassInfo(connection, resourceClassName);
         return new ResourceClassInfo(resourceClassInternalInfo.getResourceClassName(),
                                      resourceClassInternalInfo.isAuthenticatable(),
                                      resourceClassInternalInfo.isUnauthenticatedCreateAllowed());
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public ResourceClassInfo getResourceClassInfoByResource(Resource resource) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         final ResourceClassInternalInfo resourceClassInternalInfo = resourceClassPersister.getResourceClassInfoByResourceId(connection, resource);
         return new ResourceClassInfo(resourceClassInternalInfo.getResourceClassName(),
                                      resourceClassInternalInfo.isAuthenticatable(),
                                      resourceClassInternalInfo.isUnauthenticatedCreateAllowed());
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Resource getAuthenticatedResource() throws AccessControlException {
      assertAuth();

      return authenticatedResource;
   }

   @Override
   public Resource getSessionResource() throws AccessControlException {
      assertAuth();

      return sessionResource;
   }

   // methods specific AccessControlSession interface

   @Override
   public void assertPostCreateResourcePermission(String resourceClassName,
                                                  ResourcePermission requestedResourcePermission)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertResourceClassNotBlank(resourceClassName);
      assertPermissionSpecified(requestedResourcePermission);

      try {
         connection = getConnection();

         __assertPostCreateResourcePermission(connection, resourceClassName,
                                              requestedResourcePermission,
                                              sessionResourceDomainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void assertPostCreateResourcePermission(String resourceClassName,
                                                  ResourcePermission requestedResourcePermission,
                                                  String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();
      assertResourceClassNotBlank(resourceClassName);
      assertPermissionSpecified(requestedResourcePermission);
      assertDomainSpecified(domainName);

      try {
         connection = getConnection();

         __assertPostCreateResourcePermission(connection, resourceClassName, requestedResourcePermission, domainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __assertPostCreateResourcePermission(SQLConnection connection,
                                                     String resourceClassName,
                                                     ResourcePermission requestedResourcePermission,
                                                     String domainName)
         throws AccessControlException {
      assertPermissionValid(connection, resourceClassName, requestedResourcePermission);

      boolean createSysPermissionFound = false;
      final Set<ResourceCreatePermission> effectiveResourceCreatePermissions
            = __getEffectiveResourceCreatePermissions(connection,
                                                      sessionResource,
                                                      resourceClassName,
                                                      domainName);

      for (ResourceCreatePermission resourceCreatePermission : effectiveResourceCreatePermissions) {
         if (resourceCreatePermission.isSystemPermission()
               && ResourceCreatePermission.CREATE.equals(resourceCreatePermission.getSysPermissionName())) {
            createSysPermissionFound = true;
            break;
         }
      }

      if (createSysPermissionFound) {
         final Set<ResourcePermission> postCreateResourcePermissions
               = __getPostCreateResourcePermissions(effectiveResourceCreatePermissions);

         if (__containsIgnoringGrant(postCreateResourcePermissions, requestedResourcePermission)) {
            return;
         }

         if (__containsIgnoringGrant(__getEffectiveGlobalPermissions(connection,
                                                                     sessionResource,
                                                                     resourceClassName,
                                                                     domainName),
                                     requestedResourcePermission)) {
            return;
         }
      }

      if (__isSuperUserOfDomain(connection, domainName)) {
         return;
      }

      // if none of the above then complain...
      if (createSysPermissionFound) {
         throw new AccessControlException("No create permission: " + requestedResourcePermission, true);
      }
      else {
         throw new AccessControlException("No *CREATE permission to create any " + resourceClassName
                                                + " resources in domain " + domainName, true);
      }
   }

   @Override
   public void assertGlobalResourcePermission(String resourceClassName, ResourcePermission requestedResourcePermission)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __assertGlobalPermission(connection, resourceClassName, requestedResourcePermission, sessionResourceDomainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void assertGlobalResourcePermission(String resourceClassName,
                                              ResourcePermission requestedResourcePermission,
                                              String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         __assertGlobalPermission(connection, resourceClassName, requestedResourcePermission, domainName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private void __assertGlobalPermission(SQLConnection connection,
                                         String resourceClassName,
                                         ResourcePermission requestedResourcePermission, String domainName)
         throws AccessControlException {
      final Set<ResourcePermission>
            globalResourcePermissions = __getEffectiveGlobalPermissions(connection,
                                                                        sessionResource,
                                                                        resourceClassName,
                                                                        domainName);

      if (__containsIgnoringGrant(globalResourcePermissions, requestedResourcePermission)) {
         return;
      }

      if (__isSuperUserOfDomain(connection, domainName)) {
         return;
      }

      // if none of the above then complain...
      throw new AccessControlException("No global permission: " + requestedResourcePermission,
                                 true);
   }

   @Override
   public void assertResourcePermission(Resource accessedResource, ResourcePermission requestedResourcePermission)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         if (!__hasPermission(connection, sessionResource, accessedResource, requestedResourcePermission)) {
            // if none of the above then complain...
            if (sessionResource.equals(sessionResource)) {
               throw new AccessControlException("Current resource does not have requested permission: "
                                                + requestedResourcePermission,
                                          true);
            }
            else {
               throw new AccessControlException("Resource " + sessionResource + " does not have requested permission: "
                                                + requestedResourcePermission,
                                          true);
            }
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public void assertResourcePermission(Resource accessorResource,
                                        Resource accessedResource,
                                        ResourcePermission requestedResourcePermission)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         if (!__hasPermission(connection, accessorResource, accessedResource, requestedResourcePermission)) {
            // if none of the above then complain...
            if (sessionResource.equals(accessorResource)) {
               throw new AccessControlException("Current resource does not have requested permission: "
                                                + requestedResourcePermission,
                                          true);
            }
            else {
               throw new AccessControlException("Resource " + accessorResource + " does not have requested permission: "
                                                + requestedResourcePermission,
                                          true);
            }
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private boolean __hasPermission(SQLConnection connection,
                                   Resource accessorResource,
                                   Resource accessedResource,
                                   ResourcePermission requestedResourcePermission)
         throws AccessControlException, SQLException {
      // first check for direct resource permissions
      if (__containsIgnoringGrant(__getEffectiveResourcePermissions(connection, accessorResource, accessedResource),
                                  requestedResourcePermission)) {
         return true;
      }

      // next check for global permissions to the domain of the accessed resource
      final String
            resourceClassName = resourceClassPersister.getResourceClassInfoByResourceId(connection,
                                                                                        accessedResource).getResourceClassName();
      final String
            domainName = domainPersister.getResourceDomainNameByResourceId(connection, accessedResource);

      if (__containsIgnoringGrant(__getEffectiveGlobalPermissions(connection,
                                                                  accessorResource,
                                                                  resourceClassName,
                                                                  domainName),
                                  requestedResourcePermission)) {
         return true;
      }

      if (__isSuperUserOfDomain(connection, domainName)) {
         return true;
      }

      return false;
   }

   private boolean __containsIgnoringGrant(Set<ResourcePermission> resourcePermissions,
                                           ResourcePermission checkResourcePermission) {
      for (ResourcePermission resourcePermission : resourcePermissions) {
         if (resourcePermission.equalsIgnoreGrant(checkResourcePermission)) {
            return true;
         }
      }

      return false;
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(String resourceClassName,
                                                         ResourcePermission resourcePermission)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getResourcesByPermission(connection, sessionResource, resourceClassName, resourcePermission);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getResourcesByPermission(connection, accessorResource, resourceClassName, resourcePermission);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Set<Resource> __getResourcesByPermission(SQLConnection connection,
                                                    Resource accessorResource,
                                                    String resourceClassName,
                                                    ResourcePermission resourcePermission) throws AccessControlException {
      // first verify that resource class is defined
      Id<ResourceClassId> resourceClassId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      Set<Resource> resources = new HashSet<>();

      if (resourcePermission.isSystemPermission()) {
         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionSysPersister.getResourcesBySysPermission(connection,
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
            throw new AccessControlException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }

         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionPersister.getResourcesByPermission(connection,
                                                                                    accessorResource,
                                                                                    resourceClassId,
                                                                                    resourcePermission,
                                                                                    permissionId));

         // get the list of objects of the specified type that the session has access to via global permissions
         resources.addAll(grantGlobalResourcePermissionPersister.getResourcesByPermission(connection,
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
                                                         String domainName)
         throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getResourcesByPermission(connection,
                                           sessionResource,
                                           resourceClassName,
                                           resourcePermission,
                                           domainName
         );
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public Set<Resource> getResourcesByResourcePermission(Resource accessorResource,
                                                         String resourceClassName,
                                                         ResourcePermission resourcePermission,
                                                         String domainName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         if (__hasPermission(connection,
                             sessionResource,
                             accessorResource,
                             ResourcePermission.getInstance(ResourcePermission.IMPERSONATE))
               ||
               __hasPermission(connection,
                               sessionResource,
                               accessorResource,
                               ResourcePermission.getInstance(ResourcePermission.INHERIT))
               ||
               __hasPermission(connection,
                               sessionResource,
                               accessorResource,
                               ResourcePermission.getInstance(ResourcePermission.RESET_PASSWORD))) {
            return __getResourcesByPermission(connection,
                                              accessorResource,
                                              resourceClassName,
                                              resourcePermission,
                                              domainName
            );
         }
         else {
            throw new AccessControlException("Current resource must have IMPERSONATE, RESET_PASSWORD or INHERIT permission to: "
                                             + accessorResource,
                                       true);
         }
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Set<Resource> __getResourcesByPermission(SQLConnection connection,
                                                    Resource accessorResource,
                                                    String resourceClassName,
                                                    ResourcePermission resourcePermission,
                                                    String domainName) throws AccessControlException {
      // first verify that resource class and domain is defined
      Id<ResourceClassId> resourceClassId;
      Id<DomainId> domainId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      domainId = domainPersister.getResourceDomainId(connection, domainName);

      if (domainId == null) {
         throw new AccessControlException("Could not find domain: " + domainName);
      }


      Set<Resource> resources = new HashSet<>();

      if (resourcePermission.isSystemPermission()) {
         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionSysPersister.getResourcesBySysPermission(connection,
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
         permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection, resourceClassId, resourcePermission.getPermissionName());

         if (permissionId == null) {
            throw new AccessControlException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }

         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionPersister.getResourcesByPermission(connection,
                                                                                    accessorResource,
                                                                                    resourceClassId,
                                                                                    domainId,
                                                                                    resourcePermission,
                                                                                    permissionId));

         // get the list of objects of the specified type that the session has access to via global permissions
         resources.addAll(grantGlobalResourcePermissionPersister.getResourcesByPermission(connection,
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
                                                                 ResourcePermission resourcePermission) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return __getAccessorResourcesByPermission(connection, accessedResource, resourceClassName, resourcePermission);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   private Set<Resource> __getAccessorResourcesByPermission(SQLConnection connection,
                                                            Resource accessedResource,
                                                            String resourceClassName,
                                                            ResourcePermission resourcePermission) throws AccessControlException {
      // first verify that resource class is defined
      Id<ResourceClassId> resourceClassId;
      Id<ResourcePermissionId> permissionId;

      resourceClassId = resourceClassPersister.getResourceClassId(connection, resourceClassName);

      if (resourceClassId == null) {
         throw new AccessControlException("Could not find resource class: " + resourceClassName);
      }

      Set<Resource> resources = new HashSet<>();

      if (resourcePermission.isSystemPermission()) {
         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionSysPersister.getAccessorResourcesBySysPermission(connection,
                                                                                                  accessedResource,
                                                                                                  resourceClassId,
                                                                                                  resourcePermission));
      }
      else {
         // check if the non-system permission name is valid
         permissionId = resourceClassPermissionPersister.getResourceClassPermissionId(connection, resourceClassId, resourcePermission.getPermissionName());

         if (permissionId == null) {
            throw new AccessControlException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }

         // get the list of objects of the specified type that the session has access to via direct permissions
         resources.addAll(grantResourcePermissionPersister.getAccessorResourcesByPermission(connection,
                                                                                            accessedResource,
                                                                                            resourceClassId,
                                                                                            resourcePermission,
                                                                                            permissionId));
      }

      return resources;
   }

   @Override
   public List<String> getResourceClassNames() throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return resourceClassPersister.getResourceClassNames(connection);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   @Override
   public List<String> getResourcePermissionNames(String resourceClassName) throws AccessControlException {
      SQLConnection connection = null;

      assertAuth();

      try {
         connection = getConnection();

         return resourceClassPermissionPersister.getPermissionNames(connection, resourceClassName);
      }
      catch (SQLException e) {
         throw new AccessControlException(e);
      }
      finally {
         closeConnection(connection);
      }
   }

   // private shared helper methods

   private boolean __isSuperUserOfResource(SQLConnection connection, Resource resource)
         throws AccessControlException {
      return __isSuperUserOfDomain(connection,
                                   domainPersister.getResourceDomainNameByResourceId(connection,
                                                                                     resource));
   }

   private boolean __isSuperUserOfDomain(SQLConnection connection, String domainName) throws AccessControlException {
      Set<DomainPermission> domainPermissions = __getEffectiveDomainPermissions(connection,
                                                                                sessionResource,
                                                                                domainName);

      return domainPermissions.contains(DomainPermission_SUPER_USER)
            || domainPermissions.contains(DomainPermission_SUPER_USER_GRANT);
   }

   private Set<DomainPermission> __getPostCreateDomainPermissions(Set<DomainCreatePermission> domainCreatePermissions) {
      Set<DomainPermission> domainPermissions = new HashSet<>();

      for (DomainCreatePermission domainCreatePermission : domainCreatePermissions) {
         domainPermissions.add(domainCreatePermission.getPostCreateDomainPermission());
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

   // shared assets

   private void assertPasswordOK(String password)
         throws AccessControlException {
      if (password == null) {
         throw new AccessControlException("Password expected, none specified");
      }

      if (password.length() != password.trim().length()) {
         throw new AccessControlException("Password may not contain leading/trailing spaces");
      }

      if (password.length() < 6) {
         throw new AccessControlException("Password must have at least 6 characters");
      }
   }

   private void assertPasswordEmpty(String password)
         throws AccessControlException {
      if (password != null && !password.isEmpty()) {
         throw new AccessControlException("Password not permitted for resources of specified class");
      }
   }

   private void assertDomainSpecified(String domainName)
         throws AccessControlException {
      if (domainName == null || domainName.trim().isEmpty()) {
         throw new AccessControlException("Domain required, none specified");
      }
   }

   private void assertParentDomainSpecified(String domainName)
         throws AccessControlException {
      if (domainName == null || domainName.isEmpty()) {
         throw new AccessControlException("Parent domain required, none specified");
      }
   }

   private void assertSysAuth()
         throws AccessControlException {
      if (sessionResource.getId() != SYSTEM_RESOURCE_ID) {
         throw new AccessControlException("Operation requires this session be authenticated by the SYSTEM resource",
                                    true);
      }
   }

   private void assertAuth() throws AccessControlException {
      if (sessionResource == null) {
         throw new AccessControlException("Session not authenticated",
                                    true);
      }
   }

   private void assertNotAuth() throws AccessControlException {
      if (sessionResource != null) {
         throw new AccessControlException("This call is not valid when the session is authenticated",
                                    true);
      }
   }

   private void assertResourceClassNotBlank(String resourceClassName) throws AccessControlException {
      if (resourceClassName == null || resourceClassName.trim().isEmpty()) {
         throw new AccessControlException("Resource class required, none specified");
      }
   }

   private void assertPermissionSpecified(ResourcePermission resourcePermission) throws AccessControlException {
      if (resourcePermission == null) {
         throw new AccessControlException("Resource permission required, none specified");
      }
   }

   private void assertPermissionNameValid(String permissionName) throws AccessControlException {
      if (permissionName == null || permissionName.trim().isEmpty()) {
         throw new AccessControlException("Permission name may not be null or blank");
      }

      if (permissionName.trim().startsWith("*")) {
         throw new AccessControlException("Permission name may not start with asterisk '*'");
      }
   }

   private void assertResourceClassNameValid(String resourceClassName) throws AccessControlException {
      if (resourceClassName == null || resourceClassName.trim().isEmpty()) {
         throw new AccessControlException("Resource class name may not be null or blank");
      }
   }

   private void assertPermissionValid(SQLConnection connection,
                                      String resourceClassName,
                                      ResourcePermission resourcePermission) throws AccessControlException {
      if (!resourcePermission.isSystemPermission()) {
         final List<String> permissionNames
               = resourceClassPermissionPersister.getPermissionNames(connection, resourceClassName);
         if (!permissionNames.contains(resourcePermission.getPermissionName())) {
            throw new AccessControlException("Permission: " + resourcePermission + " is not defined for resource class: " + resourceClassName);
         }
      }
   }

   // private connection management helper methods

   private SQLConnection getConnection() throws SQLException, AccessControlException {
      if (dataSource != null) {
         return new SQLConnection(dataSource.getConnection());
      }
      else if (connection != null) {
         return new SQLConnection(connection);
      }
      else {
         throw new AccessControlException("Not initialized! No data source or connection, perhaps missing call to postDeserialize()?");
      }
   }

   private void closeConnection(SQLConnection connection) throws AccessControlException {
      // only close the connection if we got it from a pool, otherwise just leave the connection open
      if (dataSource != null) {
         if (connection != null) {
            try {
               connection.close();
            }
            catch (SQLException e) {
               throw new AccessControlException(e);
            }
         }
      }
   }

   private class PasswordAuthenticationProvider implements AuthenticationProvider {
      @Override
      public void setContext(AuthenticationProviderContext context) throws AccessControlException {
         // nothing to do here, since this method will not get called for this built-in implementation
      }

      @Override
      public void authenticate(Credentials credentials) throws AccessControlException {
         if (!(credentials instanceof PasswordCredentials)) {
            throw new AccessControlException("Unsupported credentials implementation: " + credentials.getClass());
         }

         final PasswordCredentials passwordCredentials = ((PasswordCredentials) credentials);

         SQLConnection connection = null;
         try {
            connection = getConnection();

            __authenticate(connection, passwordCredentials.getResource(), passwordCredentials.getPassword());
         }
         catch (SQLException e) {
            throw new AccessControlException(e);
         }
         finally {
            closeConnection(connection);
         }
      }

      private void __authenticate(SQLConnection connection, Resource resource, String password)
            throws AccessControlException, SQLException {
         // first locate the resource
         final String encryptedBoundPassword = resourcePersister.getEncryptedBoundPasswordByResourceId(connection, resource);

         final String plainBoundPassword = PasswordUtils.computeBoundPassword(resource, password);

         if (!passwordEncryptor.checkPassword(plainBoundPassword, encryptedBoundPassword)) {
            throw new AccessControlException("Invalid password, " + resource, true);
         }
      }

      @Override
      public void updateCredentials(Credentials credentials) throws AccessControlException {
         if (!(credentials instanceof PasswordCredentials)) {
            throw new AccessControlException("Unsupported credentials implementation: " + credentials.getClass());
         }

         final PasswordCredentials passwordCredentials = ((PasswordCredentials) credentials);

         SQLConnection connection = null;
         try {
            connection = getConnection();

            __setResourcePassword(connection,
                                  passwordCredentials.getResource(),
                                  passwordCredentials.getPassword());
         }
         catch (SQLException e) {
            throw new AccessControlException(e);
         }
         finally {
            closeConnection(connection);
         }
      }

      private void __setResourcePassword(SQLConnection connection, Resource resource, String newPassword)
            throws AccessControlException, SQLException {
         final String encryptedBoundPassword = resourcePersister.getEncryptedBoundPasswordByResourceId(connection, resource);

         // complain if the resource has no password set
         if (encryptedBoundPassword == null) {
            throw new AccessControlException(resource + " has no password set (assuming not authenticatable), cannot set new password");
         }

         // if all ok, set new password
         final String newBoundPassword = PasswordUtils.computeBoundPassword(resource, newPassword);
         final String newEncryptedBoundPassword = passwordEncryptor.encryptPassword(newBoundPassword);
         resourcePersister.updateEncryptedBoundPasswordByResourceId(connection,
                                                                    resource,
                                                                    newEncryptedBoundPassword);
      }
   }

   private static class AuthenticationProviderContextImpl implements AuthenticationProviderContext {
      private final AuthenticationProvider builtInAuthenticationProvider;

      private AuthenticationProviderContextImpl(AuthenticationProvider builtInAuthenticationProvider) {
         this.builtInAuthenticationProvider = builtInAuthenticationProvider;
      }

      public AuthenticationProvider getBuiltInAuthenticationProvider() {
         return builtInAuthenticationProvider;
      }
   }
}