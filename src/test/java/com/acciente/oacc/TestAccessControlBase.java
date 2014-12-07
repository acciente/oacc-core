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
package com.acciente.oacc;

import com.acciente.oacc.helper.Constants;
import com.acciente.oacc.helper.SQLAccessControlSystemResetUtil;
import com.acciente.oacc.helper.TestDataSourceFactory;
import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import com.acciente.oacc.sql.SQLDialect;
import org.junit.After;
import org.junit.Before;

import javax.sql.DataSource;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class TestAccessControlBase {
   public static final Resource SYS_RESOURCE = Resources.getInstance(0);

   private static SQLDialect           sqlDialect;
   private static DataSource           dataSource;
   private static AccessControlContext systemAccessControlContext;
   private static boolean              isDBCaseSensitive;

   static {
      sqlDialect = TestDataSourceFactory.getSQLDialect();
      try {
         dataSource = TestDataSourceFactory.getDataSource();
         isDBCaseSensitive = TestDataSourceFactory.isDatabaseCaseSensitive();
         systemAccessControlContext
               = SQLAccessControlContextFactory.getAccessControlContext(dataSource, Constants.DB_SCHEMA, sqlDialect);
      }
      catch (SQLException | AccessControlException e) {
         throw new RuntimeException(e);
      }
   }

   protected AccessControlContext accessControlContext;

   @Before
   public void setUpTest() throws Exception {
      SQLAccessControlSystemResetUtil.resetOACC(dataSource, Constants.DB_SCHEMA, Constants.OACC_ROOT_PWD);
      accessControlContext
            = SQLAccessControlContextFactory.getAccessControlContext(dataSource, Constants.DB_SCHEMA, sqlDialect);
   }

   @After
   public void tearDownTest() throws Exception {
      accessControlContext.unauthenticate(); // because it doesn't hurt, in case we authenticated during a test
   }


   public static Resource getSystemResource() {
      return SYS_RESOURCE;
   }

   protected static boolean isDatabaseCaseSensitive() {
      return isDBCaseSensitive;
   }

   protected static String generateDomain() throws AccessControlException {
      authenticateSystemAccessControlContext();
      final String domainName = generateUniqueDomainName();
      systemAccessControlContext.createDomain(domainName);
      return domainName;
   }

   protected static String generateChildDomain(String parentDomainName) throws AccessControlException {
      authenticateSystemAccessControlContext();
      final String domainName = generateUniqueDomainName();
      systemAccessControlContext.createDomain(domainName, parentDomainName);
      return domainName;
   }

   protected static String generateResourceClass(boolean authenticatable,
                                                 boolean nonAuthenticatedCreateAllowed) throws AccessControlException {
      authenticateSystemAccessControlContext();
      final String resourceClassName = generateUniqueResourceClassName();
      systemAccessControlContext.createResourceClass(resourceClassName, authenticatable, nonAuthenticatedCreateAllowed);
      return resourceClassName;
   }

   protected static String generateResourceClassPermission(String resourceClassName) throws AccessControlException {
      authenticateSystemAccessControlContext();
      final String permissionName = generateUniquePermissionName();
      systemAccessControlContext.createResourcePermission(resourceClassName, permissionName);
      return permissionName;
   }

   private static void authenticateSystemAccessControlContext() throws AccessControlException {
      systemAccessControlContext.authenticate(SYS_RESOURCE,
                                              PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
   }

   protected void authenticateSystemResource() throws AccessControlException {
      accessControlContext.authenticate(SYS_RESOURCE,
                                        PasswordCredentials.newInstance(Constants.OACC_ROOT_PWD));
   }

   public static String generateUniqueDomainName() {
      return "rd_" + generateUniqueID();
   }

   public static String generateUniqueResourceClassName() {
      return "rc_" + generateUniqueID();
   }

   public static String generateUniquePermissionName() {
      return "p_" + generateUniqueID();
   }

   public static char[] generateUniquePassword() {
      return ("pwd_" + generateUniqueID()).toCharArray();
   }

   private static long generateUniqueID() {
      return System.nanoTime();
   }

   protected Resource generateResourceAndAuthenticate() throws AccessControlException {
      authenticateSystemAccessControlContext();
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.authenticate(authenticatableResource,
                                        PasswordCredentials.newInstance(password));
      return authenticatableResource;
   }

   protected Resource generateAuthenticatableResource(char[] password) throws AccessControlException {
      authenticateSystemAccessControlContext();
      return systemAccessControlContext.createResource(generateResourceClass(true, false), generateDomain(),
                                                       PasswordCredentials.newInstance(password));
   }

   protected Resource generateUnauthenticatableResource() throws AccessControlException {
      authenticateSystemAccessControlContext();
      return systemAccessControlContext.createResource(generateResourceClass(false, true), generateDomain());
   }

   protected String generateResourceClassSingleton(String domainName) throws AccessControlException {
      authenticateSystemAccessControlContext();
      final String resourceClassName = generateResourceClass(false, true);
      systemAccessControlContext.createResource(resourceClassName, domainName);
      return resourceClassName;
   }

   protected void grantDomainCreatePermission(Resource accessorResource) throws AccessControlException {
      authenticateSystemAccessControlContext();
      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(DomainCreatePermission.getInstance(DomainCreatePermission.CREATE,
                                                               false));

      systemAccessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);
   }

   protected void grantDomainAndChildCreatePermission(Resource accessorResource) throws AccessControlException {
      authenticateSystemAccessControlContext();
      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(DomainCreatePermission.getInstance(DomainCreatePermission.CREATE,
                                                               false));
      domainCreatePermissions.add(DomainCreatePermission.getInstance(DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN),
                                                               false));

      systemAccessControlContext.setDomainCreatePermissions(accessorResource, domainCreatePermissions);
   }

   protected void grantResourceCreatePermission(Resource accessorResource,
                                                String resourceClassName,
                                                String domainName,
                                                String... permissionNames) throws AccessControlException {
      authenticateSystemAccessControlContext();
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, false));
      // create & add each unique permission
      Set<String> uniquePermissionNames = new HashSet<>();
      Collections.addAll(uniquePermissionNames, permissionNames);
      for (String permissionName : uniquePermissionNames) {
         resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourcePermission.getInstance(permissionName)));
      }

      systemAccessControlContext.setResourceCreatePermissions(accessorResource,
                                                              resourceClassName,
                                                              resourceCreatePermissions, domainName
      );
   }
}