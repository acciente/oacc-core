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
package com.acciente.oacc.sql;

import com.acciente.oacc.AccessControlContext;
import com.acciente.oacc.AccessControlException;
import com.acciente.oacc.PasswordCredentialsBuilder;
import com.acciente.oacc.ResourceCreatePermission;
import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.Resource;
import com.acciente.oacc.helper.SQLAccessControlSystemResetUtil;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class TestSQLAccessControlContext extends TestSQLAccessControlContextBase {
   // domain permissions constants
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN       = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN, false);
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN_GRANT = DomainPermission.getInstance(DomainPermission.CREATE_CHILD_DOMAIN, true);
   private static final DomainPermission DomainPermission_SUPER_USER                = DomainPermission.getInstance(DomainPermission.SUPER_USER, false);
   private static final DomainPermission DomainPermission_SUPER_USER_GRANT          = DomainPermission.getInstance(DomainPermission.SUPER_USER, true);

   public static void main(String args[]) throws SQLException, IOException, ClassNotFoundException, IllegalAccessException, InstantiationException, InterruptedException, AccessControlException {
      if (!checkDBConnectArgs(args)) {
         return;
      }

      readDBConnectArgs(args);

      //      test_authenticate();
      //      test_createResourceClass();
      //      test_createResourceClassPermissions();
      //      test_createDomain();
      //      test_createResource();
      //      test_createResource_NonAuth();
      //      test_setDomainCreate_1();
      //      test_setDomainCreate_2();
      //      test_setPermissions();
      //      test_setGlobalPermissions();
      //      test_getResourcesByPermission();
      //      test_getResourceClassNames();
      //      test_getDomainDescendants();
      //      test_getSingletonResource();
      test_serializability();
   }

   private static AccessControlContext newSQLAccessControlContext()
         throws SQLException, InterruptedException, AccessControlException {
      Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPwd);
      SQLAccessControlSystemResetUtil.resetOACC(connection, dbSchema, oaccRootPwd);
      return SQLAccessControlContextFactory.getAccessControlContext(connection, dbSchema, SQLDialect.DB2_10_5);
   }

   private static void authSysResource(final AccessControlContext accessControlContext) {
      Resource sysAuthResource = Resource.getInstance(0);

      setupName("ACS authenticate( SYSTEM, valid-password )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(sysAuthResource,
                                                                                             oaccRootPwd));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }
   }

   private static void test_authenticate() throws SQLException, InterruptedException, AccessControlException {
      testName("test_authenticate");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      Resource sysAuthResource = Resource.getInstance(0);

      testName("authenticate( resource-0, <invalid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(sysAuthResource,
                                                                                             "foobar"));
         testFail();
      }
      catch (AccessControlException e) {
         if (e.getMessage().toLowerCase().contains("invalid password")) {
            testOK();
         }
         else {
            testFail(e);
         }
      }

      testName("authenticate( resource-0, valid-password )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(sysAuthResource,
                                                                                             oaccRootPwd));

         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_createResourceClass() throws SQLException, InterruptedException, AccessControlException {
      testName("test_createResourceClass");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      testName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResourceClass( BLOG, false )");
      try {
         accessControlContext.createResourceClass("BLOG", false, false);
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to fail
      testName("createResourceClass( USER, true ) : duplicate");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         testFail();
      }
      catch (AccessControlException e) {
         if (e.getMessage().toLowerCase().contains("duplicate")) {
            testOK();
         }
         else {
            testFail(e);
         }
      }

      // we attempt to create a resource which we expect to fail
      testName("createResourceClass( BLOG, false ) : duplicate");
      try {
         accessControlContext.createResourceClass("BLOG", false, false);
         testFail();
      }
      catch (AccessControlException e) {
         if (e.getMessage().toLowerCase().contains("duplicate")) {
            testOK();
         }
         else {
            testFail(e);
         }
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResourceClass( SITE, false )");
      try {
         accessControlContext.createResourceClass("SITE", false, false);
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_createResourceClassPermissions() throws SQLException, InterruptedException, AccessControlException {
      testName("test_createResourceClassPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // first we need to create a permission which we expect to succeed
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail();
      }

      // we attempt to create a permission which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      try {
         accessControlContext.createResourceClass("BLOG", false, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail();
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, VIEW )");
      try {
         accessControlContext.createResourcePermission("USER", "VIEW");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, CHANGE )");
      try {
         accessControlContext.createResourcePermission("USER", "CHANGE");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, CREATE-POST )");
      try {
         accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, EDIT-POST )");
      try {
         accessControlContext.createResourcePermission("BLOG", "EDIT-POST");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, VIEW ) : duplicate");
      try {
         accessControlContext.createResourcePermission("USER", "VIEW");
         testFail();
      }
      catch (AccessControlException e) {
         testOK();
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, CHANGE ) : duplicate");
      try {
         accessControlContext.createResourcePermission("USER", "CHANGE");
         testFail();
      }
      catch (AccessControlException e) {
         testOK();
      }
   }

   private static void test_createDomain() throws SQLException, InterruptedException, AccessControlException {
      testName("test_createDomain");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      testName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createDomain( INFO-SOLUTIONS )");
      try {
         accessControlContext.createDomain("INFO-SOLUTIONS");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_createResource() throws AccessControlException, SQLException, InterruptedException {
      testName("test_createResource");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      try {
         accessControlContext.createResourceClass("BLOG", false, false);
         accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp )");
      try {
         acmeRootUser = accessControlContext.createAuthenticatableResource("USER", "ACMECorp", "foobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we grant the new user permission to create BLOGs
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, true));
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.INHERIT), true));
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourcePermission.getInstance("CREATE-POST"), true));

      setupName("setResourceCreatePermissions( acmeRootUser, BLOG, " + resourceCreatePermissions + " )");
      try {
         accessControlContext.setResourceCreatePermissions(acmeRootUser,
                                                           "BLOG",
                                                           resourceCreatePermissions, "ACMECorp"
         );
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(acmeRootUser, "foobar"));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_createResource_NonAuth() throws AccessControlException, SQLException, InterruptedException {
      testName("test_createResource_NonAuth");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true, true )");
      try {
         accessControlContext.createResourceClass("USER", true, true);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      try {
         accessControlContext.createResourceClass("BLOG", false, false);
         accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      accessControlContext.unauthenticate();

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp )");
      try {
         acmeRootUser = accessControlContext.createAuthenticatableResource("USER", "ACMECorp", "foobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we grant the new user permission to create BLOGs
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, true));
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourcePermission.getInstance(ResourcePermission.INHERIT), true));
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourcePermission.getInstance("CREATE-POST"), true));

      setupName("setResourceCreatePermissions( acmeRootUser, BLOG, " + resourceCreatePermissions + " )");
      try {
         accessControlContext.setResourceCreatePermissions(acmeRootUser,
                                                           "BLOG",
                                                           resourceCreatePermissions, "ACMECorp"
         );
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(acmeRootUser, "foobar"));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_setDomainCreate_1() throws SQLException, InterruptedException, AccessControlException {
      testName("test_setDomainCreate_1");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp, <pwd> )");
      try {
         acmeRootUser = accessControlContext.createAuthenticatableResource("USER", "ACMECorp", "foobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(acmeRootUser, "foobar"));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      String clientDomain = "ScottsdaleCardiologyAssociates";

      // we expect the create domain below to fail, since the new use does not have domain create permissions
      testName("createDomain( \"" + clientDomain + "\" ) : NO AUTH");
      try {
         accessControlContext.createDomain(clientDomain);
         testFail();
      }
      catch (AccessControlException e) {
         testOK();
      }
   }

   private static void test_setDomainCreate_2() throws SQLException, InterruptedException, AccessControlException {
      testName("test_setDomainCreate_2");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we create a user resource type
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp )");
      try {
         acmeRootUser = accessControlContext.createAuthenticatableResource("USER", "ACMECorp", "foobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we permit the new user to create child domains in the ACMECorp domain
      Set<DomainPermission> domainPermissions = new HashSet<>();
      domainPermissions.add(DomainPermission_CREATE_CHILD_DOMAIN);
      setupName("setDomainPermissions( acmeRootUser, ACMECorp, " + domainPermissions + " )");
      try {
         accessControlContext.setDomainPermissions(acmeRootUser, "ACMECorp", domainPermissions);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we permit the new user to new create new domains
      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(DomainCreatePermission.getInstance(DomainCreatePermission.CREATE, false));
      domainCreatePermissions.add(DomainCreatePermission.getInstance(DomainPermission_SUPER_USER, false));
      setupName("setDomainCreatePermissions( acmeRootUser, \"" + domainCreatePermissions + "\" )");
      try {
         accessControlContext.setDomainCreatePermissions(acmeRootUser, domainCreatePermissions);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we re-auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(acmeRootUser, "foobar"));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      String clientDomain = "ScottsdaleCardiologyAssociates";

      // we expect the create domain below to fail, since the new use does not have domain create permissions
      testName("createDomain( \"" + clientDomain + "\", \"ACMECorp\" ) : AUTH OK");
      try {
         accessControlContext.createDomain(clientDomain, "ACMECorp");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_setPermissions() throws SQLException, InterruptedException, AccessControlException {
      testName("test_setPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      Resource newUser_1 = null;
      Resource newUser_2 = null;

      // we create new user #1
      setupName("newUser_1 = createAuthResource( USER, <pwd> )");
      try {
         newUser_1 = accessControlContext.createAuthenticatableResource("USER", "foobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we create new user #2
      setupName("newUser_2 = createAuthResource( USER, <pwd> )");
      try {
         newUser_2 = accessControlContext.createAuthenticatableResource("USER", "goobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we give user 1 some domain create permissions
      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(DomainCreatePermission.getInstance(DomainCreatePermission.CREATE, false));
      domainCreatePermissions.add(DomainCreatePermission.getInstance(DomainPermission_SUPER_USER, false));
      setupName("setDomainCreatePermissions( newUser_1, \"" + domainCreatePermissions + "\" )");
      try {
         accessControlContext.setDomainCreatePermissions(newUser_1, domainCreatePermissions);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      setupName("getEffectiveDomainCreatePermissions( newUser_1 )");
      try {
         System.out.print(accessControlContext.getEffectiveDomainCreatePermissions(newUser_1));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      setupName("getEffectiveDomainCreatePermissions( newUser_2 )");
      try {
         System.out.print(accessControlContext.getEffectiveDomainCreatePermissions(newUser_2));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // give user 2 inherit permission on user 1
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      setupName("setResourcePermissions( newUser_2, newUser_1, \"" + resourcePermissions + "\" )");
      try {
         accessControlContext.setResourcePermissions(newUser_2, newUser_1, resourcePermissions);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      testName("setResourcePermissions( newUser_1, newUser_2, \"" + resourcePermissions + "\" ) [attempt to create an inherit cycle]");
      try {
         accessControlContext.setResourcePermissions(newUser_1, newUser_2, resourcePermissions);
         testFail();
      }
      catch (AccessControlException e) {
         testOK(e);
      }

      testName("assert: getEffectiveDomainCreatePermissions( newUser_1 ) equals getEffectiveDomainCreatePermissions( newUser_2 )");
      try {
         Set<DomainCreatePermission> newUser_1_Permissions = accessControlContext.getEffectiveDomainCreatePermissions(newUser_1);
         Set<DomainCreatePermission> newUser_2_Permissions = accessControlContext.getEffectiveDomainCreatePermissions(newUser_2);

         if (newUser_1_Permissions.equals(newUser_2_Permissions)) {
            System.out.println();
            System.out.println("User 1 permissions: " + newUser_1_Permissions);
            System.out.println("User 2 permissions: " + newUser_2_Permissions);

            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_setGlobalPermissions() throws SQLException, InterruptedException, AccessControlException {
      testName("test_setPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource class which we expect to succeed
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a resource class permission which we expect to succeed
      setupName("createResourcePermission( USER, VIEW )");
      try {
         accessControlContext.createResourcePermission("USER", "VIEW");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      Resource newUser_1 = null;

      // we create new user #1
      setupName("newUser_1 = createAuthResource( USER, <pwd> )");
      try {
         newUser_1 = accessControlContext.createAuthenticatableResource("USER", "foobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we give user 1 some domain create permissions
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.IMPERSONATE));
      resourcePermissions.add(ResourcePermission.getInstance("VIEW"));
      setupName("setGlobalResourcePermissions( newUser_1, \"" + resourcePermissions + "\" )");
      try {
         accessControlContext.setGlobalResourcePermissions(newUser_1, "USER", resourcePermissions);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      testName("assert: getEffectiveGlobalResourcePermissions( newUser_1 ) equals " + resourcePermissions);
      try {
         Set<ResourcePermission> newUser_1_ResourcePermissions = accessControlContext.getEffectiveGlobalResourcePermissions(newUser_1, "USER");

         if (newUser_1_ResourcePermissions.equals(resourcePermissions)) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
         e.printStackTrace();
      }
   }

   private static void test_getResourcesByPermission() throws SQLException, InterruptedException, AccessControlException {
      testName("test_getResourcesByPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we create a user resource type
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we create a blog resource type
      setupName("createResourceClass( BLOG, false )");
      try {
         accessControlContext.createResourceClass("BLOG", false, false);
         accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
         accessControlContext.createResourcePermission("BLOG", "EDIT-POST");
         accessControlContext.createResourcePermission("BLOG", "DELETE-POST");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      Resource newUser_1 = null;
      Resource newUser_2 = null;

      // we create new user #1
      setupName("newUser_1 = createAuthResource( USER, <pwd> )");
      try {
         newUser_1 = accessControlContext.createAuthenticatableResource("USER", "foobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we create new user #2
      setupName("newUser_2 = createAuthResource( USER, <pwd> )");
      try {
         newUser_2 = accessControlContext.createAuthenticatableResource("USER", "goobar");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we give user 1 some create permissions
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourceCreatePermission.CREATE, true));
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourcePermission.getInstance("CREATE-POST", true), false));
      resourceCreatePermissions.add(ResourceCreatePermission.getInstance(ResourcePermission.getInstance("EDIT-POST", false), false));
      setupName("setCreatePermission( newUser_1, \"" + resourceCreatePermissions + "\" )");
      try {
         accessControlContext.setResourceCreatePermissions(newUser_1, "BLOG", resourceCreatePermissions);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we auth as user #1
      setupName("authenticate( newUser_1, <valid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(newUser_1, "foobar"));
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(newUser_1, "foobar"));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next user 1 creates 15 blogs
      setupName("15 x createResource( BLOG )");
      try {
         for (int i = 0; i < 15; i++) {
            accessControlContext.createResource("BLOG");
         }
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      final ResourcePermission filterPermission = ResourcePermission.getInstance("CREATE-POST", false);
      setupName("getResourcesByPermissions( BLOG, " + filterPermission + " )");
      Set<Resource> newUser_1_ResourceList;
      try {
         newUser_1_ResourceList = accessControlContext.getResourcesByResourcePermission("BLOG", filterPermission);
         System.out.print(newUser_1_ResourceList);
         setupOK();
      }
      catch (AccessControlException e) {
         newUser_1_ResourceList = null;
         setupFail(e);
      }

      // next we auth as user #2
      setupName("authenticate( newUser_2, <valid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(newUser_2, "goobar"));
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(newUser_2, "goobar"));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      setupName("getResourcesByPermissions( BLOG, " + filterPermission + " )");
      try {
         System.out.print(accessControlContext.getResourcesByResourcePermission("BLOG", filterPermission));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we auth as the system resource
      authSysResource(accessControlContext);
      authSysResource(accessControlContext);

      // next we give user 2 inherit permissions on user 1
      final Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermission.getInstance(ResourcePermission.INHERIT));
      setupName("setResourcePermissions( newUser_2, newUser_1, \"" + resourcePermissions + "\" )");
      try {
         accessControlContext.setResourcePermissions(newUser_2, newUser_1, resourcePermissions);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // next we auth as user #2
      setupName("authenticate( newUser_2, <valid-pwd> )");
      try {
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(newUser_2, "goobar"));
         accessControlContext.authenticate(PasswordCredentialsBuilder.newPasswordCredentials(newUser_2, "goobar"));
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      setupName("getResourcesByResourcePermission( BLOG, " + filterPermission + " )");
      Set<Resource> newUser_2_ResourceList;
      try {
         newUser_2_ResourceList = accessControlContext.getResourcesByResourcePermission("BLOG", filterPermission);
         System.out.print(newUser_2_ResourceList);
         setupOK();
      }
      catch (AccessControlException e) {
         newUser_2_ResourceList = null;
         setupFail(e);
      }

      testName("assert: NewUser_1->getResourcesByResourcePermission( BLOG, " + filterPermission + " ) equals NewUser_2->getResourcesByResourcePermission( BLOG, " + filterPermission + " )");
      if (newUser_1_ResourceList.size() == 15
            && newUser_2_ResourceList.size() == 15
            && newUser_1_ResourceList.equals(newUser_2_ResourceList)) {
         testOK();
      }
      else {
         testFail();
      }
   }

   private static void test_getResourceClassNames() throws SQLException, InterruptedException, AccessControlException {
      testName("test_getResourceClassNames");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // first we need to create a permission which we expect to succeed
      setupName("createResourceClass( USER, true )");
      try {
         accessControlContext.createResourceClass("USER", true, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail();
      }

      // we attempt to create a permission which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      try {
         accessControlContext.createResourceClass("BLOG", false, false);
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail();
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, VIEW )");
      try {
         accessControlContext.createResourcePermission("USER", "VIEW");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, CHANGE )");
      try {
         accessControlContext.createResourcePermission("USER", "CHANGE");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, CREATE-POST )");
      try {
         accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, EDIT-POST )");
      try {
         accessControlContext.createResourcePermission("BLOG", "EDIT-POST");
         testOK();
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      testName("new HashSet( accessControlContext.getResourceClassNames() ).equals( new HashSet( Arrays.asList( \"USER\", \"BLOG\" ) )");
      try {
         if (new HashSet(accessControlContext.getResourceClassNames()).equals(new HashSet(Arrays.asList("USER", "BLOG")))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      testName("new HashSet( accessControlContext.getResourcePermissionNames( \"USER\" ) ).equals( new HashSet( Arrays.asList( \"VIEW\", \"CHANGE\" ) ) )");
      try {
         if (new HashSet(accessControlContext.getResourcePermissionNames("USER")).equals(new HashSet(Arrays.asList("VIEW", "CHANGE")))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      testName("new HashSet( accessControlContext.getResourcePermissionNames( \"BLOG\" ) ).equals( new HashSet( Arrays.asList( \"CREATE-POST\", \"EDIT-POST\" ) ) )");
      try {
         if (new HashSet(accessControlContext.getResourcePermissionNames("BLOG")).equals(new HashSet(Arrays.asList("CREATE-POST", "EDIT-POST")))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_getDomainDescendants() throws SQLException, InterruptedException, AccessControlException {
      testName("test_getDomainDescendants");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createDomain( ROOT-DOMAIN-1 )");
      try {
         accessControlContext.createDomain("ROOT-DOMAIN-1");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-1, ROOT-DOMAIN-1 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-1", "ROOT-DOMAIN-1");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-2, ROOT-DOMAIN-1 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-2", "ROOT-DOMAIN-1");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-3, CHILD-DOMAIN-1 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-3", "CHILD-DOMAIN-1");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-4, CHILD-DOMAIN-3 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-4", "CHILD-DOMAIN-3");
         setupOK();
      }
      catch (AccessControlException e) {
         setupFail(e);
      }

      testName("getDomainDescendants( CHILD-DOMAIN-4 ) = { CHILD-DOMAIN-4 } ");
      try {
         String domainName = "CHILD-DOMAIN-4";
         List expected = Arrays.asList("CHILD-DOMAIN-4");

         if (accessControlContext.getDomainDescendants(domainName).equals(new HashSet(expected))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      testName("getDomainDescendants( CHILD-DOMAIN-3 ) = { CHILD-DOMAIN-3, CHILD-DOMAIN-4 } ");
      try {
         String domainName = "CHILD-DOMAIN-3";
         List expected = Arrays.asList("CHILD-DOMAIN-3", "CHILD-DOMAIN-4");

         if (accessControlContext.getDomainDescendants(domainName).equals(new HashSet(expected))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      testName("getDomainDescendants( CHILD-DOMAIN-2 ) = { CHILD-DOMAIN-2 } ");
      try {
         String domainName = "CHILD-DOMAIN-2";
         List expected = Arrays.asList("CHILD-DOMAIN-2");

         if (accessControlContext.getDomainDescendants(domainName).equals(new HashSet(expected))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      testName("getDomainDescendants( CHILD-DOMAIN-1 ) = { CHILD-DOMAIN-1, CHILD-DOMAIN-3, CHILD-DOMAIN-4 } ");
      try {
         String domainName = "CHILD-DOMAIN-1";
         List expected = Arrays.asList("CHILD-DOMAIN-1", "CHILD-DOMAIN-3", "CHILD-DOMAIN-4");

         if (accessControlContext.getDomainDescendants(domainName).equals(new HashSet(expected))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }

      testName("getDomainDescendants( ROOT-DOMAIN-1 ) = { ROOT-DOMAIN-1, CHILD-DOMAIN-1, CHILD-DOMAIN-2, CHILD-DOMAIN-3, CHILD-DOMAIN-4 } ");
      try {
         String domainName = "ROOT-DOMAIN-1";
         List expected = Arrays.asList("ROOT-DOMAIN-1", "CHILD-DOMAIN-1", "CHILD-DOMAIN-2", "CHILD-DOMAIN-3", "CHILD-DOMAIN-4");

         if (accessControlContext.getDomainDescendants(domainName).equals(new HashSet(expected))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (AccessControlException e) {
         testFail(e);
      }
   }

   private static void test_serializability() throws SQLException, InterruptedException, IOException, AccessControlException {
      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      ObjectOutputStream objectOutputStream = new ObjectOutputStream(new ByteArrayOutputStream());

      testName("test_serializability()");
      try {
         SQLAccessControlContextFactory.preSerialize(accessControlContext);

         objectOutputStream.writeObject(accessControlContext);

         testOK();
      }
      catch (NotSerializableException e) {
         testFail(e);
      }
      finally {
         objectOutputStream.close();
      }
   }
}

// EOF