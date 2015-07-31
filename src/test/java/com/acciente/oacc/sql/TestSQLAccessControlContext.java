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
package com.acciente.oacc.sql;

import com.acciente.oacc.AccessControlContext;
import com.acciente.oacc.DomainCreatePermission;
import com.acciente.oacc.DomainCreatePermissions;
import com.acciente.oacc.DomainPermission;
import com.acciente.oacc.DomainPermissions;
import com.acciente.oacc.OaccException;
import com.acciente.oacc.PasswordCredentials;
import com.acciente.oacc.Resource;
import com.acciente.oacc.ResourceCreatePermission;
import com.acciente.oacc.ResourceCreatePermissions;
import com.acciente.oacc.ResourcePermission;
import com.acciente.oacc.ResourcePermissions;
import com.acciente.oacc.Resources;
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
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN       = DomainPermissions.getInstance(
         DomainPermissions.CREATE_CHILD_DOMAIN,
         false);
   private static final DomainPermission DomainPermission_CREATE_CHILD_DOMAIN_GRANT = DomainPermissions.getInstance(
         DomainPermissions.CREATE_CHILD_DOMAIN,
         true);
   private static final DomainPermission DomainPermission_SUPER_USER                = DomainPermissions.getInstance(
         DomainPermissions.SUPER_USER,
         false);
   private static final DomainPermission DomainPermission_SUPER_USER_GRANT          = DomainPermissions.getInstance(
         DomainPermissions.SUPER_USER,
         true);
   public static final  char[]           PASSWORD                                   = "foobar".toCharArray();
   public static final  char[]           PASSWORD2                                  = "goobar".toCharArray();

   public static void main(String args[]) throws SQLException, IOException {
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
         throws SQLException {
      Connection connection = DriverManager.getConnection(dbUrl, dbUser, dbPwd);
      SQLAccessControlSystemResetUtil.resetOACC(connection, dbSchema, oaccRootPwd);
      return SQLAccessControlContextFactory.getAccessControlContext(connection, dbSchema, SQLType.DB2_10_5_RECURSIVE);
   }

   private static void authSysResource(final AccessControlContext accessControlContext) {
      Resource sysAuthResource = Resources.getInstance(0);

      setupName("authenticate( SYSTEM, valid-password )");
      try {
         accessControlContext.authenticate(sysAuthResource, PasswordCredentials.newInstance(oaccRootPwd));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }
   }

   private static void test_authenticate() throws SQLException {
      testName("test_authenticate");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      Resource sysAuthResource = Resources.getInstance(0);

      testName("authenticate( resource-0, <invalid-pwd> )");
      try {
         accessControlContext.authenticate(sysAuthResource, PasswordCredentials.newInstance(PASSWORD));
         testFail();
      }
      catch (OaccException e) {
         if (e.getMessage().toLowerCase().contains("invalid password")) {
            testOK();
         }
         else {
            testFail(e);
         }
      }

      testName("authenticate( resource-0, valid-password )");
      try {
         accessControlContext.authenticate(sysAuthResource, PasswordCredentials.newInstance(oaccRootPwd));

         testOK();
      }
      catch (Exception e) {
         testFail(e);
      }
   }

   private static void test_createResourceClass() throws SQLException {
      testName("test_createResourceClass");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      testName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      testOK();

      // we attempt to create a resource which we expect to succeed
      testName("createResourceClass( BLOG, false )");
      accessControlContext.createResourceClass("BLOG", false, false);
      testOK();

      // we attempt to create a resource which we expect to fail
      testName("createResourceClass( USER, true ) : duplicate");
      accessControlContext.createResourceClass("USER", true, false);
      testFail();

      // we attempt to create a resource which we expect to fail
      testName("createResourceClass( BLOG, false ) : duplicate");
      accessControlContext.createResourceClass("BLOG", false, false);
      testFail();

      // we attempt to create a resource which we expect to succeed
      testName("createResourceClass( SITE, false )");
      accessControlContext.createResourceClass("SITE", false, false);
      testOK();
   }

   private static void test_createResourceClassPermissions() throws SQLException {
      testName("test_createResourceClassPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // first we need to create a permission which we expect to succeed
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      // we attempt to create a permission which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      accessControlContext.createResourceClass("BLOG", false, false);
      setupOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, VIEW )");
      accessControlContext.createResourcePermission("USER", "VIEW");
      testOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, CHANGE )");
      accessControlContext.createResourcePermission("USER", "CHANGE");
      testOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, CREATE-POST )");
      accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
      testOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, EDIT-POST )");
      accessControlContext.createResourcePermission("BLOG", "EDIT-POST");
      testOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, VIEW ) : duplicate");
      accessControlContext.createResourcePermission("USER", "VIEW");
      testFail();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, CHANGE ) : duplicate");
      accessControlContext.createResourcePermission("USER", "CHANGE");
      testFail();
   }

   private static void test_createDomain() throws SQLException {
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
      catch (OaccException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createDomain( INFO-SOLUTIONS )");
      try {
         accessControlContext.createDomain("INFO-SOLUTIONS");
         testOK();
      }
      catch (OaccException e) {
         testFail(e);
      }
   }

   private static void test_createResource() throws SQLException {
      testName("test_createResource");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      accessControlContext.createResourceClass("BLOG", false, false);
      accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
      setupOK();

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp )");
      try {
         acmeRootUser = accessControlContext.createResource("USER", "ACMECorp", PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we grant the new user permission to create BLOGs
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ResourcePermissions.INHERIT), true));
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("CREATE-POST"),
                                                                          true));

      setupName("setResourceCreatePermissions( acmeRootUser, BLOG, " + resourceCreatePermissions + " )");
      try {
         accessControlContext.setResourceCreatePermissions(acmeRootUser,
                                                           "BLOG",
                                                           "ACMECorp",
                                                           resourceCreatePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(acmeRootUser, PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG",
                                             accessControlContext
                                                   .getDomainNameByResource(accessControlContext.getSessionResource()));
         testOK();
      }
      catch (OaccException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG",
                                             accessControlContext
                                                   .getDomainNameByResource(accessControlContext.getSessionResource()));
         testOK();
      }
      catch (OaccException e) {
         testFail(e);
      }
   }

   private static void test_createResource_NonAuth() throws SQLException {
      testName("test_createResource_NonAuth");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true, true )");
      accessControlContext.createResourceClass("USER", true, true);
      setupOK();

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      accessControlContext.createResourceClass("BLOG", false, false);
      accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
      setupOK();

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      accessControlContext.unauthenticate();

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp )");
      try {
         acmeRootUser = accessControlContext.createResource("USER", "ACMECorp", PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we grant the new user permission to create BLOGs
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance(
            ResourcePermissions.INHERIT), true));
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("CREATE-POST"),
                                                                          true));

      setupName("setResourceCreatePermissions( acmeRootUser, BLOG, " + resourceCreatePermissions + " )");
      try {
         accessControlContext.setResourceCreatePermissions(acmeRootUser,
                                                           "BLOG",
                                                           "ACMECorp",
                                                           resourceCreatePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(acmeRootUser, PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG",
                                             accessControlContext
                                                   .getDomainNameByResource(accessControlContext.getSessionResource()));
         testOK();
      }
      catch (OaccException e) {
         testFail(e);
      }

      // we attempt to create a resource which we expect to succeed
      testName("createResource( BLOG )");
      try {
         accessControlContext.createResource("BLOG",
                                             accessControlContext
                                                   .getDomainNameByResource(accessControlContext.getSessionResource()));
         testOK();
      }
      catch (OaccException e) {
         testFail(e);
      }
   }

   private static void test_setDomainCreate_1() throws SQLException {
      testName("test_setDomainCreate_1");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp, <pwd> )");
      try {
         acmeRootUser = accessControlContext.createResource("USER",
                                                            "ACMECorp",
                                                            PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(acmeRootUser, PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      String clientDomain = "ScottsdaleCardiologyAssociates";

      // we expect the create domain below to fail, since the new use does not have domain create permissions
      testName("createDomain( \"" + clientDomain + "\" ) : NO AUTH");
      try {
         accessControlContext.createDomain(clientDomain);
         testFail();
      }
      catch (OaccException e) {
         testOK();
      }
   }

   private static void test_setDomainCreate_2() throws SQLException {
      testName("test_setDomainCreate_2");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we create a user resource type
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      // we create a domain to hold a new user
      setupName("createDomain( ACMECorp )");
      try {
         accessControlContext.createDomain("ACMECorp");
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      Resource acmeRootUser = null;

      // we create a new user in the domain
      setupName("acmeRootUser = createAuthResource( USER, ACMECorp )");
      try {
         acmeRootUser = accessControlContext.createResource("USER",
                                                            "ACMECorp",
                                                            PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
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
      catch (OaccException e) {
         setupFail(e);
      }

      // we permit the new user to new create new domains
      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, false));
      domainCreatePermissions.add(DomainCreatePermissions.getInstance(DomainPermission_SUPER_USER, false));
      setupName("setDomainCreatePermissions( acmeRootUser, \"" + domainCreatePermissions + "\" )");
      try {
         accessControlContext.setDomainCreatePermissions(acmeRootUser, domainCreatePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we re-auth as the new user in the ACMECorp domain
      setupName("authenticate( acmeRootUser, <valid-pwd> )");
      try {
         accessControlContext.authenticate(acmeRootUser, PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      String clientDomain = "ScottsdaleCardiologyAssociates";

      // we expect the create domain below to fail, since the new use does not have domain create permissions
      testName("createDomain( \"" + clientDomain + "\", \"ACMECorp\" ) : AUTH OK");
      try {
         accessControlContext.createDomain(clientDomain, "ACMECorp");
         testOK();
      }
      catch (OaccException e) {
         testFail(e);
      }
   }

   private static void test_setPermissions() throws SQLException {
      testName("test_setPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource which we expect to succeed
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      Resource newUser_1 = null;
      Resource newUser_2 = null;

      // we create new user #1
      setupName("newUser_1 = createAuthResource( USER, <pwd> )");
      try {
         newUser_1 = accessControlContext.createResource("USER",
                                                         accessControlContext
                                                               .getDomainNameByResource(accessControlContext.getSessionResource()),
                                                         PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we create new user #2
      setupName("newUser_2 = createAuthResource( USER, <pwd> )");
      try {
         newUser_2 = accessControlContext.createResource("USER",
                                                         accessControlContext
                                                               .getDomainNameByResource(accessControlContext.getSessionResource()),
                                                         PasswordCredentials.newInstance(PASSWORD2));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we give user 1 some domain create permissions
      Set<DomainCreatePermission> domainCreatePermissions = new HashSet<>();
      domainCreatePermissions.add(DomainCreatePermissions.getInstance(DomainCreatePermissions.CREATE, false));
      domainCreatePermissions.add(DomainCreatePermissions.getInstance(DomainPermission_SUPER_USER, false));
      setupName("setDomainCreatePermissions( newUser_1, \"" + domainCreatePermissions + "\" )");
      try {
         accessControlContext.setDomainCreatePermissions(newUser_1, domainCreatePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      setupName("getEffectiveDomainCreatePermissions( newUser_1 )");
      try {
         System.out.print(accessControlContext.getEffectiveDomainCreatePermissions(newUser_1));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      setupName("getEffectiveDomainCreatePermissions( newUser_2 )");
      try {
         System.out.print(accessControlContext.getEffectiveDomainCreatePermissions(newUser_2));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // give user 2 inherit permission on user 1
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      setupName("setResourcePermissions( newUser_2, newUser_1, \"" + resourcePermissions + "\" )");
      try {
         accessControlContext.setResourcePermissions(newUser_2, newUser_1, resourcePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      testName("setResourcePermissions( newUser_1, newUser_2, \"" + resourcePermissions + "\" ) [attempt to create an inherit cycle]");
      try {
         accessControlContext.setResourcePermissions(newUser_1, newUser_2, resourcePermissions);
         testFail();
      }
      catch (OaccException e) {
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
      catch (OaccException e) {
         testFail(e);
      }
   }

   private static void test_setGlobalPermissions() throws SQLException {
      testName("test_setPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we attempt to create a resource class which we expect to succeed
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      // we attempt to create a resource class permission which we expect to succeed
      setupName("createResourcePermission( USER, VIEW )");
      accessControlContext.createResourcePermission("USER", "VIEW");
      setupOK();

      Resource newUser_1 = null;

      // we create new user #1
      setupName("newUser_1 = createAuthResource( USER, <pwd> )");
      try {
         newUser_1 = accessControlContext.createResource("USER",
                                                         accessControlContext
                                                               .getDomainNameByResource(accessControlContext.getSessionResource()),
                                                         PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we give user 1 some domain create permissions
      Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));
      resourcePermissions.add(ResourcePermissions.getInstance("VIEW"));
      setupName("setGlobalResourcePermissions( newUser_1, \"" + resourcePermissions + "\" )");
      try {
         accessControlContext.setGlobalResourcePermissions(newUser_1,
                                                           "USER",
                                                           accessControlContext
                                                                 .getDomainNameByResource(accessControlContext
                                                                                                .getSessionResource()),
                                                           resourcePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      testName("assert: getEffectiveGlobalResourcePermissions( newUser_1 ) equals " + resourcePermissions);
      try {
         Set<ResourcePermission> newUser_1_ResourcePermissions
               = accessControlContext.getEffectiveGlobalResourcePermissions(newUser_1,
                                                                            "USER",
                                                                            accessControlContext
                                                                                  .getDomainNameByResource(accessControlContext.getSessionResource()));

         if (newUser_1_ResourcePermissions.equals(resourcePermissions)) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (OaccException e) {
         testFail(e);
         e.printStackTrace();
      }
   }

   private static void test_getResourcesByPermission() throws SQLException {
      testName("test_getResourcesByPermission");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // we create a user resource type
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      // we create a blog resource type
      setupName("createResourceClass( BLOG, false )");
      accessControlContext.createResourceClass("BLOG", false, false);
      accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
      accessControlContext.createResourcePermission("BLOG", "EDIT-POST");
      accessControlContext.createResourcePermission("BLOG", "DELETE-POST");
      setupOK();

      Resource newUser_1 = null;
      Resource newUser_2 = null;

      // we create new user #1
      setupName("newUser_1 = createAuthResource( USER, <pwd> )");
      try {
         newUser_1 = accessControlContext.createResource("USER",
                                                         accessControlContext
                                                               .getDomainNameByResource(accessControlContext.getSessionResource()),
                                                         PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we create new user #2
      setupName("newUser_2 = createAuthResource( USER, <pwd> )");
      try {
         newUser_2 = accessControlContext.createResource("USER",
                                                         accessControlContext
                                                               .getDomainNameByResource(accessControlContext.getSessionResource()),
                                                         PasswordCredentials.newInstance(PASSWORD2));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we give user 1 some create permissions
      Set<ResourceCreatePermission> resourceCreatePermissions = new HashSet<>();
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourceCreatePermissions.CREATE, true));
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("CREATE-POST",
                                                                                                          true), false));
      resourceCreatePermissions.add(ResourceCreatePermissions.getInstance(ResourcePermissions.getInstance("EDIT-POST",
                                                                                                          false), false));
      setupName("setCreatePermission( newUser_1, \"" + resourceCreatePermissions + "\" )");
      try {
         accessControlContext.setResourceCreatePermissions(newUser_1,
                                                           "BLOG",
                                                           accessControlContext
                                                                 .getDomainNameByResource(accessControlContext.getSessionResource()),
                                                           resourceCreatePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we auth as user #1
      setupName("authenticate( newUser_1, <valid-pwd> )");
      try {
         accessControlContext.authenticate(newUser_1, PasswordCredentials.newInstance(PASSWORD));
         accessControlContext.authenticate(newUser_1, PasswordCredentials.newInstance(PASSWORD));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next user 1 creates 15 blogs
      setupName("15 x createResource( BLOG )");
      try {
         for (int i = 0; i < 15; i++) {
            accessControlContext.createResource("BLOG",
                                                accessControlContext
                                                      .getDomainNameByResource(accessControlContext.getSessionResource()));
         }
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      final ResourcePermission filterPermission = ResourcePermissions.getInstance("CREATE-POST", false);
      setupName("getResourcesByPermissions( BLOG, " + filterPermission + " )");
      Set<Resource> newUser_1_ResourceList;
      try {
         newUser_1_ResourceList = accessControlContext.getResourcesByResourcePermissions(newUser_1, "BLOG", filterPermission);
         System.out.print(newUser_1_ResourceList);
         setupOK();
      }
      catch (OaccException e) {
         newUser_1_ResourceList = null;
         setupFail(e);
      }

      // next we auth as user #2
      setupName("authenticate( newUser_2, <valid-pwd> )");
      try {
         accessControlContext.authenticate(newUser_2, PasswordCredentials.newInstance(PASSWORD2));
         accessControlContext.authenticate(newUser_2, PasswordCredentials.newInstance(PASSWORD2));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      setupName("getResourcesByPermissions( BLOG, " + filterPermission + " )");
      try {
         System.out.print(accessControlContext.getResourcesByResourcePermissions(newUser_2, "BLOG", filterPermission));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we auth as the system resource
      authSysResource(accessControlContext);
      authSysResource(accessControlContext);

      // next we give user 2 inherit permissions on user 1
      final Set<ResourcePermission> resourcePermissions = new HashSet<>();
      resourcePermissions.add(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      setupName("setResourcePermissions( newUser_2, newUser_1, \"" + resourcePermissions + "\" )");
      try {
         accessControlContext.setResourcePermissions(newUser_2, newUser_1, resourcePermissions);
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // next we auth as user #2
      setupName("authenticate( newUser_2, <valid-pwd> )");
      try {
         accessControlContext.authenticate(newUser_2, PasswordCredentials.newInstance(PASSWORD2));
         accessControlContext.authenticate(newUser_2, PasswordCredentials.newInstance(PASSWORD2));
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      setupName("getResourcesByResourcePermission( BLOG, " + filterPermission + " )");
      Set<Resource> newUser_2_ResourceList;
      try {
         newUser_2_ResourceList = accessControlContext.getResourcesByResourcePermissions(newUser_2, "BLOG", filterPermission);
         System.out.print(newUser_2_ResourceList);
         setupOK();
      }
      catch (OaccException e) {
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

   private static void test_getResourceClassNames() throws SQLException {
      testName("test_getResourceClassNames");

      final AccessControlContext accessControlContext = newSQLAccessControlContext();

      // authenticate the session with system resource
      authSysResource(accessControlContext);

      // first we need to create a permission which we expect to succeed
      setupName("createResourceClass( USER, true )");
      accessControlContext.createResourceClass("USER", true, false);
      setupOK();

      // we attempt to create a permission which we expect to succeed
      setupName("createResourceClass( BLOG, false )");
      accessControlContext.createResourceClass("BLOG", false, false);
      setupOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, VIEW )");
      accessControlContext.createResourcePermission("USER", "VIEW");
      testOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( USER, CHANGE )");
      accessControlContext.createResourcePermission("USER", "CHANGE");
      testOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, CREATE-POST )");
      accessControlContext.createResourcePermission("BLOG", "CREATE-POST");
      testOK();

      // we attempt to create a permission which we expect to succeed
      testName("createResourceClassPermissions( BLOG, EDIT-POST )");
      accessControlContext.createResourcePermission("BLOG", "EDIT-POST");
      testOK();

      testName("new HashSet( accessControlContext.getResourceClassNames() ).equals( new HashSet( Arrays.asList( \"USER\", \"BLOG\" ) )");
      try {
         if (new HashSet(accessControlContext.getResourceClassNames()).equals(new HashSet(Arrays.asList("USER", "BLOG")))) {
            testOK();
         }
         else {
            testFail();
         }
      }
      catch (OaccException e) {
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
      catch (OaccException e) {
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
      catch (OaccException e) {
         testFail(e);
      }
   }

   private static void test_getDomainDescendants() throws SQLException {
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
      catch (OaccException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-1, ROOT-DOMAIN-1 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-1", "ROOT-DOMAIN-1");
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-2, ROOT-DOMAIN-1 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-2", "ROOT-DOMAIN-1");
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-3, CHILD-DOMAIN-1 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-3", "CHILD-DOMAIN-1");
         setupOK();
      }
      catch (OaccException e) {
         setupFail(e);
      }

      // we attempt to create a child domain which we expect to succeed
      setupName("createDomain( CHILD-DOMAIN-4, CHILD-DOMAIN-3 )");
      try {
         accessControlContext.createDomain("CHILD-DOMAIN-4", "CHILD-DOMAIN-3");
         setupOK();
      }
      catch (OaccException e) {
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
      catch (OaccException e) {
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
      catch (OaccException e) {
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
      catch (OaccException e) {
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
      catch (OaccException e) {
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
      catch (OaccException e) {
         testFail(e);
      }
   }

   private static void test_serializability() throws SQLException, IOException {
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