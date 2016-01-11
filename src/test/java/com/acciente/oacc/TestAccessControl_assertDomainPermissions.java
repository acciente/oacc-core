/*
 * Copyright 2009-2016, Acciente LLC
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

import org.junit.Test;

import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_assertDomainPermissions extends TestAccessControlBase {
   @Test
   public void assertDomainPermissions_succeedsAsSystemResource() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();

      final Set<DomainPermission> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissions(SYS_RESOURCE, domainName);

      assertThat(allDomainPermissions.size(), is(3));

      // verify
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   setOf(DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER)));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   setOf(DomainPermissions
                                                               .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   setOf(DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN)));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.DELETE));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   setOf(DomainPermissions
                                                               .getInstance(DomainPermissions.DELETE)));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstanceWithGrantOption(DomainPermissions.DELETE));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   setOf(DomainPermissions
                                                               .getInstanceWithGrantOption(DomainPermissions.DELETE)));

      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                   DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                   DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                   DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                   DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER));
      accessControlContext.assertDomainPermissions(SYS_RESOURCE,
                                                   domainName,
                                                   setOf(DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                         DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                         DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                         DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER)));

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions
                                                                  .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.DELETE));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions
                                                                  .getInstance(DomainPermissions.DELETE)));
         fail("asserting domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting multiple domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER),
                                                            DomainPermissions
                                                                  .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
         fail("asserting multiple domain permission for accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
   }

   @Test
   public void assertDomainPermissions_emptyAsAuthenticated() {
      final Resource accessorResource = generateUnauthenticatableResource();

      final String domainName = generateDomain();
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      // set up query authorization
      grantQueryPermission(authenticatableResource, accessorResource);

      // authenticate
      accessControlContext.authenticate(authenticatableResource,
                                        PasswordCredentials.newInstance(password));

      final Map<String,Set<DomainPermission>> allDomainPermissions 
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.isEmpty(), is(true));

      // verify
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN));
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions
                                                                  .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN)));
         fail("asserting domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                      DomainPermissions.getInstance(DomainPermissions.SUPER_USER));
         fail("asserting multiple domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions
                                                                  .getInstance(DomainPermissions.CREATE_CHILD_DOMAIN),
                                                            DomainPermissions.getInstance(DomainPermissions.SUPER_USER)));
         fail("asserting multiple domain permission for authenticated accessor resource when none exist should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
   }

   @Test
   public void assertDomainPermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domPerm_superuser);
      domainPermissions_pre1.add(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_superuser, domPerm_child);
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child, domPerm_superuser);
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, setOf(domPerm_child, domPerm_superuser));

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = new HashSet<>();
      domainPermissions_pre2.add(domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2
            = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      accessControlContext.assertDomainPermissions(accessorResource, domainName2, domPerm_child_withGrant);
      accessControlContext.assertDomainPermissions(accessorResource, domainName2, setOf(domPerm_child_withGrant));
   }

   @Test
   public void assertDomainPermissions_withExtId() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();

      // set domain permissions
      final String externalId = generateUniqueExternalId();
      Resource accessorResource = generateUnauthenticatableResourceWithExtId(externalId);
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domPerm_superuser);
      domainPermissions_pre1.add(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      accessControlContext.assertDomainPermissions(Resources.getInstance(externalId), domainName1, domPerm_superuser, domPerm_child);
      accessControlContext.assertDomainPermissions(Resources.getInstance(externalId), domainName1, setOf(domPerm_child, domPerm_superuser));
   }

   @Test
   public void assertDomainPermissions_partiallyValidAsSystemResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();
      final String domainName2 = generateDomain();

      // set domain permissions
      final char[] password = generateUniquePassword();
      Resource accessorResource = accessControlContext.createResource(generateResourceClass(true, false),
                                                                      domainName1,
                                                                      PasswordCredentials.newInstance(password));
      Set<DomainPermission> domainPermissions_pre1 = setOf(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName1,
                                                      domPerm_child,
                                                      domPerm_child_withGrant);
         fail("asserting partially valid domain permission for system resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName1,
                                                      domPerm_child_withGrant,
                                                      domPerm_child);
         fail("asserting partially valid domain permission for system resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName1,
                                                      domPerm_child_withGrant,
                                                      domPerm_child);
         fail("asserting partially valid domain permission for system resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName1,
                                                      setOf(domPerm_child_withGrant,
                                                            domPerm_child));
         fail("asserting partially valid domain permission for system resource should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      // let's try another domain
      Set<DomainPermission> domainPermissions_pre2 = setOf(domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, domainName2, domainPermissions_pre2);

      // get domain create permissions and verify
      final Map<String,Set<DomainPermission>> allDomainPermissions2
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions2.size(), is(2));
      assertThat(allDomainPermissions2.get(domainName1), is(domainPermissions_pre1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      try {accessControlContext.assertDomainPermissions(accessorResource,
                                                        domainName2,
                                                        domPerm_child_withGrant,
                                                        domPerm_superuser);
         fail("asserting partially valid domain permissions should have failed for system resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {accessControlContext.assertDomainPermissions(accessorResource,
                                                        domainName2,
                                                        setOf(domPerm_child_withGrant,
                                                              domPerm_superuser));
         fail("asserting partially valid domain permissions should have failed for system resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName2,
                                                   domPerm_child_withGrant,
                                                   domPerm_child);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName2,
                                                   setOf(domPerm_child_withGrant,
                                                         domPerm_child));
   }

   @Test
   public void assertDomainPermissions_superUser_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_delete
            = DomainPermissions.getInstance(DomainPermissions.DELETE);
      final DomainPermission domPerm_delete_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.DELETE);

      // set super-user domain permission
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password);
      final String domainName1 = accessControlContext.getDomainNameByResource(accessorResource);
      Set<DomainPermission> domainPermissions_pre1 = setOf(domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_superuser_withGrant);
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, setOf(domPerm_superuser_withGrant));
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName1,
                                                   domPerm_child_withGrant,
                                                   domPerm_child,
                                                   domPerm_delete,
                                                   domPerm_delete_withGrant,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_superuser);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName1,
                                                   setOf(domPerm_child_withGrant,
                                                         domPerm_child,
                                                         domPerm_delete,
                                                         domPerm_delete_withGrant,
                                                         domPerm_superuser_withGrant,
                                                         domPerm_superuser));
   }

   @Test
   public void assertDomainPermissions_validWithDifferingGrantingRights_succeedsAsAuthenticatedResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      // set super-user domain permission
      final char[] password = generateUniquePassword();
      Resource accessorResource = generateAuthenticatableResource(password);
      final String domainName1 = accessControlContext.getDomainNameByResource(accessorResource);
      Set<DomainPermission> domainPermissions_pre1 = setOf(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // get domain create permissions
      final Map<String,Set<DomainPermission>> allDomainPermissions
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource);
      assertThat(allDomainPermissions.size(), is(1));
      assertThat(allDomainPermissions.get(domainName1), is(domainPermissions_pre1));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource, PasswordCredentials.newInstance(password));

      // verify
      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child_withGrant);
         fail("asserting domain permission with exceeding granting rights should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName1, setOf(domPerm_child_withGrant));
         fail("asserting domain permission with exceeding granting rights should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child_withGrant);
         fail("asserting domain permission with exceeding granting rights should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName1, setOf(domPerm_child_withGrant));
         fail("asserting domain permission with exceeding granting rights should have failed for authenticated resource");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("does not have domain permission"));
      }

      // let's try another domain
      authenticateSystemResource();
      Resource accessorResource2 = generateAuthenticatableResource(password);
      final String domainName2 = accessControlContext.getDomainNameByResource(accessorResource2);
      Set<DomainPermission> domainPermissions_pre2 = setOf(domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(accessorResource2, domainName2, domainPermissions_pre2);

      // get domain create permissions
      final Map<String,Set<DomainPermission>> allDomainPermissions2
            = accessControlContext.getEffectiveDomainPermissionsMap(accessorResource2);
      assertThat(allDomainPermissions2.size(), is(1));
      assertThat(allDomainPermissions2.get(domainName2), is(domainPermissions_pre2));

      // authenticate accessor resource
      accessControlContext.authenticate(accessorResource2, PasswordCredentials.newInstance(password));

      // verify
      accessControlContext.assertDomainPermissions(accessorResource2, domainName2, setOf(domPerm_child));
      accessControlContext.assertDomainPermissions(accessorResource2,
                                                   domainName2,
                                                   setOf(domPerm_child_withGrant,
                                                         domPerm_child));
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromParentDomain() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = setOf(domPerm_superuser, domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // verify
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   childDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   childDomain,
                                                   setOf(domPerm_superuser_withGrant,
                                                         domPerm_createchilddomain_withGrant));
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromAncestorDomainWithEmptyIntermediaryAncestors() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String parentDomain = generateDomain();
      final String childDomain = generateUniqueDomainName();
      accessControlContext.createDomain(childDomain, parentDomain);
      final String grandChildDomain = generateUniqueDomainName();
      accessControlContext.createDomain(grandChildDomain, childDomain);
      final String greatGrandChildDomain = generateUniqueDomainName();
      accessControlContext.createDomain(greatGrandChildDomain, grandChildDomain);
      final String greatGreatGrandChildDomain = generateUniqueDomainName();
      accessControlContext.createDomain(greatGreatGrandChildDomain, greatGrandChildDomain);

      // set parent domain create permissions
      final PasswordCredentials passwordCredentials = PasswordCredentials.newInstance(generateUniquePassword());
      Resource accessorResource = accessControlContext.createResource(generateResourceClass(true, false),
                                                                      greatGreatGrandChildDomain,
                                                                      passwordCredentials);
      Set<DomainPermission> parentDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = setOf(domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // set great-great-grand-child domain permissions
      Set<DomainPermission> greatGreatGrandChildDomainPermissions_pre = setOf(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(accessorResource,
                                                greatGreatGrandChildDomain,
                                                greatGreatGrandChildDomainPermissions_pre);

      // verify
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   greatGreatGrandChildDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   greatGreatGrandChildDomain,
                                                   setOf(domPerm_superuser_withGrant,
                                                         domPerm_createchilddomain_withGrant));
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // set child domain permissions
      Set<DomainPermission> directDomainPermissions_pre = new HashSet<>();
      directDomainPermissions_pre.add(domPerm_superuser_withGrant);
      directDomainPermissions_pre.add(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, domainName, directDomainPermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<DomainPermission> donorDomainPermissions_pre = new HashSet<>();
      donorDomainPermissions_pre.add(domPerm_superuser);
      donorDomainPermissions_pre.add(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(donorResource, domainName, donorDomainPermissions_pre);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermissions);

      // verify
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   domainName,
                                                   setOf(domPerm_superuser_withGrant,
                                                         domPerm_createchilddomain_withGrant));
   }

   @Test
   public void assertDomainPermissions_validWithInheritFromAncestorDomainAndResource() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_createchilddomain
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_createchilddomain_withGrant
            = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String childDomain = generateUniqueDomainName();
      final String parentDomain = generateDomain();
      accessControlContext.createDomain(childDomain, parentDomain);

      // set parent domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, parentDomain, parentDomainPermissions_pre);

      // set child domain permissions
      Set<DomainPermission> childDomainPermissions_pre = setOf(domPerm_createchilddomain);
      accessControlContext.setDomainPermissions(accessorResource, childDomain, childDomainPermissions_pre);

      // set donor permissions
      Resource donorResource = generateUnauthenticatableResource();
      Set<DomainPermission> parentDomainDonorPermissions_pre = setOf(domPerm_createchilddomain_withGrant);
      accessControlContext.setDomainPermissions(donorResource, childDomain, parentDomainDonorPermissions_pre);

      // set accessor --INHERIT-> donor
      Set<ResourcePermission> inheritanceResourcePermissions = setOf(ResourcePermissions.getInstance(ResourcePermissions.INHERIT));
      accessControlContext.setResourcePermissions(accessorResource, donorResource, inheritanceResourcePermissions);

      // verify
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   childDomain,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_createchilddomain_withGrant);
      accessControlContext.assertDomainPermissions(accessorResource,
                                                   childDomain,
                                                   setOf(domPerm_superuser_withGrant,
                                                         domPerm_createchilddomain_withGrant));
   }

   @Test
   public void assertDomainPermissions_withoutQueryAuthorization_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domPerm_superuser);
      domainPermissions_pre1.add(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // authenticate without query authorization
      generateResourceAndAuthenticate();

      // attempt to verify
      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child);
         fail("asserting domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName1, setOf(domPerm_child));
         fail("asserting domain permissions without query authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("is not authorized to query resource"));
      }
   }

   @Test
   public void assertDomainPermissions_withImplicitQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateAuthenticatableResource(generateUniquePassword());
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domPerm_superuser);
      domainPermissions_pre1.add(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // setup implicit query permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      accessControlContext.grantResourcePermissions(authenticatableResource,
                                                    accessorResource,
                                                    ResourcePermissions.getInstance(ResourcePermissions.IMPERSONATE));

      // authenticate
      accessControlContext.authenticate(authenticatableResource,
                                        PasswordCredentials.newInstance(password));

      // attempt to verify
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child);
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, setOf(domPerm_child));
   }

   @Test
   public void assertDomainPermissions_withQueryAuthorization_shouldSucceedAsAuthenticated() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final String domainName1 = generateDomain();

      // set domain permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre1 = new HashSet<>();
      domainPermissions_pre1.add(domPerm_superuser);
      domainPermissions_pre1.add(domPerm_child);
      accessControlContext.setDomainPermissions(accessorResource, domainName1, domainPermissions_pre1);

      // setup implicit query permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      grantQueryPermission(authenticatableResource, accessorResource);

      // authenticate
      accessControlContext.authenticate(authenticatableResource,
                                        PasswordCredentials.newInstance(password));

      // attempt to verify
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, domPerm_child);
      accessControlContext.assertDomainPermissions(accessorResource, domainName1, setOf(domPerm_child));
   }

   @Test
   public void assertDomainPermissions_whitespaceConsistent() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";

      // set domain create permissions
      Resource accessorResource = generateUnauthenticatableResource();
      Set<DomainPermission> domainPermissions_pre = new HashSet<>();
      domainPermissions_pre.add(domCreatePerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource, domainName, domainPermissions_pre);

      // get domain create permissions and verify
      accessControlContext.assertDomainPermissions(accessorResource, domainName_whitespaced, domCreatePerm_superuser);
      accessControlContext.assertDomainPermissions(accessorResource, domainName_whitespaced, setOf(domCreatePerm_superuser));
   }

   @Test
   public void assertDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_createChild = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final String domainName = generateDomain();

      try {
         accessControlContext.assertDomainPermissions(null, domainName, domPerm_superUser);
         fail("asserting domain permissions with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertDomainPermissions(Resources.getInstance(null), domainName, domPerm_superUser);
         fail("asserting domain permissions with null internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, (String) null, domPerm_superUser);
         fail("asserting domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, (DomainPermission) null);
         fail("asserting domain permissions with null domain permission reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, domPerm_superUser, null);
         fail("asserting domain permissions with null domain permission reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      domPerm_superUser,
                                                      new DomainPermission[] {null});
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      domPerm_superUser,
                                                      domPerm_createChild,
                                                      null);
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("without null element"));
      }

      // test set-based version
      try {
         accessControlContext.assertDomainPermissions(null, domainName, setOf(domPerm_superUser));
         fail("asserting domain permissions with null accessor resource reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }
      try {
         accessControlContext.assertDomainPermissions(Resources.getInstance(null), domainName, setOf(domPerm_superUser));
         fail("asserting domain permissions with null internal/external resource references should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource id and/or external id is required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, null, setOf(domPerm_superUser));
         fail("asserting domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, (Set<DomainPermission>) null);
         fail("asserting domain permissions with null domain permission reference should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(domPerm_superUser, null));
         fail("asserting domain permissions with null domain permission element should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void assertDomainPermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      try {
         accessControlContext.assertDomainPermissions(accessorResource, domainName, Collections.<DomainPermission>emptySet());
         fail("asserting domain permissions with null domain permission reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void assertDomainPermissions_emptyPermissions_shouldSucceed() {
      authenticateSystemResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();

      accessControlContext.assertDomainPermissions(SYS_RESOURCE, domainName, domPerm_superUser);
      accessControlContext.assertDomainPermissions(SYS_RESOURCE, domainName, domPerm_superUser, new DomainPermission[]{});
   }

   @Test
   public void assertDomainPermissions_duplicatePermissions_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();

      try {
         accessControlContext.assertDomainPermissions(SYS_RESOURCE, domainName, domPerm_superUser, domPerm_superUser);
         fail("asserting domain permission for duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void assertDomainPermissions_duplicatePermissions_shouldSucceed() {
      authenticateSystemResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superUser_grantable = DomainPermissions.getInstanceWithGrantOption(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();

      accessControlContext.assertDomainPermissions(SYS_RESOURCE, domainName, domPerm_superUser, domPerm_superUser_grantable);
      accessControlContext.assertDomainPermissions(SYS_RESOURCE, domainName, setOf(domPerm_superUser, domPerm_superUser_grantable));
   }

   @Test
   public void assertDomainPermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();

      final Resource accessorResource = generateUnauthenticatableResource();
      final DomainPermission domPerm_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final String domainName = generateDomain();
      final Resource invalidResource = Resources.getInstance(-999L);
      final Resource invalidExternalResource = Resources.getInstance("invalid");
      final Resource mismatchedResource = Resources.getInstance(-999L, "invalid");

      try {
         accessControlContext.assertDomainPermissions(invalidResource, domainName, domPerm_superUser);
         fail("asserting domain permissions for invalid accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertDomainPermissions(invalidExternalResource, domainName, domPerm_superUser);
         fail("asserting domain permissions for invalid external accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertDomainPermissions(mismatchedResource, domainName, domPerm_superUser);
         fail("asserting domain permissions for invalid external accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.assertDomainPermissions(invalidResource, domainName, setOf(domPerm_superUser));
         fail("asserting domain permissions for invalid accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertDomainPermissions(invalidExternalResource, domainName, setOf(domPerm_superUser));
         fail("asserting domain permissions for invalid external accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(invalidExternalResource).toLowerCase() + " not found"));
      }
      try {
         accessControlContext.assertDomainPermissions(mismatchedResource, domainName, setOf(domPerm_superUser));
         fail("asserting domain permissions for invalid external accessor resource should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not resolve"));
      }

      try {
         accessControlContext.assertDomainPermissions(accessorResource, "invalid_domain", domPerm_superUser);
         fail("asserting domain permissions with invalid domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
      try {
         accessControlContext.assertDomainPermissions(accessorResource, "invalid_domain", setOf(domPerm_superUser));
         fail("asserting domain permissions with invalid domain name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
