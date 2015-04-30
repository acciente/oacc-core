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
package com.acciente.oacc;

import org.junit.Test;

import java.util.Collections;
import java.util.Set;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_grantDomainPermissions extends TestAccessControlBase {
   @Test
   public void grantDomainPermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_child_withGrant = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true);

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      // grant domain permissions and verify
      accessControlContext.grantDomainPermissions(accessorResource,
                                                  domainName,
                                                  domainPermission_superUser,
                                                  domainPermission_child_withGrant);

      Set<DomainPermission> domainPermissions_expected
            = setOf(domainPermission_superUser, domainPermission_child_withGrant);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_expected));
   }

   @Test
   public void grantDomainPermissions_validAsAuthorized() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();

      // set up an authenticatable resource
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = setOf(domPerm_superuser_withGrant,
                                                                    domPerm_child_withGrant);

      // grant domain permissions and verify
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // create a new resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      // grant domainPermissions as the authenticatable resource and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.grantDomainPermissions(accessorResource, domainName, domPerm_superuser, domPerm_child_withGrant);

      Set<DomainPermission> domainPermissions_expected = setOf(domPerm_superuser, domPerm_child_withGrant);
      assertThat(domainPermissions_expected, is(not(domainPermissions_granter)));
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_expected));
   }

   @Test
   public void grantDomainPermissions_authorizedAsSuperUserWithoutGrant() {
      // Note: SuperUser privilege is enough to grant permissions on a domain, i.e. the 'with grant' option is meaningless for super users

      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = setOf(domCreatePerm_superuser);

      final String domainName = generateDomain();

      // grant domain permissions without granting rights and verify
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // now create a new resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      // grant domainPermissions as the authenticatable resource and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.grantDomainPermissions(accessorResource,
                                                  domainName,
                                                  domCreatePerm_superuser_withGrant,
                                                  domCreatePerm_child);

      Set<DomainPermission> domainPermissions_expected = setOf(domCreatePerm_superuser_withGrant, domCreatePerm_child);
      assertThat(domainPermissions_expected, is(not(domainPermissions_granter)));
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_expected));
   }

   @Test
   public void grantDomainPermissions_addPermission() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();

      // set up an authenticatable resource
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = setOf(domPerm_superuser_withGrant, domPerm_child_withGrant);

      // create a new resource and set domain permission
      Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(accessorResource, domainName, setOf(domPerm_child_withGrant));
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).get(domainName),
                 is(setOf(domPerm_child_withGrant)));

      // grant domain permissions and verify
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // grant domainPermissions as the authenticatable resource and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.grantDomainPermissions(accessorResource, domainName, domPerm_superuser);

      Set<DomainPermission> domainPermissions_expected = setOf(domPerm_superuser, domPerm_child_withGrant);
      assertThat(domainPermissions_expected, is(not(domainPermissions_granter)));
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_expected));
   }

   @Test
   public void grantDomainPermissions_addPermission_withAndWithoutGrant_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();

      // set up an authenticatable resource
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = setOf(domPerm_child_withGrant);

      // create a new resource and set domain permission
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      // grant domain permissions and verify
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // grant domainPermissions as the authenticatable resource and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      try {
         accessControlContext.grantDomainPermissions(accessorResource, domainName, domPerm_superuser, domPerm_child);
         fail("granting additional permissions as grantor without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(domPerm_superuser.getPermissionName().toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(domPerm_child.getPermissionName().toLowerCase())));
      }
   }

   @Test
   public void grantDomainPermissions_regrantPermissions() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_child = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);
      final DomainPermission domainPermission_child_withGrant = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true);

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      Set<DomainPermission> domainPermissions_expected
            = setOf(domainPermission_superUser, domainPermission_child_withGrant);

      // initialize domain permissions and verify
      accessControlContext.grantDomainPermissions(accessorResource,
                                                  domainName,
                                                  domainPermission_superUser,
                                                  domainPermission_child_withGrant);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_expected));

      // regrant domain permissions and verify that nothing changed
      accessControlContext.grantDomainPermissions(accessorResource, domainName, domainPermission_child);

      final Set<DomainPermission> domainPermissions_post2
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post2, is(domainPermissions_expected));
   }

   @Test
   public void grantDomainPermissions_addPermission_withUnauthorizedPermissionsGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = setOf(DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantDomainPermissions(accessorResource,
                                                     domainName,
                                                     DomainPermissions.getInstance(grantedPermissionName),
                                                     DomainPermissions.getInstance(ungrantedPermissionName));
         fail("granting existing permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantDomainPermissions_downgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantDomainPermissions(accessorResource,
                                                  domainName,
                                                  DomainPermissions.getInstance(grantedPermissionName, false));

      final Set<DomainPermission> permissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(permissions_post, is(accessorPermissions_pre));
   }

   @Test
   public void grantDomainPermissions_downgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = setOf(DomainPermissions.getInstance(ungrantedPermissionName, true));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantDomainPermissions(accessorResource,
                                                     domainName,
                                                     DomainPermissions.getInstance(ungrantedPermissionName));
         fail("Downgrading (=removal of granting rights) of domain permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantDomainPermissions_upgradeGrantingRights_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = setOf(DomainPermissions.getInstance(grantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName),
                 is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      accessControlContext.grantDomainPermissions(accessorResource,
                                                  domainName,
                                                  DomainPermissions.getInstance(grantedPermissionName, true));

      Set<DomainPermission> permissions_expected = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      final Set<DomainPermission> permissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(permissions_post, is(permissions_expected));
   }

   @Test
   public void grantDomainPermissions_upgradeGrantingRights_forUnauthorizedPermissionGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre = setOf(DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getEffectiveDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // grant permissions as grantor and verify
      try {
         accessControlContext.grantDomainPermissions(accessorResource,
                                                     domainName,
                                                     DomainPermissions.getInstance(ungrantedPermissionName, true));
         fail("Upgrading (=addition of granting rights) of domain permission granted elsewhere, to which I have no granting rights, should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void grantDomainPermissions_whitespaceConsistent() {
      authenticateSystemResource();

      final DomainPermission domCreatePerm_superuser_trailingspaces
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER + " \t");
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(" \t" + DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      // grant domain permissions and verify
      accessControlContext.grantDomainPermissions(accessorResource,
                                                  domainName_whitespaced,
                                                  domCreatePerm_superuser_trailingspaces,
                                                  domCreatePerm_child_withGrant);

      Set<DomainPermission> domainPermissions_expected = setOf(domCreatePerm_superuser_trailingspaces,
                                                               domCreatePerm_child_withGrant);
      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_expected));
   }

   @Test
   public void grantDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to grant domain permissions with nulls
      try {
         accessControlContext.grantDomainPermissions(null, domainName, domCreatePerm_child_withGrant);
         fail("granting domain permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.grantDomainPermissions(accessorResource, null, domCreatePerm_child_withGrant);
         fail("granting domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.grantDomainPermissions(accessorResource, domainName, null);
         fail("granting domain permissions with null domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.grantDomainPermissions(accessorResource, domainName, domCreatePerm_child_withGrant, null);
         fail("granting domain permissions with null element in domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }
   }

   @Test
   public void grantDomainPermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      try {
         accessControlContext.grantDomainPermissions(Resources.getInstance(-999L),
                                                     domainName,
                                                     domCreatePerm_child_withGrant);
         fail("granting domain permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }

      try {
         accessControlContext.grantDomainPermissions(accessorResource,
                                                     "invalid_domain",
                                                     domCreatePerm_child_withGrant);
         fail("granting domain permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }

   @Test
   public void grantDomainPermissions_notEnoughPermission_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domCreatePerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      // set up an authenticatable resource with resource class create permission
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);

      final Set<DomainPermission> domainPermissions_granter = setOf(domCreatePerm_child);

      final String dmainName = generateDomain();

      // grant domain permissions without granting rights and verify
      accessControlContext.setDomainPermissions(authenticatableResource, dmainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, dmainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // now create a new resource and try to grant domainPermissions as the authenticatable resource
      Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissionsMap(accessorResource).isEmpty(), is(true));

      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));

      try {
         accessControlContext.grantDomainPermissions(accessorResource,
                                                     dmainName,
                                                     domCreatePerm_child,
                                                     domCreatePerm_superuser);
         fail("granting domain permissions without having rights to grant should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(authenticatableResource).toLowerCase()
                                                                 + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("domain permission"));
      }

      // attempt again, but for permission that we neither have with nor without granting rights
      try {
         accessControlContext.grantDomainPermissions(accessorResource, dmainName, domCreatePerm_superuser);
         fail("granting domain permissions without having rights to grant should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(String.valueOf(authenticatableResource).toLowerCase()
                                                                       + " is not authorized"));
         assertThat(e.getMessage().toLowerCase(), containsString("domain permission"));
      }
   }

   @Test
   public void grantDomainPermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_superUser_withGrant = DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                                  true);

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      // grant domain permissions and verify
      try {
         accessControlContext.grantDomainPermissions(accessorResource,
                                                     domainName,
                                                     domainPermission_superUser,
                                                     domainPermission_superUser_withGrant);
         fail("granting permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void grantDomainPermissions_duplicateIdenticalPermissions_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      // grant domain permissions and verify
      try {
         accessControlContext.grantDomainPermissions(accessorResource,
                                                     domainName,
                                                     domainPermission_superUser,
                                                     domainPermission_superUser);
         fail("granting domain permissions with duplicate (identical) permissions should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }
}
