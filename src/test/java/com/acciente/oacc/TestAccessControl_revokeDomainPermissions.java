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

public class TestAccessControl_revokeDomainPermissions extends TestAccessControlBase {
   @Test
   public void revokeDomainPermissions_validAsSystemResource() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_child_withGrant = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true);

      final String domainName = generateDomain();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      // setup accessor permissions
      final Set<DomainPermission> domainPermissions_pre = setOf(domainPermission_child_withGrant,
                                                                domainPermission_superUser);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                domainPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName), is(domainPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource,
                                                sysDomainName,
                                                domainPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, sysDomainName),
                 is(domainPermissions_pre));

      // revoke domain permissions and verify
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domainPermission_superUser,
                                                   domainPermission_child_withGrant);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post.isEmpty(), is(true));

      // test set-based version
      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                domainPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, domainName), is(domainPermissions_pre));
      accessControlContext.setDomainPermissions(accessorResource2,
                                                sysDomainName,
                                                domainPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, sysDomainName),
                 is(domainPermissions_pre));

      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName,
                                                   setOf(domainPermission_superUser,
                                                         domainPermission_child_withGrant));
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_validAsAuthorized() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      final String domainName = generateDomain();

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domPerm_child_withGrant, domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, domainName), is(accessorPermissions_pre));

      // grant domain permissions
      final Set<DomainPermission> grantorPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, grantorPermissions_pre);

      Set<DomainPermission> grantorPermissions_post;
      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(grantorPermissions_post, is(grantorPermissions_pre));

      // revoke domainPermissions as the authenticatable resource and verify
      grantQueryPermission(authenticatableResource, accessorResource);
      grantQueryPermission(authenticatableResource, accessorResource2);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser,
                                                   domPerm_child_withGrant);

      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(grantorPermissions_post.isEmpty(), is(true));

      // test set-based version
      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName,
                                                   setOf(domPerm_superuser,
                                                         domPerm_child_withGrant));

      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_ungrantedPermissions_shouldSucceed() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_child_withGrant = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true);

      final String domainName = generateDomain();
      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, sysDomainName).isEmpty(), is(true));

      // revoke domain permissions and verify
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domainPermission_superUser,
                                                   domainPermission_child_withGrant);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post.isEmpty(), is(true));

      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   setOf(domainPermission_superUser,
                                                         domainPermission_child_withGrant));
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_ungrantedPermissions_withAndWithoutGrant() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // grant domain permissions
      final Set<DomainPermission> grantorPermissions_pre = setOf(domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, grantorPermissions_pre);

      Set<DomainPermission> grantorPermissions_post;
      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(grantorPermissions_post, is(grantorPermissions_pre));

      // revoke domainPermissions as the authenticatable resource and verify
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      domainName,
                                                      domPerm_superuser,
                                                      domPerm_child_withGrant);
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(domPerm_superuser.getPermissionName().toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(domPerm_child_withGrant.getPermissionName().toLowerCase())));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(domPerm_superuser,
                                                            domPerm_child_withGrant));
         fail("revoking permissions without grant-authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(domPerm_superuser.getPermissionName().toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(domPerm_child_withGrant.getPermissionName().toLowerCase())));
      }
   }

   @Test
   public void revokeDomainPermissions_reRevokePermissions() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_child_withGrant = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN,
                                                                                              true);

      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      // setup accessor permissions
      final Set<DomainPermission> domainPermissions_pre = setOf(domainPermission_child_withGrant,
                                                                domainPermission_superUser);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                domainPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName), is( domainPermissions_pre));

      // revoke domain permissions and verify
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domainPermission_superUser,
                                                   domainPermission_child_withGrant);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post.isEmpty(), is(true));

      // revoke permissions again and verify
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domainPermission_superUser,
                                                   domainPermission_child_withGrant);

      final Set<DomainPermission> domainPermissions_post2
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post2.isEmpty(), is(true));

      // revoke permissions again via set-based version and verify
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   setOf(domainPermission_superUser,
                                                         domainPermission_child_withGrant));
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_revokeSubsetOfPermissions() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      final String domainName = generateDomain();

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domPerm_child_withGrant,
                                                                  domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                accessorPermissions_pre);

      // grant domain permissions
      final Set<DomainPermission> grantorPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, grantorPermissions_pre);

      Set<DomainPermission> grantorPermissions_post;
      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(grantorPermissions_post, is(grantorPermissions_pre));

      // revoke domainPermissions as the authenticatable resource and verify
      grantQueryPermission(authenticatableResource, accessorResource);
      grantQueryPermission(authenticatableResource, accessorResource2);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser);

      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(grantorPermissions_post, is(setOf(domPerm_child_withGrant)));

      // test set-based version
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, domainName),
                 is(accessorPermissions_pre));
      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName,
                                                   setOf(domPerm_superuser));

      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName);
      assertThat(grantorPermissions_post, is(setOf(domPerm_child_withGrant)));
   }

   @Test
   public void revokeDomainPermissions_withUnauthorizedPermissionsGrantedElsewhere_shouldFail() {
      authenticateSystemResource();
      final String grantedPermissionName = DomainPermissions.CREATE_CHILD_DOMAIN;
      final String ungrantedPermissionName = DomainPermissions.SUPER_USER;
      final char[] password = generateUniquePassword();
      final Resource grantorResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final String domainName = generateDomain();

      // setup accessor permissions
      Set<DomainPermission> accessorPermissions_pre
            = setOf(DomainPermissions.getInstance(grantedPermissionName),
                    DomainPermissions.getInstance(ungrantedPermissionName));

      accessControlContext.setDomainPermissions(accessorResource, domainName, accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      // setup grantor permissions
      Set<DomainPermission> grantorPermissions = setOf(DomainPermissions.getInstance(grantedPermissionName, true));

      accessControlContext.setDomainPermissions(grantorResource, domainName, grantorPermissions);
      assertThat(accessControlContext.getDomainPermissions(grantorResource, domainName), is(grantorPermissions));

      // authenticate grantor resource
      accessControlContext.authenticate(grantorResource, PasswordCredentials.newInstance(password));

      // revoke permissions as grantor and verify
      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      domainName,
                                                      DomainPermissions.getInstance(grantedPermissionName),
                                                      DomainPermissions.getInstance(ungrantedPermissionName));
         fail("revoking existing permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(DomainPermissions.getInstance(grantedPermissionName),
                                                            DomainPermissions.getInstance(ungrantedPermissionName)));
         fail("revoking existing permission granted elsewhere without authorization should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString(ungrantedPermissionName.toLowerCase()));
         assertThat(e.getMessage().toLowerCase(), not(containsString(grantedPermissionName)));
      }
   }

   @Test
   public void revokeDomainPermissions_identicalPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      final String domainName = generateDomain();

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domPerm_child_withGrant,
                                                                  domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                accessorPermissions_pre);

      // grant domain permissions
      final Set<DomainPermission> grantorPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, grantorPermissions_pre);

      Set<DomainPermission> grantorPermissions_post;
      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(grantorPermissions_post, is(grantorPermissions_pre));

      // revoke domainPermissions as the authenticatable resource and verify
      grantQueryPermission(authenticatableResource, accessorResource);
      grantQueryPermission(authenticatableResource, accessorResource2);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser,
                                                   domPerm_child_withGrant);

      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(grantorPermissions_post.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName,
                                                   setOf(domPerm_superuser,
                                                         domPerm_child_withGrant));

      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_lesserGrantingRightPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      final String domainName = generateDomain();

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domPerm_child,
                                                                  domPerm_superuser);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                accessorPermissions_pre);

      // grant domain permissions
      final Set<DomainPermission> grantorPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, grantorPermissions_pre);

      Set<DomainPermission> grantorPermissions_post;
      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(grantorPermissions_post, is(grantorPermissions_pre));

      // revoke domainPermissions as the authenticatable resource and verify
      grantQueryPermission(authenticatableResource, accessorResource);
      grantQueryPermission(authenticatableResource, accessorResource2);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_child_withGrant);

      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(grantorPermissions_post.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, domainName),
                 is( accessorPermissions_pre));
      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName,
                                                   setOf(domPerm_superuser_withGrant,
                                                         domPerm_child_withGrant));
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_greaterGrantingRightPermissions_shouldSucceedAsAuthorized() {
      authenticateSystemResource();
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      // set up an authenticatable resource
      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      final String domainName = generateDomain();

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domPerm_child_withGrant,
                                                                  domPerm_superuser_withGrant);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                accessorPermissions_pre);

      // grant domain permissions
      final Set<DomainPermission> grantorPermissions_pre = setOf(domPerm_superuser_withGrant, domPerm_child_withGrant);
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, grantorPermissions_pre);

      Set<DomainPermission> grantorPermissions_post;
      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(authenticatableResource, domainName);
      assertThat(grantorPermissions_post, is(grantorPermissions_pre));

      // revoke domainPermissions as the authenticatable resource and verify
      grantQueryPermission(authenticatableResource, accessorResource);
      grantQueryPermission(authenticatableResource, accessorResource2);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser,
                                                   domPerm_child);

      grantorPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(grantorPermissions_post.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName),
                 is(accessorPermissions_pre));
      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName,
                                                   setOf(domPerm_superuser,
                                                         domPerm_child));
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_authorizedAsSuperUserWithoutGrant() {
      // Note: SuperUser privilege is enough to revoke permissions on a domain,
      //       i.e. the 'with grant' option is meaningless for super users

      authenticateSystemResource();
      final DomainPermission domPerm_superuser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_withGrant
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER, true);
      final DomainPermission domPerm_child
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN);

      final char[] password = generateUniquePassword();
      final Resource authenticatableResource = generateAuthenticatableResource(password);
      final Resource accessorResource = generateUnauthenticatableResource();
      final Resource accessorResource2 = generateUnauthenticatableResource();

      final String domainName = generateDomain();

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domPerm_child,
                                                                  domPerm_superuser_withGrant);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName),
                 is(accessorPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                accessorPermissions_pre);

      // grant domain permissions to authenticatable resource without granting rights
      final Set<DomainPermission> domainPermissions_granter = setOf(domPerm_superuser);
      accessControlContext.setDomainPermissions(authenticatableResource, domainName, domainPermissions_granter);

      Set<DomainPermission> domainPermissions_post;
      domainPermissions_post = accessControlContext.getDomainPermissions(authenticatableResource, domainName);
      assertThat(domainPermissions_post, is(domainPermissions_granter));

      // revoke domainPermissions as the authenticatable resource and verify
      grantQueryPermission(authenticatableResource, accessorResource);
      grantQueryPermission(authenticatableResource, accessorResource2);
      accessControlContext.authenticate(authenticatableResource, PasswordCredentials.newInstance(password));
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName,
                                                   domPerm_superuser_withGrant,
                                                   domPerm_child);

      domainPermissions_post = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, domainName),
                 is(accessorPermissions_pre));
      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName,
                                                   setOf(domPerm_superuser_withGrant,
                                                         domPerm_child));
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_duplicatePermissionNames_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domainPermission_superUser_withGrant = DomainPermissions.getInstance(DomainPermissions.SUPER_USER,
                                                                                              true);

      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domainPermission_superUser_withGrant);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName), is(accessorPermissions_pre));

      accessControlContext.setDomainPermissions(accessorResource,
                                                sysDomainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, sysDomainName), is(accessorPermissions_pre));

      // revoke domain permissions and verify
      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      domainName,
                                                      domainPermission_superUser,
                                                      domainPermission_superUser_withGrant);
         fail("revoking permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      domainName,
                                                      setOf(domainPermission_superUser,
                                                            domainPermission_superUser_withGrant));
         fail("revoking permissions that include the same permission - by name - but with different grant-options, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate permission"));
      }
   }

   @Test
   public void revokeDomainPermissions_duplicateIdenticalPermissions_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domainPermission_superUser = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);

      final String sysDomainName = accessControlContext.getDomainNameByResource(SYS_RESOURCE);
      final String domainName = generateDomain();
      final Resource accessorResource = generateUnauthenticatableResource();
      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName).isEmpty(), is(true));

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domainPermission_superUser);
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName),
                 is(accessorPermissions_pre));
      accessControlContext.setDomainPermissions(accessorResource,
                                                sysDomainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, sysDomainName),
                 is(accessorPermissions_pre));

      // revoke domain permissions
      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      domainName,
                                                      domainPermission_superUser,
                                                      domainPermission_superUser);
         fail("revoking domain permissions for duplicate (identical) permissions, should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate element"));
      }
   }

   @Test
   public void revokeDomainPermissions_whitespaceConsistent() {
      authenticateSystemResource();

      final DomainPermission domainPermission_superUser
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER);
      final DomainPermission domPerm_superuser_trailingspaces
            = DomainPermissions.getInstance(DomainPermissions.SUPER_USER + " \t");
      final DomainPermission domPerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);
      final DomainPermission domPerm_child_withGrant_whitespaced
            = DomainPermissions.getInstance(" \t" + DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      final String domainName_whitespaced = " " + domainName + "\t";

      // setup accessor permissions
      final Set<DomainPermission> accessorPermissions_pre = setOf(domainPermission_superUser, domPerm_child_withGrant);
      final Resource accessorResource = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(accessorResource,
                                                domainName,
                                                accessorPermissions_pre);
      assertThat(accessControlContext.getDomainPermissions(accessorResource, domainName), is(
            accessorPermissions_pre));

      final Resource accessorResource2 = generateUnauthenticatableResource();
      accessControlContext.setDomainPermissions(accessorResource2,
                                                domainName,
                                                accessorPermissions_pre);
      // revoke domain permissions and verify
      accessControlContext.revokeDomainPermissions(accessorResource,
                                                   domainName_whitespaced,
                                                   domPerm_superuser_trailingspaces,
                                                   domPerm_child_withGrant_whitespaced);

      final Set<DomainPermission> domainPermissions_post
            = accessControlContext.getEffectiveDomainPermissions(accessorResource, domainName);
      assertThat(domainPermissions_post.isEmpty(), is(true));

      // test set-based version
      assertThat(accessControlContext.getDomainPermissions(accessorResource2, domainName), is(accessorPermissions_pre));

      accessControlContext.revokeDomainPermissions(accessorResource2,
                                                   domainName_whitespaced,
                                                   setOf(domPerm_superuser_trailingspaces,
                                                         domPerm_child_withGrant_whitespaced));

      assertThat(accessControlContext.getEffectiveDomainPermissions(accessorResource2, domainName).isEmpty(), is(true));
   }

   @Test
   public void revokeDomainPermissions_nulls_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to revoke domain permissions with nulls
      try {
         accessControlContext.revokeDomainPermissions(null, domainName, domCreatePerm_child_withGrant);
         fail("revoking domain permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource, (String) null, domCreatePerm_child_withGrant);
         fail("revoking domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource, domainName, (DomainPermission) null);
         fail("revoking domain permissions with null domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permission required"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource, domainName, domCreatePerm_child_withGrant, null);
         fail("revoking domain permissions with null element in domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("array or a sequence"));
      }

      try {
         accessControlContext.revokeDomainPermissions(null, domainName, setOf(domCreatePerm_child_withGrant));
         fail("revoking domain permissions with null accessor resource should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("resource required"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource, null, setOf(domCreatePerm_child_withGrant));
         fail("revoking domain permissions with null domain name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("domain required"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource, domainName, (Set<DomainPermission>) null);
         fail("revoking domain permissions with null domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource, domainName, setOf(domCreatePerm_child_withGrant, null));
         fail("revoking domain permissions with null element in domain permission set should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("contains null element"));
      }
   }

   @Test
   public void revokeDomainPermissions_emptyPermissionSet_shouldFail() {
      authenticateSystemResource();

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      // attempt to revoke domain permissions with nulls
      try {
         accessControlContext.revokeDomainPermissions(accessorResource, domainName, Collections.<DomainPermission>emptySet());
         fail("revoking domain permissions with null domain permission set should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("permissions required"));
      }
   }

   @Test
   public void revokeDomainPermissions_nonExistentReferences_shouldFail() {
      authenticateSystemResource();
      final DomainPermission domCreatePerm_child_withGrant
            = DomainPermissions.getInstance(DomainPermissions.CREATE_CHILD_DOMAIN, true);

      final String domainName = generateDomain();
      Resource accessorResource = generateUnauthenticatableResource();

      try {
         accessControlContext.revokeDomainPermissions(Resources.getInstance(-999L),
                                                      domainName,
                                                      domCreatePerm_child_withGrant);
         fail("revoking domain permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      "invalid_domain",
                                                      domCreatePerm_child_withGrant);
         fail("revoking domain permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }

      try {
         accessControlContext.revokeDomainPermissions(Resources.getInstance(-999L),
                                                      domainName,
                                                      setOf(domCreatePerm_child_withGrant));
         fail("revoking domain permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("not found"));
      }

      try {
         accessControlContext.revokeDomainPermissions(accessorResource,
                                                      "invalid_domain",
                                                      setOf(domCreatePerm_child_withGrant));
         fail("revoking domain permissions with non-existent accessor resource reference should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("could not find domain"));
      }
   }
}
