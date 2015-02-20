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

import java.util.List;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.hasItem;
import static org.hamcrest.CoreMatchers.hasItems;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

public class TestAccessControl_createResourceClass extends TestAccessControlBase {
   @Test
   public void createResourceClass_asSystemUser() throws Exception {
      authenticateSystemResource();

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));

      // create two resource classes with different properties and verify them
      final String authenticatable_resClassName = generateUniqueResourceClassName();
      final String publicCreatable_resClassName = generateUniqueResourceClassName();
      accessControlContext.createResourceClass(authenticatable_resClassName, true, false);
      accessControlContext.createResourceClass(publicCreatable_resClassName, false, true);

      final List<String> resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames.size(), is(2));
      assertThat(resourceClassNames, hasItems(authenticatable_resClassName, publicCreatable_resClassName));

      final ResourceClassInfo resourceClassInfo_authenticatable
            = accessControlContext.getResourceClassInfo(authenticatable_resClassName);
      assertThat(resourceClassInfo_authenticatable.getResourceClassName(), is(authenticatable_resClassName));
      assertThat(resourceClassInfo_authenticatable.isAuthenticatable(), is(true));
      assertThat(resourceClassInfo_authenticatable.isUnauthenticatedCreateAllowed(), is(false));

      final ResourceClassInfo resourceClassInfo_public
            = accessControlContext.getResourceClassInfo(publicCreatable_resClassName);
      assertThat(resourceClassInfo_public.getResourceClassName(), is(publicCreatable_resClassName));
      assertThat(resourceClassInfo_public.isAuthenticatable(), is(false));
      assertThat(resourceClassInfo_public.isUnauthenticatedCreateAllowed(), is(true));
   }

   @Test
   public void createResourceClass_whitespaceConsistent() throws Exception {
      authenticateSystemResource();

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));

      final String resClassName = generateUniqueResourceClassName().trim();
      final String resClassNameWhitespaced = " " + resClassName + "\t";

      // create with whitespace and verify
      accessControlContext.createResourceClass(resClassNameWhitespaced, true, false);

      final List<String> resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames.size(), is(1));
      assertThat(resourceClassNames, hasItem(resClassName));
   }

   @Test
   public void createResourceClass_caseSensitiveConsistent() throws Exception {
      authenticateSystemResource();

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));

      final String resClassNameBase = generateUniqueResourceClassName();
      final String resClassName_lower = resClassNameBase + "_ccc";
      final String resClassName_UPPER = resClassNameBase + "_CCC";

      // create with case-sensitive names and verify
      accessControlContext.createResourceClass(resClassName_lower, true, false);

      List<String> resourceClassNames;
      resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames.size(), is(1));
      assertThat(resourceClassNames, hasItem(resClassName_lower));
      assertThat(resourceClassNames, not(hasItem(resClassName_UPPER)));

      if (isDatabaseCaseSensitive()) {
         accessControlContext.createResourceClass(resClassName_UPPER, true, false);

         resourceClassNames = accessControlContext.getResourceClassNames();
         assertThat(resourceClassNames.size(), is(2));
         assertThat(resourceClassNames, hasItems(resClassName_lower, resClassName_UPPER));
      }
      else {
         try {
            accessControlContext.createResourceClass(resClassName_UPPER, true, false);
            fail("creating a resource class with the name of an existing class that differs in case only should have failed for case-insensitive databases");
         }
         catch (IllegalArgumentException e) {
            assertThat(e.getMessage().toLowerCase(), containsString("duplicate resource class"));
         }
      }
   }

   @Test
   public void createResourceClass_duplicate_shouldFail() throws Exception {
      authenticateSystemResource();

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));

      final String resClassName = generateResourceClass(true, false);
      final String duplicate_resClassName = resClassName;

      List<String> resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames.size(), is(1));
      assertThat(resourceClassNames, hasItems(resClassName));

      // attempt to create duplicate resource class (with different properties)
      try {
         accessControlContext.createResourceClass(duplicate_resClassName, false, true);
         fail("creating resource class with duplicate name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("duplicate resource class"));
      }

      resourceClassNames = accessControlContext.getResourceClassNames();
      assertThat(resourceClassNames.size(), is(1));
      assertThat(resourceClassNames, hasItems(resClassName));
   }

   @Test
   public void createResourceClass_null_shouldFail() throws Exception {
      authenticateSystemResource();

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));

      // attempt to create duplicate resource class
      try {
         accessControlContext.createResourceClass(null, false, false);
         fail("creating resource class with null name should have failed");
      }
      catch (NullPointerException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("may not be null"));
      }

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));
   }

   @Test
   public void createResourceClass_blankName_shouldFail() throws Exception {
      authenticateSystemResource();

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));

      // attempt to create resource class with empty name
      try {
         final String empty_ResClassName = "";
         accessControlContext.createResourceClass(empty_ResClassName, true, true);
         fail("creating resource class with empty name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("may not be blank"));
      }

      // attempt to create resource class with empty name
      try {
         final String empty_ResClassName = " \t";
         accessControlContext.createResourceClass(empty_ResClassName, true, true);
         fail("creating resource class with blank name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("may not be blank"));
      }

      assertThat(accessControlContext.getResourceClassNames().isEmpty(), is(true));
   }

   @Test
   public void createResourceClass_notAuthorized_shouldFail() throws Exception {
      generateResourceAndAuthenticate();
      final int numOfResourceClassesPreTest = accessControlContext.getResourceClassNames().size();

      // attempt to create resource class while not authorized
      try {
         final String empty_ResClassName = "rc_not_authorized";
         accessControlContext.createResourceClass(empty_ResClassName, true, true);
         fail("creating resource class without being authorized to do so should have failed");
      }
      catch (NotAuthorizedException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("reserved for the system resource"));
      }

      assertThat(accessControlContext.getResourceClassNames().size(), is(numOfResourceClassesPreTest));
   }
}
