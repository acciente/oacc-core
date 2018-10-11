/*
 * Copyright 2009-2018, Acciente LLC
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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class TestResource {
   @Test
   public void toString_resourceIdOnly() {
      final long resourceId = 123L;
      final String stringRepresentation = Resources.getInstance(resourceId).toString();
      assertThat(stringRepresentation, is("{resourceId: " + resourceId + "}"));
   }

   @Test
   public void toString_externalIdOnly() {
      final String externalId = "007";
      final String stringRepresentation = Resources.getInstance(externalId).toString();
      assertThat(stringRepresentation, is("{externalId: \"" + externalId + "\"}"));
   }

   @Test
   public void toString_resourceIdAndExternalId() {
      final long resourceId = 123L;
      final String externalId = "007";
      final String stringRepresentation = Resources.getInstance(resourceId, externalId).toString();
      assertThat(stringRepresentation, is("{resourceId: " + resourceId
                                                + ", externalId: \"" + externalId + "\"}"));
   }

   @Test
   public void toString_neitherResourceIdNorExternalId() {
      final String stringRepresentation = Resources.getInstance(null).toString();
      assertThat(stringRepresentation, is("{}"));
   }
}
