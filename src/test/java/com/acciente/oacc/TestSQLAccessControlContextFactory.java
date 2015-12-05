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

import com.acciente.oacc.sql.SQLAccessControlContextFactory;
import org.junit.Test;

import javax.sql.DataSource;
import java.sql.Connection;

import static com.ibm.icu.impl.Assert.fail;
import static org.hamcrest.CoreMatchers.containsString;
import static org.junit.Assert.assertThat;

public class TestSQLAccessControlContextFactory {
   @Test
   public void getAccessControlContext_invalidSchemaName_shouldFail() {
      final String invalidSchemaName = "oacc.temp;drop database oaccdb;--";

      try {
         SQLAccessControlContextFactory.getAccessControlContext((DataSource) null,
                                                                invalidSchemaName,
                                                                null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }
      try {
         SQLAccessControlContextFactory.getAccessControlContext((DataSource) null,
                                                                invalidSchemaName,
                                                                null,
                                                                null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }

      try {
         SQLAccessControlContextFactory.getAccessControlContext((Connection) null,
                                                                invalidSchemaName,
                                                                null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }
      try {
         SQLAccessControlContextFactory.getAccessControlContext((Connection) null,
                                                                invalidSchemaName,
                                                                null,
                                                                null);
         fail("getting access control context with invalid schema name should have failed");
      }
      catch (IllegalArgumentException e) {
         assertThat(e.getMessage().toLowerCase(), containsString("invalid database schema name"));
      }
   }
}
