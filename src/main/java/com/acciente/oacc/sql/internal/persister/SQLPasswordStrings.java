/*
 * Copyright 2009-2017, Acciente LLC
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
package com.acciente.oacc.sql.internal.persister;

import java.io.Serializable;

public class SQLPasswordStrings implements Serializable {
   private static final long serialVersionUID = 1L;

   // SQL string constants

   // ResourcePassword
   public final String SQL_findInResourcePassword_Password_BY_ResourceID;
   public final String SQL_createInResourcePassword_WITH_ResourceID_Password;
   public final String SQL_updateInResourcePassword_Password_BY_ResourceID;
   public final String SQL_removeInResourcePassword_BY_ResourceID;

   public static SQLPasswordStrings getSQLPasswordStrings(String schemaName) {
      return new SQLPasswordStrings(schemaName);
   }

   private SQLPasswordStrings(String schemaName) {
      final String schemaNameAndTablePrefix = schemaName != null ? schemaName + ".OAC_" : "OAC_";

      // GrantDomainCreatePermissionSys
      SQL_findInResourcePassword_Password_BY_ResourceID
            = "SELECT Password FROM "
            + schemaNameAndTablePrefix
            + "ResourcePassword WHERE ResourceId = ?";

      SQL_createInResourcePassword_WITH_ResourceID_Password
            = "INSERT INTO "
            + schemaNameAndTablePrefix
            + "ResourcePassword ( ResourceId, Password ) VALUES ( ?, ? )";

      SQL_updateInResourcePassword_Password_BY_ResourceID
            = "UPDATE " + schemaNameAndTablePrefix + "ResourcePassword SET Password = ? WHERE ResourceId = ?";

      SQL_removeInResourcePassword_BY_ResourceID
            = "DELETE FROM " + schemaNameAndTablePrefix + "ResourcePassword WHERE ResourceId = ?";
   }
}
