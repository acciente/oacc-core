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

public enum SQLType {
   DB2_10_5_RECURSIVE(SQLDialect.DB2_10_5, true),
   DB2_10_5_NON_RECURSIVE(SQLDialect.DB2_10_5, false),
   Oracle_11_2_RECURSIVE(SQLDialect.Oracle_11_2, true),
   Oracle_11_2_NON_RECURSIVE(SQLDialect.Oracle_11_2, false),
   PostgreSQL_9_3_RECURSIVE(SQLDialect.PostgreSQL_9_3, true),
   PostgreSQL_9_3_NON_RECURSIVE(SQLDialect.PostgreSQL_9_3, false),
   SQLServer_12_0_RECURSIVE(SQLDialect.SQLServer_12_0, true),
   SQLServer_12_0_NON_RECURSIVE(SQLDialect.SQLServer_12_0, false),
   ;

   SQLType(SQLDialect sqlDialect, boolean isRecursionCompatible) {
      this.sqlDialect = sqlDialect;
      this.recursionCompatible = isRecursionCompatible;
   }

   private final SQLDialect sqlDialect;
   private final boolean    recursionCompatible;

   public SQLDialect getSqlDialect() {
      return sqlDialect;
   }

   public boolean isRecursionCompatible() {
      return recursionCompatible;
   }
}
