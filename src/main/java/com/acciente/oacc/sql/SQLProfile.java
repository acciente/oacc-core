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

import java.io.Serializable;
import java.util.LinkedHashMap;
import java.util.Map;

public class SQLProfile implements Serializable {
   public static final SQLProfile DB2_10_5_RECURSIVE =
         new SQLProfile.EnumBldr("DB2_10_5_RECURSIVE")
               .sqlDialect(SQLDialect.DB2_10_5)
               .recursionSupported(true)
               .recursiveDeleteSupported(false)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile DB2_10_5_NON_RECURSIVE =
         new SQLProfile.EnumBldr("DB2_10_5_NON_RECURSIVE")
               .sqlDialect(SQLDialect.DB2_10_5)
               .recursionSupported(false)
               .recursiveDeleteSupported(false)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile Oracle_11_2_RECURSIVE =
         new SQLProfile.EnumBldr("Oracle_11_2_RECURSIVE")
               .sqlDialect(SQLDialect.Oracle_11_2)
               .recursionSupported(true)
               .recursiveDeleteSupported(true)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile Oracle_11_2_NON_RECURSIVE =
         new SQLProfile.EnumBldr("Oracle_11_2_NON_RECURSIVE")
               .sqlDialect(SQLDialect.Oracle_11_2)
               .recursionSupported(false)
               .recursiveDeleteSupported(false)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile PostgreSQL_9_3_RECURSIVE =
         new SQLProfile.EnumBldr("PostgreSQL_9_3_RECURSIVE")
               .sqlDialect(SQLDialect.PostgreSQL_9_3)
               .recursionSupported(true)
               .recursiveDeleteSupported(true)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile PostgreSQL_9_3_NON_RECURSIVE =
         new SQLProfile.EnumBldr("PostgreSQL_9_3_NON_RECURSIVE")
               .sqlDialect(SQLDialect.PostgreSQL_9_3)
               .recursionSupported(false)
               .recursiveDeleteSupported(false)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile SQLServer_12_0_RECURSIVE =
         new SQLProfile.EnumBldr("SQLServer_12_0_RECURSIVE")
               .sqlDialect(SQLDialect.SQLServer_12_0)
               .recursionSupported(true)
               .recursiveDeleteSupported(true)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile SQLServer_12_0_NON_RECURSIVE =
         new SQLProfile.EnumBldr("SQLServer_12_0_NON_RECURSIVE")
               .sqlDialect(SQLDialect.SQLServer_12_0)
               .recursionSupported(false)
               .recursiveDeleteSupported(false)
               .sequenceSupported(true)
               .build();
   public static final SQLProfile SQLite_3_8_RECURSIVE =
         new SQLProfile.EnumBldr("SQLite_3_8_RECURSIVE")
               .sqlDialect(SQLDialect.SQLite_3_8)
               .recursionSupported(true)
               .recursiveDeleteSupported(true)
               .sequenceSupported(false)
               .build();
   public static final SQLProfile SQLite_3_8_NON_RECURSIVE =
         new SQLProfile.EnumBldr("SQLite_3_8_NON_RECURSIVE")
               .sqlDialect(SQLDialect.SQLite_3_8)
               .recursionSupported(false)
               .recursiveDeleteSupported(false)
               .sequenceSupported(false)
               .build();
   public static final SQLProfile MySQL_5_6_NON_RECURSIVE =
         new SQLProfile.EnumBldr("MySQL_5_6_NON_RECURSIVE")
               .sqlDialect(SQLDialect.MySQL_5_6)
               .recursionSupported(false)
               .recursiveDeleteSupported(false)
               .sequenceSupported(false)
               .build();
   public static final SQLProfile HSQLDB_2_3_NON_RECURSIVE =
         new SQLProfile.EnumBldr("HSQLDB_2_3_NON_RECURSIVE")
               .sqlDialect(SQLDialect.HSQLDB_2_3)
               .recursionSupported(false)
               .recursiveDeleteSupported(false)
               .sequenceSupported(true)
               .build();

   public static SQLProfile valueOf(String name) {
      return SQLProfile.EnumBldr.valueOf(name);
   }

   // attributes of the SQLProfile
   private final String name;
   private final SQLDialect sqlDialect;
   private final boolean recursionSupported;
   private final boolean recursiveDeleteSupported;
   private final boolean sequenceSupported;

   private SQLProfile(EnumBldr enumBldr) {
      this.name = enumBldr.name;
      this.sqlDialect = enumBldr.sqlDialect;
      this.recursionSupported = enumBldr.recursionSupported;
      this.recursiveDeleteSupported = enumBldr.recursiveDeleteSupported;
      this.sequenceSupported = enumBldr.sequenceSupported;
   }

   public String name() {
      return name;
   }

   public SQLDialect getSqlDialect() {
      return sqlDialect;
   }

   public boolean isRecursionSupported() {
      return recursionSupported;
   }

   public boolean isRecursiveDeleteSupported() {
      return recursiveDeleteSupported;
   }

   public boolean isSequenceSupported() {
      return sequenceSupported;
   }

   // private pseudo-builder helper
   private static class EnumBldr {
      // a map of all the SQLProfile values defined here keyed by there associated name
      private static final Map<String, SQLProfile> enumMap = new LinkedHashMap<>();

      private final String name;

      private SQLDialect sqlDialect;
      private boolean recursionSupported;
      private boolean recursiveDeleteSupported;
      private boolean sequenceSupported;

      private static SQLProfile valueOf(String name) {
         return enumMap.get(name);
      }

      private EnumBldr(String name) {
         this.name = name;
      }

      private EnumBldr sqlDialect(SQLDialect sqlDialect) {
         this.sqlDialect = sqlDialect;
         return this;
      }

      private EnumBldr recursionSupported(boolean isRecursionSupported) {
         this.recursionSupported = isRecursionSupported;
         return this;
      }

      private EnumBldr recursiveDeleteSupported(boolean isRecursiveDeleteSupported) {
         this.recursiveDeleteSupported = isRecursiveDeleteSupported;
         return this;
      }

      private EnumBldr sequenceSupported(boolean isSequenceSupported) {
         this.sequenceSupported = isSequenceSupported;
         return this;
      }

      private SQLProfile build() {
         SQLProfile sqlProfile = new SQLProfile(this);
         enumMap.put(name, sqlProfile);
         return sqlProfile;
      }
   }
}
