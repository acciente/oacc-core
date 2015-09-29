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
               .recursiveCTEEnabled(true)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile DB2_10_5_NON_RECURSIVE =
         new SQLProfile.EnumBldr("DB2_10_5_NON_RECURSIVE")
               .sqlDialect(SQLDialect.DB2_10_5)
               .recursiveCTEEnabled(false)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile Oracle_11_2_RECURSIVE =
         new SQLProfile.EnumBldr("Oracle_11_2_RECURSIVE")
               .sqlDialect(SQLDialect.Oracle_11_2)
               .recursiveCTEEnabled(true)
               .recursiveDeleteEnabled(true)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile Oracle_11_2_NON_RECURSIVE =
         new SQLProfile.EnumBldr("Oracle_11_2_NON_RECURSIVE")
               .sqlDialect(SQLDialect.Oracle_11_2)
               .recursiveCTEEnabled(false)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile PostgreSQL_9_3_RECURSIVE =
         new SQLProfile.EnumBldr("PostgreSQL_9_3_RECURSIVE")
               .sqlDialect(SQLDialect.PostgreSQL_9_3)
               .recursiveCTEEnabled(true)
               .recursiveDeleteEnabled(true)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile PostgreSQL_9_3_NON_RECURSIVE =
         new SQLProfile.EnumBldr("PostgreSQL_9_3_NON_RECURSIVE")
               .sqlDialect(SQLDialect.PostgreSQL_9_3)
               .recursiveCTEEnabled(false)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile SQLServer_12_0_RECURSIVE =
         new SQLProfile.EnumBldr("SQLServer_12_0_RECURSIVE")
               .sqlDialect(SQLDialect.SQLServer_12_0)
               .recursiveCTEEnabled(true)
               .recursiveDeleteEnabled(true)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile SQLServer_12_0_NON_RECURSIVE =
         new SQLProfile.EnumBldr("SQLServer_12_0_NON_RECURSIVE")
               .sqlDialect(SQLDialect.SQLServer_12_0)
               .recursiveCTEEnabled(false)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(true)
               .build();
   public static final SQLProfile SQLite_3_8_RECURSIVE =
         new SQLProfile.EnumBldr("SQLite_3_8_RECURSIVE")
               .sqlDialect(SQLDialect.SQLite_3_8)
               .recursiveCTEEnabled(true)
               .recursiveDeleteEnabled(true)
               .sequenceEnabled(false)
               .build();
   public static final SQLProfile SQLite_3_8_NON_RECURSIVE =
         new SQLProfile.EnumBldr("SQLite_3_8_NON_RECURSIVE")
               .sqlDialect(SQLDialect.SQLite_3_8)
               .recursiveCTEEnabled(false)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(false)
               .build();
   public static final SQLProfile MySQL_5_6_NON_RECURSIVE =
         new SQLProfile.EnumBldr("MySQL_5_6_NON_RECURSIVE")
               .sqlDialect(SQLDialect.MySQL_5_6)
               .recursiveCTEEnabled(false)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(false)
               .build();
   public static final SQLProfile HSQLDB_2_3_NON_RECURSIVE =
         new SQLProfile.EnumBldr("HSQLDB_2_3_NON_RECURSIVE")
               .sqlDialect(SQLDialect.HSQLDB_2_3)
               .recursiveCTEEnabled(false)
               .recursiveDeleteEnabled(false)
               .sequenceEnabled(true)
               .build();

   public static SQLProfile valueOf(String name) {
      return SQLProfile.EnumBldr.valueOf(name);
   }

   // attributes of the SQLProfile
   private final String name;
   private final SQLDialect sqlDialect;
   private final boolean recursiveCTEEnabled;
   private final boolean recursiveDeleteEnabled;
   private final boolean sequenceEnabled;

   private SQLProfile(EnumBldr enumBldr) {
      this.name = enumBldr.name;
      this.sqlDialect = enumBldr.sqlDialect;
      this.recursiveCTEEnabled = enumBldr.recursiveCTEEnabled;
      this.recursiveDeleteEnabled = enumBldr.recursiveDeleteEnabled;
      this.sequenceEnabled = enumBldr.sequenceEnabled;
   }

   public String name() {
      return name;
   }

   public SQLDialect getSqlDialect() {
      return sqlDialect;
   }

   public boolean isRecursiveCTEEnabled() {
      return recursiveCTEEnabled;
   }

   public boolean isRecursiveDeleteEnabled() {
      return recursiveDeleteEnabled;
   }

   public boolean isSequenceEnabled() {
      return sequenceEnabled;
   }

   // private builder, also provides enum-like capabilities
   private static class EnumBldr {
      // a map of all the SQLProfile values defined here keyed by there associated name
      private static final Map<String, SQLProfile> enumMap = new LinkedHashMap<>();

      private final String name;

      private SQLDialect sqlDialect;
      private boolean recursiveCTEEnabled;
      private boolean recursiveDeleteEnabled;
      private boolean sequenceEnabled;

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

      private EnumBldr recursiveCTEEnabled(boolean recursiveCTEEnabled) {
         this.recursiveCTEEnabled = recursiveCTEEnabled;
         return this;
      }

      private EnumBldr recursiveDeleteEnabled(boolean recursiveDeleteEnabled) {
         this.recursiveDeleteEnabled = recursiveDeleteEnabled;
         return this;
      }

      private EnumBldr sequenceEnabled(boolean sequenceEnabled) {
         this.sequenceEnabled = sequenceEnabled;
         return this;
      }

      private SQLProfile build() {
         SQLProfile sqlProfile = new SQLProfile(this);
         enumMap.put(name, sqlProfile);
         return sqlProfile;
      }
   }
}
