/*
 * Copyright 2009-2014, Acciente LLC
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
package com.acciente.rsf.helper;

import com.acciente.rsf.sql.SQLDialect;

import javax.sql.DataSource;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.SQLException;
import java.util.Properties;

public class TestDataSourceFactory {
   private static DataSource dataSource;
   private static Boolean    isDatabaseCaseSensitive;
   private static SQLDialect sqlDialect;

   public static final String PROP_DATA_SOURCE_CLASS = "dataSourceClass";
   public static final String PROP_SQL_DIALECT       = "sqlDialect";

   static {
      try {
         final String dbConfigFilename = System.getProperty("dbconfig");
         if (dbConfigFilename == null) {
            throw new RuntimeException("system property 'dbconfig' not specified; please specify VM parameter with -Ddbconfig=<filename> (example: -Ddbconfig=dbconfig_postgresql.properties)");
         }

         final ClassLoader contextClassLoader = Thread.currentThread().getContextClassLoader();
         final InputStream inputStream = contextClassLoader.getResourceAsStream(dbConfigFilename);
         if (inputStream == null) {
            throw new RuntimeException("could not find resource " + dbConfigFilename);
         }

         final Properties properties = new Properties();
         properties.load(inputStream);
         final Class<?> dataSourceClass = Class.forName(properties.getProperty(PROP_DATA_SOURCE_CLASS));
         final DataSource vendorSpecificDataSource = (DataSource) dataSourceClass.newInstance();

         final String sqlDialectName = properties.getProperty(PROP_SQL_DIALECT);
         if (sqlDialectName==null) {
            throw new RuntimeException("no sqlDialect property specified in database configuration property file");
         }
         sqlDialect = SQLDialect.valueOf(sqlDialectName);

         for (String propertyName : properties.stringPropertyNames()) {
            if (!(PROP_DATA_SOURCE_CLASS.equals(propertyName) || PROP_SQL_DIALECT.equals(propertyName))) {
               setDataSourceProperty(vendorSpecificDataSource, propertyName, properties.getProperty(propertyName));
            }
         }
         dataSource = vendorSpecificDataSource;
         isDatabaseCaseSensitive = CaseSensitiveChecker.isDatabaseCaseSensitive(dataSource);
      }
      catch (Exception e) {
         throw new RuntimeException(e);
      }
   }

   private static void setDataSourceProperty(DataSource vendorSpecificDataSource,
                                             String propertyName,
                                             String valueAsString) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException {
      Integer valueAsInteger;

      try {
         valueAsInteger = Integer.parseInt(valueAsString);
         valueAsString = null;
      }
      catch (NumberFormatException e) {
         valueAsInteger = null;
      }

      final String methodName = "set"
            + propertyName.substring(0, 1).toUpperCase()
            + propertyName.substring(1);
      final Method setMethod
            = vendorSpecificDataSource.getClass().getMethod(methodName,
                                                            valueAsString == null
                                                            ? int.class
                                                            : String.class);
      setMethod.invoke(vendorSpecificDataSource, valueAsString==null ? valueAsInteger : valueAsString);
   }

   public static SQLDialect getSQLDialect() {
      return sqlDialect;
   }

   public static DataSource getDataSource() throws SQLException {
      return dataSource;
   }

   public static boolean isDatabaseCaseSensitive() throws SQLException {
      return isDatabaseCaseSensitive;
   }
}
